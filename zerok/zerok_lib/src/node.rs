use crate::{
    set_merkle_tree::*, wallet::LedgerEvent, ElaboratedBlock, ElaboratedTransaction,
    ValidationError, ValidatorState,
};
use async_executors::exec::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::RemoteHandle;
pub use futures::prelude::*;
pub use futures::stream::Stream;
use futures::task::SpawnExt;
use itertools::izip;
use jf_primitives::jubjub_dsa::Signature;
use jf_txn::structs::{Nullifier, ReceiverMemo};
use phaselock::{
    error::PhaseLockError,
    event::EventType,
    handle::{HandleError, PhaseLockHandle},
};
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;

pub trait ConsensusEvent {
    fn into_event(self) -> EventType<ElaboratedBlock, ValidatorState>;
}

pub type PhaseLockEvent = phaselock::event::Event<ElaboratedBlock, ValidatorState>;

impl ConsensusEvent for PhaseLockEvent {
    fn into_event(self) -> EventType<ElaboratedBlock, ValidatorState> {
        self.event
    }
}

pub type EventStream<Event> = Pin<Box<dyn Send + Stream<Item = Event>>>;

#[async_trait]
pub trait Validator {
    type Event: ConsensusEvent;
    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError>;
    async fn start_consensus(&self);
    fn subscribe(&self) -> EventStream<Self::Event>;
}

/// A lightweight node handles consensus, and nothing more.
pub type LightWeightNode = PhaseLockHandle<ElaboratedBlock, 64>;

#[async_trait]
impl Validator for LightWeightNode {
    type Event = PhaseLockEvent;

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError> {
        self.submit_transaction(tx).await.map_err(|err| {
            if let HandleError::Transaction { source } = err {
                source
            } else {
                panic!(
                    "unexpected error from PhaseLockHandle::submit_transaction: {:?}",
                    err
                );
            }
        })
    }

    async fn start_consensus(&self) {
        self.start().await
    }

    fn subscribe(&self) -> EventStream<Self::Event> {
        // Convert from the Future-based setting of next_event() to an asynchronous stream setting
        // using `stream::unfold`.
        Box::pin(stream::unfold(self.clone(), |mut handle| async move {
            match handle.next_event().await {
                Ok(event) => Some((event, handle)),
                Err(HandleError::ShutDown) => None,
                Err(HandleError::Skipped { ammount }) => {
                    unimplemented!("handling for {:?} skipped events", ammount)
                }
                Err(err) => panic!(
                    "unexpected error from PhaseLockHandle::next_event: {:?}",
                    err
                ),
            }
        }))
    }
}

/// A QueryService accumulates the full state of the ledger, making it available for consumption by
/// network APIs and such.
#[async_trait]
pub trait QueryService {
    /// Get the `i`th committed block and the state at the time just before the block was committed.
    async fn get_block(
        &self,
        block_id: u64,
    ) -> Result<(ValidatorState, ElaboratedBlock), QueryServiceError>;

    /// Query whether a nullifier is in a nullifier set with a given root hash, and retrieve a proof
    /// of inclusion or exclusion. The root hash must be the root of a past version of the
    /// nullifiers set for this ledger.
    async fn nullifier_proof(
        &self,
        root: set_hash::Hash,
        n: Nullifier,
    ) -> Result<(bool, SetMerkleProof), QueryServiceError>;

    /// Get an asynchronous stream which yields LedgerEvents when things happen on the ledger or
    /// the associated bulletin board.
    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent>;

    /// Broadcast that a set of receiver memos corresponds to a particular transaction. The memos
    /// must be signed using the signing key for the specified transaction. The sender of a message
    /// may only post one set of receiver memos per transaction, so calling this function twice with
    /// the same (block_id, txn_id) will fail. (Note that non-senders of a transaction are prevented
    /// from effectively denying service by posting invalid memos for transactions they didn't send
    /// by the signature mechanism).
    ///
    /// If successful, the memos will be available for querying via `get_memos`. In addition, an
    /// event will be broadcast asynchronously to all subscribers informing them of the new memos
    /// and the corresponding record uids and commitments.
    async fn post_memos(
        &self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        signature: Signature,
    ) -> Result<(), QueryServiceError>;

    /// Get the receiver memos for a transaction, if they have been posted to the bulletin board.
    /// The result includes a signature over the contents of the memos using the signing key for the
    /// requested transaction, as proof that these memos are in fact the ones that the sender
    /// intended to associate with this transaction.
    async fn get_memos(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature), QueryServiceError>;
}

#[derive(Clone, Debug)]
pub enum QueryServiceError {
    InvalidNullifierRoot {},
    InvalidBlockId {},
    InvalidTxnId {},
    MemosAlreadyPosted {},
    InvalidSignature {},
    WrongNumberOfMemos { expected: usize },
    NoMemosForTxn {},
}

struct FullState {
    validator: ValidatorState,
    nullifiers: HashMap<set_hash::Hash, SetMerkleTree>,
    // All past states and state transitions of the ledger.
    history: Vec<LedgerSnapshot>,
    // The last block which was proposed. This is currently used to correllate BadBlock and
    // InconsistentBlock errors from PhaseLock with the block that caused the error. In the future,
    // PhaseLock errors will contain the bad block (or some kind of reference to it, perhaps through
    // persistent storage) and this will not be necessary.
    proposed: ElaboratedBlock,
    // All past events, so that clients can subscribe to an event stream starting at a time in the
    // past.
    events: Vec<LedgerEvent>,
    // The send ends of all channels which are subscribed to events.
    subscribers: Vec<mpsc::UnboundedSender<LedgerEvent>>,
    // Clients which have subscribed to events starting at some time in the future, to be added to
    // `subscribers` when the time comes.
    pending_subscribers: BTreeMap<u64, Vec<mpsc::UnboundedSender<LedgerEvent>>>,
}

#[derive(Clone, Debug)]
struct LedgerSnapshot {
    state: ValidatorState,
    block: ElaboratedBlock,
    // Receiver memos come in asynchronously after a block is committed, on a transaction-by-
    // transaction basis. The list of memos corresponding to each transaction in a block will be
    // None until valid memos for that block are received by the sender. Note that this may never
    // happen if the sender chooses to send the memos directly to the receiver without posting them
    // publicly.
    memos: Vec<Option<(Vec<ReceiverMemo>, Signature)>>,
    uids: Vec<Vec<u64>>,
}

impl FullState {
    fn update(&mut self, event: impl ConsensusEvent) {
        use EventType::*;
        match event.into_event() {
            Error { error } => {
                if matches!(
                    *error,
                    PhaseLockError::BadBlock { .. } | PhaseLockError::InconsistentBlock { .. }
                ) {
                    // If the error is due to a bad block, correllate it with the block that caused
                    // the error (`self.proposed` in our current hacky solution, but eventually
                    // saved somewhere in storage) and send the block through our mirror of the
                    // validator to get a helpful error.
                    let err = match self.validator.validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        self.proposed.block.clone(),
                        self.proposed.proofs.clone(),
                        true,
                    ) {
                        Err(err) => err,
                        Ok(_) => {
                            // Something weird happened: the validator reported a bad block, but our
                            // mirror of the ValidatorState accepts the block. It's unclear what
                            // this means, but we can report a generic error to the subscribers.
                            ValidationError::Failed {}
                        }
                    };
                    self.send_event(LedgerEvent::Reject(self.proposed.clone(), err));
                }

                // PhaseLock errors that don't relate to blocks being rejected (view timeouts,
                // network errors, etc.) do not correspond to LedgerEvents.
            }

            Propose { block } => {
                self.proposed = (*block).clone();
            }

            Decide { block, state } => {
                let prev_state = self.validator.clone();

                // A block has been committed. Update our mirror of the ValidatorState by applying
                // the new block, and generate a Commit event.
                match self.validator.validate_and_apply(
                    self.validator.prev_commit_time + 1,
                    block.block.clone(),
                    block.proofs.clone(),
                    true,
                ) {
                    // We update our ValidatorState for each block committed by the PhaseLock event
                    // source, so we shouldn't ever get out of sync.
                    Err(_) => panic!("state is out of sync with validator"),
                    Ok(_) if self.validator.commit() != state.commit() => {
                        panic!("state is out of sync with validator")
                    }

                    Ok(mut uids) => {
                        // Add the results of this block to our state.
                        let mut new_nullifiers =
                            self.nullifiers[&prev_state.nullifiers_root].clone();
                        let mut block_uids = vec![];
                        for txn in block.block.0.iter() {
                            for n in txn.nullifiers() {
                                new_nullifiers.insert(n);
                            }

                            // Split the uids corresponding to this transaction off the front of the
                            // list of uids for the whole block.
                            let mut this_txn_uids = uids;
                            uids = this_txn_uids.split_off(txn.output_len());
                            assert_eq!(this_txn_uids.len(), txn.output_len());
                            block_uids.push(this_txn_uids);
                        }
                        assert_eq!(new_nullifiers.hash(), self.validator.nullifiers_root);
                        self.nullifiers
                            .insert(new_nullifiers.hash(), new_nullifiers);
                        self.history.push(LedgerSnapshot {
                            state: prev_state,
                            block: (*block).clone(),
                            memos: vec![None; block.block.0.len()],
                            uids: block_uids,
                        });

                        // Notify subscribers of the new block.
                        self.send_event(LedgerEvent::Commit((*block).clone()));
                    }
                }
            }

            _ => {}
        }
    }

    fn send_event(&mut self, event: LedgerEvent) {
        // Subscribers who asked for a subscription starting from the current time can now be added
        // to the list of active subscribers.
        let now = self.events.len() as u64;
        if let Some(new_subscribers) = self.pending_subscribers.remove(&now) {
            self.subscribers.extend(new_subscribers);
        }

        // Send the message to all active subscribers. Filter out subscribers where the send fails,
        // which means that the client has disconnected.
        self.subscribers = std::mem::take(&mut self.subscribers)
            .into_iter()
            .filter(|subscriber| subscriber.unbounded_send(event.clone()).is_ok())
            .collect();

        // Save the event so we can feed it to later subscribers who want to start from some time in
        // the past.
        self.events.push(event);
    }

    fn subscribe(&mut self, t: u64) -> EventStream<LedgerEvent> {
        let (sender, receiver) = mpsc::unbounded();
        if (t as usize) < self.events.len() {
            // If the start time is in the past, send the subscriber all saved events since the
            // start time and make them an active subscriber starting now.
            self.subscribers.push(sender);
            let past_events = self
                .events
                .iter()
                .skip(t as usize)
                .cloned()
                .collect::<Vec<_>>();
            Box::pin(stream::iter(past_events).chain(receiver))
        } else {
            // Otherwise, add the subscriber to the list of pending subscribers to start receiving
            // events at time `t`.
            self.pending_subscribers.entry(t).or_default().push(sender);
            Box::pin(receiver)
        }
    }

    fn verify_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        new_memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), QueryServiceError> {
        let block_id = block_id as usize;
        let txn_id = txn_id as usize;

        // Validate `block_id` and get the corresponding state snapshot.
        if block_id >= self.history.len() {
            return Err(QueryServiceError::InvalidBlockId {});
        }
        let LedgerSnapshot {
            block, memos, uids, ..
        } = &mut self.history[block_id];
        let num_txns = block.block.0.len();
        assert_eq!(memos.len(), num_txns);
        assert_eq!(uids.len(), num_txns);
        assert_eq!(block.proofs.len(), num_txns);

        // Validate `txn_id` and get the relevant information for the transaction within `block`.
        if txn_id >= num_txns {
            return Err(QueryServiceError::InvalidTxnId {});
        }
        let txn = &block.block.0[txn_id];
        let stored_memos = &mut memos[txn_id];
        let uids = &uids[txn_id];

        // Validate the new memos.
        if stored_memos.is_some() {
            return Err(QueryServiceError::MemosAlreadyPosted {});
        }
        if txn
            .verify_receiver_memos_signature(&new_memos, &sig)
            .is_err()
        {
            return Err(QueryServiceError::InvalidSignature {});
        }
        if new_memos.len() != txn.output_len() {
            return Err(QueryServiceError::WrongNumberOfMemos {
                expected: txn.output_len(),
            });
        }

        // Store and broadcast the new memos.
        *stored_memos = Some((new_memos.clone(), sig));
        let merkle_tree = &self.validator.record_merkle_frontier;
        let merkle_paths = uids
            .iter()
            .map(|uid| merkle_tree.get_leaf(*uid).expect_ok().unwrap().1);
        let event = LedgerEvent::Memos(
            izip!(
                new_memos,
                txn.output_commitments(),
                uids.iter().cloned(),
                merkle_paths
            )
            .collect(),
        );
        self.send_event(event);

        Ok(())
    }

    fn get_snapshot(&self, block_id: u64) -> Result<&LedgerSnapshot, QueryServiceError> {
        self.history
            .get(block_id as usize)
            .ok_or(QueryServiceError::InvalidBlockId {})
    }
}

/// A QueryService that aggregates the full ledger state by observing consensus.
pub struct PhaseLockQueryService {
    state: Arc<RwLock<FullState>>,
    // When dropped, this handle will cancel and join the event handling task. It is not used
    // explicitly; it is merely stored with the rest of the struct for the auto-generated drop glue.
    _event_task: RemoteHandle<()>,
}

impl PhaseLockQueryService {
    pub fn new(
        event_source: EventStream<impl ConsensusEvent + Send + 'static>,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        validator: ValidatorState,
        nullifiers: SetMerkleTree,
    ) -> Self {
        //todo !jeb.bearer If we are not starting from the genesis of the ledger, query the full
        // state at this point from another full node, like
        //  let state = other_node.full_state(validator.commit());
        // For now, just assume we are starting at the beginning:
        let history = Vec::new();
        let events = Vec::new();

        let state = Arc::new(RwLock::new(FullState {
            validator,
            nullifiers: vec![(nullifiers.hash(), nullifiers)].into_iter().collect(),
            history,
            proposed: ElaboratedBlock::default(),
            events,
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
        }));

        // Spawn event handling task.
        let task = {
            let state = state.clone();
            let mut event_source = Box::pin(event_source);
            AsyncStd::new()
                .spawn_with_handle(async move {
                    while let Some(event) = event_source.next().await {
                        state.write().await.update(event);
                    }
                })
                .unwrap()
        };

        Self {
            state,
            _event_task: task,
        }
    }
}

#[async_trait]
impl QueryService for PhaseLockQueryService {
    async fn get_block(
        &self,
        i: u64,
    ) -> Result<(ValidatorState, ElaboratedBlock), QueryServiceError> {
        let state = self.state.read().await;
        let snapshot = state.get_snapshot(i)?;
        Ok((snapshot.state.clone(), snapshot.block.clone()))
    }

    async fn nullifier_proof(
        &self,
        root: set_hash::Hash,
        n: Nullifier,
    ) -> Result<(bool, SetMerkleProof), QueryServiceError> {
        let state = self.state.read().await;
        state
            .nullifiers
            .get(&root)
            .map(|nullifiers| nullifiers.contains(n).unwrap())
            .ok_or(QueryServiceError::InvalidNullifierRoot {})
    }

    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent> {
        let mut state = self.state.write().await;
        state.subscribe(i)
    }

    async fn post_memos(
        &self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), QueryServiceError> {
        let mut state = self.state.write().await;
        state.verify_memos(block_id, txn_id, memos, sig)
    }

    async fn get_memos(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature), QueryServiceError> {
        let state = self.state.read().await;
        let snapshot = state.get_snapshot(block_id)?;
        snapshot
            .memos
            .get(txn_id as usize)
            .cloned()
            .ok_or(QueryServiceError::InvalidTxnId {})?
            .ok_or(QueryServiceError::NoMemosForTxn {})
    }
}

/// A full node is a QueryService running alongside a lightweight validator.
pub struct FullNode {
    validator: LightWeightNode,
    query_service: PhaseLockQueryService,
}

impl FullNode {
    pub fn new(
        validator: LightWeightNode,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        state: ValidatorState,
        nullifiers: SetMerkleTree,
    ) -> Self {
        let query_service = PhaseLockQueryService::new(validator.subscribe(), state, nullifiers);
        Self {
            validator,
            query_service,
        }
    }

    fn as_validator(&self) -> &impl Validator<Event = <Self as Validator>::Event> {
        &self.validator
    }

    fn as_query_service(&self) -> &impl QueryService {
        &self.query_service
    }
}

#[async_trait]
impl Validator for FullNode {
    type Event = <LightWeightNode as Validator>::Event;

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError> {
        self.as_validator().submit_transaction(tx).await
    }

    async fn start_consensus(&self) {
        self.as_validator().start_consensus().await
    }

    fn subscribe(&self) -> EventStream<Self::Event> {
        self.as_validator().subscribe()
    }
}

#[async_trait]
impl QueryService for FullNode {
    async fn get_block(
        &self,
        i: u64,
    ) -> Result<(ValidatorState, ElaboratedBlock), QueryServiceError> {
        self.as_query_service().get_block(i).await
    }

    async fn nullifier_proof(
        &self,
        root: set_hash::Hash,
        n: Nullifier,
    ) -> Result<(bool, SetMerkleProof), QueryServiceError> {
        self.as_query_service().nullifier_proof(root, n).await
    }

    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent> {
        self.as_query_service().subscribe(i).await
    }

    async fn post_memos(
        &self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), QueryServiceError> {
        self.as_query_service()
            .post_memos(block_id, txn_id, memos, sig)
            .await
    }

    async fn get_memos(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature), QueryServiceError> {
        self.as_query_service().get_memos(block_id, txn_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MultiXfrRecordSpec, MultiXfrTestState};
    use async_std::task::block_on;
    use jf_primitives::jubjub_dsa::KeyPair;
    use jf_primitives::merkle_tree::MerkleTree;
    use jf_txn::sign_receiver_memos;
    use quickcheck::QuickCheck;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;

    struct MockConsensusEvent {
        event: EventType<ElaboratedBlock, ValidatorState>,
    }

    impl ConsensusEvent for MockConsensusEvent {
        fn into_event(self) -> EventType<ElaboratedBlock, ValidatorState> {
            self.event
        }
    }

    #[allow(clippy::type_complexity)]
    fn generate_valid_history(
        txs: Vec<Vec<(bool, u16, u16, u8, u8, i32)>>,
        nkeys: u8,
        ndefs: u8,
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>, // (def,key) -> amount
    ) -> (
        (ValidatorState, SetMerkleTree),
        Vec<(
            ValidatorState,
            ElaboratedBlock,
            Vec<(Vec<ReceiverMemo>, Signature)>,
            ValidatorState,
        )>,
    ) {
        let mut state = MultiXfrTestState::initialize(
            [0x7au8; 32],
            nkeys,
            ndefs,
            (
                MultiXfrRecordSpec {
                    asset_def_ix: init_rec.0,
                    owner_key_ix: init_rec.1,
                    asset_amount: init_rec.2,
                },
                init_recs
                    .into_iter()
                    .map(
                        |(asset_def_ix, owner_key_ix, asset_amount)| MultiXfrRecordSpec {
                            asset_def_ix,
                            owner_key_ix,
                            asset_amount,
                        },
                    )
                    .collect(),
            ),
        )
        .unwrap();
        let initial_state = (state.validator.clone(), state.nullifiers.clone());

        let num_txs = txs.len();

        println!("{} blocks", num_txs);

        let mut history = vec![];
        for (i, block) in txs.into_iter().enumerate() {
            assert_eq!(state.owners.len(), state.memos.len());
            assert_eq!(state.validator.nullifiers_root, state.nullifiers.hash());
            MultiXfrTestState::update_timer(&mut state.outer_timer, |_| {
                println!(
                    "Block {}/{}, {} candidate txns",
                    i + 1,
                    num_txs,
                    block.len()
                )
            });

            // let block = block.into_iter().take(5).collect::<Vec<_>>();
            let txns = state.generate_transactions(i, block, num_txs).unwrap();

            let mut generation_time: f32 = 0.0;
            MultiXfrTestState::update_timer(&mut state.outer_timer, |t| {
                generation_time = t;
                println!("Block {}/{} txns generated: {}s", i + 1, num_txs, t)
            });

            let mut blk = ElaboratedBlock::default();
            let mut signed_memos = vec![];
            for (ix, keys_and_memos, sig, txn) in txns {
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                if state
                    .try_add_transaction(&mut blk, txn, i, ix, num_txs, owner_memos.clone(), kixs)
                    .is_ok()
                {
                    signed_memos.push((owner_memos, sig));
                }
            }

            let prev_state = state.validator.clone();
            state
                .validate_and_apply(blk.clone(), i, num_txs, generation_time)
                .unwrap();
            history.push((prev_state, blk, signed_memos, state.validator.clone()));
        }

        (initial_state, history)
    }

    #[allow(clippy::type_complexity)]
    fn test_query_service(
        txs: Vec<Vec<(bool, u16, u16, u8, u8, i32)>>,
        nkeys: u8,
        ndefs: u8,
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>, // (def,key) -> amount
    ) {
        if txs.iter().map(|block| block.len()).sum::<usize>() == 0 {
            println!("skipping test because no transactions were generated");
            return;
        }

        let mut rng = ChaChaRng::from_seed([0x42u8; 32]);
        let dummy_key_pair = KeyPair::generate(&mut rng);

        block_on(async {
            let (initial_state, history) =
                generate_valid_history(txs, nkeys, ndefs, init_rec, init_recs);
            let initial_uid = initial_state.0.record_merkle_frontier.num_leaves();
            assert_eq!(initial_state.0.commit(), history[0].0.commit());
            let events = Box::pin(stream::iter(history.clone().into_iter().map(
                |(_, block, _, state)| MockConsensusEvent {
                    event: EventType::Decide {
                        block: Arc::new(block),
                        state: Arc::new(state),
                    },
                },
            )));
            let qs = PhaseLockQueryService::new(events, initial_state.0, initial_state.1);

            let mut events = qs.subscribe(0).await;
            for (_, hist_block, _, hist_state) in history.iter() {
                match events.next().await.unwrap() {
                    LedgerEvent::Commit(block, ..) => {
                        assert_eq!(block, *hist_block);

                        // We should be able to get inclusion proofs for all the nullifiers in the
                        // new block.
                        for txn in block.block.0 {
                            for n in txn.nullifiers() {
                                let (incl, proof) = qs
                                    .nullifier_proof(hist_state.nullifiers_root, n)
                                    .await
                                    .unwrap();
                                assert!(incl);
                                proof.check(n, &hist_state.nullifiers_root).unwrap();
                            }
                        }
                    }

                    event => {
                        panic!("Expected Commit event, got {:?}", event);
                    }
                }
            }

            // We should now be able to submit receiver memos for the blocks that just got committed.
            let mut expected_uid = initial_uid;
            for (block_id, (_, block, memos, _)) in history.iter().enumerate() {
                for (txn_id, (txn, (memos, sig))) in block.block.0.iter().zip(memos).enumerate() {
                    // Posting memos with an invalid signature should fail.
                    let dummy_signature = sign_receiver_memos(&dummy_key_pair, memos).unwrap();
                    match qs
                        .post_memos(
                            block_id as u64,
                            txn_id as u64,
                            memos.clone(),
                            dummy_signature,
                        )
                        .await
                    {
                        Err(QueryServiceError::InvalidSignature { .. }) => {}
                        res => {
                            panic!("Expected error InvalidSignature, got {:?}", res);
                        }
                    }

                    qs.post_memos(block_id as u64, txn_id as u64, memos.clone(), sig.clone())
                        .await
                        .unwrap();
                    match events.next().await.unwrap() {
                        LedgerEvent::Memos(info) => {
                            // After successfully posting memos, we should get a Memos event.
                            for ((memo, comm, uid, merkle_path), (expected_memo, expected_comm)) in
                                info.into_iter()
                                    .zip(memos.iter().zip(txn.output_commitments()))
                            {
                                // The contents of the event should match the memos we just posted.
                                assert_eq!(memo, *expected_memo);
                                assert_eq!(comm, expected_comm);
                                assert_eq!(uid, expected_uid);

                                // The event should contain a valid inclusion proof for each
                                // commitment. This proof is relative to the root hash of the
                                // latest validator state in the event stream.
                                let state = &history[history.len() - 1].3;
                                MerkleTree::check_proof(
                                    state.record_merkle_frontier.get_root_value(),
                                    uid,
                                    comm,
                                    &merkle_path,
                                )
                                .unwrap();

                                expected_uid += 1;
                            }
                        }

                        event => {
                            panic!("Expected Memos event, got {:?}", event);
                        }
                    }

                    // Posting the same memos twice should fail.
                    match qs
                        .post_memos(block_id as u64, txn_id as u64, memos.clone(), sig.clone())
                        .await
                    {
                        Err(QueryServiceError::MemosAlreadyPosted { .. }) => {}
                        res => {
                            panic!("Expected error MemosAlreadyPosted, got {:?}", res);
                        }
                    }

                    // We should be able to query the newly posted memos.
                    let (queried_memos, sig) =
                        qs.get_memos(block_id as u64, txn_id as u64).await.unwrap();
                    txn.verify_receiver_memos_signature(&queried_memos, &sig)
                        .unwrap();
                    assert_eq!(queried_memos, *memos);
                }
            }

            for (block_id, (state, block, _, _)) in history.into_iter().enumerate() {
                // We should be able to query the block and state at each time step in the history
                // of the ledger.
                let (qs_state, qs_block) = qs.get_block(block_id as u64).await.unwrap();
                assert_eq!(qs_state.commit(), state.commit());
                assert_eq!(qs_block, block);

                // We should be able to get non-inclusion proofs for new nullifiers.
                let n = Nullifier::random_for_test(&mut rng);
                let (incl, proof) = qs.nullifier_proof(state.nullifiers_root, n).await.unwrap();
                assert!(!incl);
                proof.check(n, &state.nullifiers_root).unwrap();
            }
        });
    }

    // Runs test_query_service() on a few small transaction sequences taken from the multixfr
    // regression tests from lib.rs.
    #[test]
    fn test_query_service_small() {
        test_query_service(
            vec![vec![(true, 0, 0, 0, 0, -2), (true, 0, 0, 0, 0, 0)]],
            0,
            0,
            (0, 0, 0),
            vec![(0, 0, 0)],
        );

        test_query_service(
            vec![vec![(true, 0, 0, 1, 1, 0)], vec![(true, 0, 0, 0, 0, 0)]],
            1,
            0,
            (0, 0, 0),
            vec![],
        );

        test_query_service(
            vec![
                vec![(false, 0, 0, 1, 1, 0)],
                vec![(false, 0, 0, 1, 1, 0)],
                vec![(false, 0, 0, 1, 1, 0)],
            ],
            2,
            1,
            (0, 0, 2),
            vec![],
        );

        test_query_service(
            vec![vec![(true, 0, 1, 1, 1, 0)], vec![(false, 5, 0, 1, 1, 0)]],
            2,
            1,
            (0, 0, 2),
            vec![(0, 0, 2), (0, 0, 2)],
        );
    }

    #[test]
    #[ignore]
    fn quickcheck_query_service() {
        QuickCheck::new()
            .tests(1)
            .quickcheck(test_query_service as fn(Vec<_>, u8, u8, _, Vec<_>) -> ())
    }
}
