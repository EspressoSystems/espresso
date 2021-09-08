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
use jf_txn::structs::Nullifier;
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
    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock);

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
}

#[derive(Clone, Debug)]
pub enum QueryServiceError {
    InvalidNullifierRoot {},
}

struct FullState {
    validator: ValidatorState,
    nullifiers: HashMap<set_hash::Hash, SetMerkleTree>,
    // All past states and state transitions of the ledger.
    history: Vec<(ValidatorState, ElaboratedBlock)>,
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
                if self
                    .validator
                    .validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        block.block.clone(),
                        block.proofs.clone(),
                        true,
                    )
                    .is_err()
                    || self.validator.commit() != state.commit()
                {
                    // We update our ValidatorState for each block committed by the PhaseLock event
                    // source, so we shouldn't ever get out of sync.
                    panic!("state is out of sync with validator");
                } else {
                    // Add the results of this block to our state.
                    let mut new_nullifiers = self.nullifiers[&prev_state.nullifiers_root].clone();
                    for txn in block.block.0.iter() {
                        for n in txn.nullifiers() {
                            new_nullifiers.insert(n);
                        }
                    }
                    assert_eq!(new_nullifiers.hash(), self.validator.nullifiers_root);
                    self.nullifiers
                        .insert(new_nullifiers.hash(), new_nullifiers);
                    self.history.push((prev_state, (*block).clone()));

                    // Notify subscribers of the new block.
                    //todo !jeb.bearer get receiver memos somehow
                    self.send_event(LedgerEvent::Commit((*block).clone(), vec![]));
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
    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock) {
        let state = self.state.read().await;
        state.history[i as usize].clone()
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
    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MultiXfrRecordSpec, MultiXfrTestState};
    use async_std::task::block_on;
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
        Vec<(ValidatorState, ElaboratedBlock, ValidatorState)>,
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
            for (ix, keys_and_memos, txn) in txns {
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                let _ = state.try_add_transaction(&mut blk, txn, i, ix, num_txs, owner_memos, kixs);
            }

            let prev_state = state.validator.clone();
            state
                .validate_and_apply(blk.clone(), i, num_txs, generation_time)
                .unwrap();
            history.push((prev_state, blk, state.validator.clone()));
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
        block_on(async {
            let (initial_state, history) =
                generate_valid_history(txs, nkeys, ndefs, init_rec, init_recs);
            assert_eq!(initial_state.0.commit(), history[0].0.commit());
            let events = Box::pin(stream::iter(history.clone().into_iter().map(
                |(_, block, state)| MockConsensusEvent {
                    event: EventType::Decide {
                        block: Arc::new(block),
                        state: Arc::new(state),
                    },
                },
            )));
            let qs = PhaseLockQueryService::new(events, initial_state.0, initial_state.1);

            let mut events = qs.subscribe(0).await;
            for (_, hist_block, hist_state) in history.iter() {
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

            for (i, (state, block, _)) in history.into_iter().enumerate() {
                // We should be able to query the block and state at each time step in the history
                // of the ledger.
                let (qs_state, qs_block) = qs.get_block(i as u64).await;
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
