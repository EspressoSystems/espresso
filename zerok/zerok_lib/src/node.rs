pub use crate::state_comm::LedgerStateCommitment;
use crate::{
    key_set::SizedKey,
    set_merkle_tree::*,
    validator_node::*,
    wallet::{
        CryptoError, QueryServiceError as QueryServiceWalletError, WalletBackend, WalletError,
        WalletState,
    },
    ElaboratedBlock, ElaboratedTransaction, ProverKeySet, ValidationError, ValidatorState,
    MERKLE_HEIGHT,
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
use jf_txn::{
    keys::{AuditorKeyPair, FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment},
    MerklePath, MerkleTree, Signature,
};
use phaselock::{
    error::PhaseLockError,
    event::EventType,
    handle::{HandleError, PhaseLockHandle},
    BlockContents, H_256,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
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

pub type LightWeightNode<NET, STORE> = PhaseLockHandle<ValidatorNodeImpl<NET, STORE>, H_256>;

#[async_trait]
impl<NET: PLNet, STORE: PLStore> Validator for LightWeightNode<NET, STORE> {
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
                Err(err) => panic!(
                    "unexpected error from PhaseLockHandle::next_event: {:?}",
                    err
                ),
            }
        }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LedgerSummary {
    pub num_blocks: usize,
    pub num_records: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub state: ValidatorState,
    pub nullifiers: SetMerkleTree,
}

#[derive(Clone, Debug)]
pub struct LedgerTransition {
    pub from_state: LedgerSnapshot,
    pub block: ElaboratedBlock,
    // Receiver memos come in asynchronously after a block is committed, on a transaction-by-
    // transaction basis. The list of memos corresponding to each transaction in a block will be
    // None until valid memos for that block are received by the sender. Note that this may never
    // happen if the sender chooses to send the memos directly to the receiver without posting them
    // publicly.
    pub memos: Vec<Option<(Vec<ReceiverMemo>, Signature)>>,
    pub uids: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, strum_macros::AsStaticStr)]
pub enum LedgerEvent {
    /// A new block was added to the ledger.
    ///
    /// Includes the block contents, the unique identifier for the block, and the new state
    /// commitment.
    Commit {
        block: ElaboratedBlock,
        block_id: u64,
        state_comm: LedgerStateCommitment,
    },

    /// A proposed block was rejected.
    ///
    /// Includes the block contents and the reason for rejection.
    Reject {
        block: ElaboratedBlock,
        error: ValidationError,
    },

    /// Receiver memos were posted for one or more previously accepted transactions.
    ///
    /// For each UTXO corresponding to the posted memos, includes the memo, the record commitment,
    /// the unique identifier for the record, and a proof that the record commitment exists in the
    /// current UTXO set.
    Memos {
        outputs: Vec<(ReceiverMemo, RecordCommitment, u64, MerklePath)>,
    },
}

/// A QueryService accumulates the full state of the ledger, making it available for consumption by
/// network APIs and such.
#[async_trait]
pub trait QueryService {
    async fn get_summary(&self) -> Result<LedgerSummary, QueryServiceError>;

    async fn num_blocks(&self) -> Result<usize, QueryServiceError> {
        Ok(self.get_summary().await?.num_blocks)
    }

    /// Get a snapshot of the designated ledger state.
    ///
    /// State 0 is the initial state. Each subsequent snapshot is the state immediately after
    /// applying a block, so `get_snapshot(1)` returns the snapshot after the 0th block is applied,
    /// `get_snapshot(i + 1)` returns the snapshot after the `i`th block is applied, and so on until
    /// `get_snapshot(num_blocks())` returns the current state.
    async fn get_snapshot(&self, index: usize) -> Result<LedgerSnapshot, QueryServiceError>;

    /// Get information about the `i`th block and the state transition it caused.
    ///
    /// The `i`th block is the block which was applied to the `i`th state (see `get_snapshot()`)
    /// resulting in the `i + 1`th state.
    ///
    /// The result includes the `i`th block as well as the `i`th state, from which the resulting
    /// state can be derived by applying the block to the input state. Of course, the resulting
    /// state can also be queried directly by calling `get_snapshot(i + 1)`.
    async fn get_block(&self, index: usize) -> Result<LedgerTransition, QueryServiceError>;

    async fn get_block_id_by_hash(&self, hash: &[u8]) -> Result<usize, QueryServiceError>;

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
        &mut self,
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
    ) -> Result<(Vec<ReceiverMemo>, Signature), QueryServiceError> {
        let LedgerTransition { memos, .. } = self.get_block(block_id as usize).await?;
        memos
            .get(txn_id as usize)
            .cloned()
            .flatten()
            .ok_or(QueryServiceError::InvalidTxnId {})
    }

    /// Make your public key and address known to other nodes.
    async fn introduce(&mut self, pub_key: &UserPubKey) -> Result<(), QueryServiceError>;

    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError>;
}

#[derive(Clone, Debug, Snafu, Serialize, Deserialize)]
pub enum QueryServiceError {
    InvalidNullifierRoot {},
    InvalidBlockId {},
    InvalidBlockHash {},
    InvalidTxnId {},
    MemosAlreadyPosted {},
    InvalidSignature {},
    WrongNumberOfMemos { expected: usize },
    NoMemosForTxn {},
    InvalidAddress {},
}

struct FullState {
    validator: ValidatorState,
    nullifiers: SetMerkleTree,
    known_nodes: HashMap<UserAddress, UserPubKey>,
    // Map from past nullifier set root hashes to the index of the state in which that root hash
    // occurred.
    past_nullifiers: HashMap<set_hash::Hash, usize>,
    // All past states and state transitions of the ledger.
    history: Vec<LedgerTransition>,
    // Block IDs indexed by block hash.
    block_hashes: HashMap<Vec<u8>, usize>,
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
                    self.send_event(LedgerEvent::Reject {
                        block: self.proposed.clone(),
                        error: err,
                    });
                }

                // PhaseLock errors that don't relate to blocks being rejected (view timeouts,
                // network errors, etc.) do not correspond to LedgerEvents.
            }

            Propose { block } => {
                self.proposed = (*block).clone();
            }

            Decide { block, state } => {
                for (block, state) in block.iter().zip(state.iter()).rev() {
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
                            // Archive the old state.
                            let index = self.history.len();
                            self.past_nullifiers.insert(self.nullifiers.hash(), index);
                            self.block_hashes
                                .insert(Vec::from(block.hash().as_ref()), index);
                            let block_uids = block
                                .block
                                .0
                                .iter()
                                .map(|txn| {
                                    // Split the uids corresponding to this transaction off the front of
                                    // the list of uids for the whole block.
                                    let mut this_txn_uids = uids.split_off(txn.output_len());
                                    std::mem::swap(&mut this_txn_uids, &mut uids);
                                    assert_eq!(this_txn_uids.len(), txn.output_len());
                                    this_txn_uids
                                })
                                .collect();
                            self.history.push(LedgerTransition {
                                from_state: LedgerSnapshot {
                                    state: prev_state,
                                    nullifiers: self.nullifiers.clone(),
                                },
                                block: (*block).clone(),
                                memos: vec![None; block.block.0.len()],
                                uids: block_uids,
                            });

                            // Add the results of this block to our current state.
                            for txn in block.block.0.iter() {
                                for n in txn.nullifiers() {
                                    self.nullifiers.insert(n);
                                }
                            }
                            assert_eq!(self.nullifiers.hash(), self.validator.nullifiers_root);

                            // Notify subscribers of the new block.
                            self.send_event(LedgerEvent::Commit {
                                block: (*block).clone(),
                                block_id: index as u64,
                                state_comm: self.validator.commit(),
                            });
                        }
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

    fn post_memos(
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
        let LedgerTransition {
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
        let event = LedgerEvent::Memos {
            outputs: izip!(
                new_memos,
                txn.output_commitments(),
                uids.iter().cloned(),
                merkle_paths
            )
            .collect(),
        };
        self.send_event(event);

        Ok(())
    }

    fn introduce(&mut self, pub_key: &UserPubKey) {
        self.known_nodes.insert(pub_key.address(), pub_key.clone());
    }

    fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        self.known_nodes
            .get(address)
            .cloned()
            .ok_or(QueryServiceError::InvalidAddress {})
    }
}

/// A QueryService that aggregates the full ledger state by observing consensus.
#[derive(Clone)]
pub struct PhaseLockQueryService<'a> {
    univ_param: &'a jf_txn::proof::UniversalParam,
    state: Arc<RwLock<FullState>>,
    // When dropped, this handle will cancel and join the event handling task. It is not used
    // explicitly; it is merely stored with the rest of the struct for the auto-generated drop glue.
    _event_task: Arc<RemoteHandle<()>>,
}

impl<'a> PhaseLockQueryService<'a> {
    pub fn new(
        event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        univ_param: &'a jf_txn::proof::UniversalParam,
        mut validator: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
    ) -> Self {
        //todo !jeb.bearer If we are not starting from the genesis of the ledger, query the full
        // state at this point from another full node, like
        //  let state = other_node.full_state(validator.commit());
        // For now, just assume we are starting at the beginning:
        let history = Vec::new();
        let block_hashes = HashMap::new();
        let events = Vec::new();
        // Use the unpruned record Merkle tree.
        assert_eq!(
            record_merkle_tree.get_root_value(),
            validator.record_merkle_frontier.get_root_value()
        );
        validator.record_merkle_frontier = record_merkle_tree;

        let state = Arc::new(RwLock::new(FullState {
            validator,
            nullifiers,
            known_nodes: Default::default(),
            past_nullifiers: HashMap::new(),
            history,
            block_hashes,
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
                    {
                        // Broadcast the initial receiver memos so that clients can access the
                        // records they have been granted at ledger setup time.
                        let mut state = state.write().await;
                        let (memos, uids): (Vec<_>, Vec<_>) = unspent_memos.into_iter().unzip();
                        let (comms, merkle_paths): (Vec<_>, Vec<_>) = uids
                            .iter()
                            .map(|uid| {
                                state
                                    .validator
                                    .record_merkle_frontier
                                    .get_leaf(*uid)
                                    .expect_ok()
                                    .unwrap()
                            })
                            .unzip();
                        let comms = comms
                            .into_iter()
                            .map(RecordCommitment::from_field_element)
                            .collect::<Vec<_>>();
                        state.send_event(LedgerEvent::Memos {
                            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
                        });
                    }

                    // Handle events as they come in from the network.
                    while let Some(event) = event_source.next().await {
                        state.write().await.update(event);
                    }
                })
                .unwrap()
        };

        Self {
            univ_param,
            state,
            _event_task: Arc::new(task),
        }
    }
}

#[async_trait]
impl<'a> QueryService for PhaseLockQueryService<'a> {
    async fn get_summary(&self) -> Result<LedgerSummary, QueryServiceError> {
        let state = self.state.read().await;
        Ok(LedgerSummary {
            num_blocks: state.history.len(),
            num_records: state.validator.record_merkle_frontier.num_leaves() as usize,
        })
    }

    async fn get_snapshot(&self, index: usize) -> Result<LedgerSnapshot, QueryServiceError> {
        use std::cmp::Ordering::*;
        let state = self.state.read().await;
        match index.cmp(&state.history.len()) {
            Less => Ok(state.history[index].from_state.clone()),
            Equal => Ok(LedgerSnapshot {
                state: state.validator.clone(),
                nullifiers: state.nullifiers.clone(),
            }),
            Greater => Err(QueryServiceError::InvalidBlockId {}),
        }
    }

    async fn get_block(&self, index: usize) -> Result<LedgerTransition, QueryServiceError> {
        let state = self.state.read().await;
        state
            .history
            .get(index)
            .cloned()
            .ok_or(QueryServiceError::InvalidBlockId {})
    }

    async fn get_block_id_by_hash(&self, hash: &[u8]) -> Result<usize, QueryServiceError> {
        let state = self.state.read().await;
        state
            .block_hashes
            .get(hash)
            .cloned()
            .ok_or(QueryServiceError::InvalidBlockHash {})
    }

    async fn nullifier_proof(
        &self,
        root: set_hash::Hash,
        n: Nullifier,
    ) -> Result<(bool, SetMerkleProof), QueryServiceError> {
        let state = self.state.read().await;

        let nullifiers = if root == state.nullifiers.hash() {
            &state.nullifiers
        } else {
            state
                .past_nullifiers
                .get(&root)
                .map(|index| &state.history[*index].from_state.nullifiers)
                .ok_or(QueryServiceError::InvalidNullifierRoot {})?
        };
        Ok(nullifiers.contains(n).unwrap())
    }

    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent> {
        let mut state = self.state.write().await;
        state.subscribe(i)
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), QueryServiceError> {
        let mut state = self.state.write().await;
        state.post_memos(block_id, txn_id, memos, sig)
    }

    async fn introduce(&mut self, pub_key: &UserPubKey) -> Result<(), QueryServiceError> {
        self.state.write().await.introduce(pub_key);
        Ok(())
    }

    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        self.state.read().await.get_user(address)
    }
}

/// A full node is a QueryService running alongside a lightweight validator.
#[derive(Clone)]
pub struct FullNode<'a, NET: PLNet, STORE: PLStore> {
    validator: LightWeightNode<NET, STORE>,
    query_service: PhaseLockQueryService<'a>,
}

impl<'a, NET: PLNet, STORE: PLStore> FullNode<'a, NET, STORE> {
    pub fn new(
        validator: LightWeightNode<NET, STORE>,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        univ_param: &'a jf_txn::proof::UniversalParam,
        state: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
    ) -> Self {
        let query_service = PhaseLockQueryService::new(
            validator.subscribe(),
            univ_param,
            state,
            record_merkle_tree,
            nullifiers,
            unspent_memos,
        );
        Self {
            validator,
            query_service,
        }
    }

    fn as_validator(
        &self,
    ) -> &impl Validator<Event = <FullNode<'a, NET, STORE> as Validator>::Event> {
        &self.validator
    }

    fn as_query_service(&self) -> &(impl QueryService + 'a) {
        &self.query_service
    }

    fn as_query_service_mut(&mut self) -> &mut (impl QueryService + 'a) {
        &mut self.query_service
    }
}

#[async_trait]
impl<'a, NET: PLNet, STORE: PLStore> Validator for FullNode<'a, NET, STORE> {
    type Event = <LightWeightNode<NET, STORE> as Validator>::Event;

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
impl<'a, NET: PLNet, STORE: PLStore> QueryService for FullNode<'a, NET, STORE> {
    async fn get_summary(&self) -> Result<LedgerSummary, QueryServiceError> {
        self.as_query_service().get_summary().await
    }

    async fn get_snapshot(&self, index: usize) -> Result<LedgerSnapshot, QueryServiceError> {
        self.as_query_service().get_snapshot(index).await
    }

    async fn get_block(&self, index: usize) -> Result<LedgerTransition, QueryServiceError> {
        self.as_query_service().get_block(index).await
    }

    async fn get_block_id_by_hash(&self, hash: &[u8]) -> Result<usize, QueryServiceError> {
        self.as_query_service().get_block_id_by_hash(hash).await
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
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), QueryServiceError> {
        self.as_query_service_mut()
            .post_memos(block_id, txn_id, memos, sig)
            .await
    }

    async fn introduce(&mut self, pub_key: &UserPubKey) -> Result<(), QueryServiceError> {
        self.as_query_service_mut().introduce(pub_key).await
    }

    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        self.as_query_service().get_user(address).await
    }
}

#[async_trait]
impl<'a, NET: PLNet, STORE: PLStore> WalletBackend<'a> for FullNode<'a, NET, STORE> {
    type EventStream = EventStream<LedgerEvent>;

    async fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
        // There is no storage backend implemented yet, so load() always returns a fresh wallet from
        // the start of the history of the ledger.
        let mut rng = ChaChaRng::from_entropy();
        let snapshot = self.as_query_service().get_snapshot(0).await.unwrap();
        let validator = snapshot.state;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.query_service.univ_param;
        let proving_keys =
            ProverKeySet {
                mint: jf_txn::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                    .context(CryptoError)?
                    .0,
                freeze: validator
                    .verif_crs
                    .freeze
                    .iter()
                    .map(|k| {
                        Ok(jf_txn::proof::freeze::preprocess(
                            univ_param,
                            k.num_inputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0)
                    })
                    .collect::<Result<_, _>>()?,
                xfr: validator
                    .verif_crs
                    .xfr
                    .iter()
                    .map(|k| {
                        Ok(jf_txn::proof::transfer::preprocess(
                            univ_param,
                            k.num_inputs(),
                            k.num_outputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0)
                    })
                    .collect::<Result<_, _>>()?,
            };

        // Publish the address of the new wallet.
        self.query_service
            .state
            .write()
            .await
            .introduce(&key_pair.pub_key());

        Ok(WalletState {
            validator,
            proving_keys,
            nullifiers: snapshot.nullifiers,
            now: 0,
            records: Default::default(),
            defined_assets: Default::default(),
            pending_txns: Default::default(),
            expiring_txns: Default::default(),
            auditable_assets: Default::default(),
            auditor_key_pair: AuditorKeyPair::generate(&mut rng),
            freezer_key_pair: FreezerKeyPair::generate(&mut rng),
            rng,
        })
    }

    async fn store(
        &mut self,
        _key_pair: &UserKeyPair,
        _state: &WalletState,
    ) -> Result<(), WalletError> {
        Ok(())
    }

    async fn subscribe(&self, starting_at: u64) -> Self::EventStream {
        self.as_query_service().subscribe(starting_at).await
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        self.as_query_service()
            .get_user(address)
            .await
            .map_err(|err| match err {
                QueryServiceError::InvalidAddress {} => WalletError::InvalidAddress {
                    address: address.clone(),
                },
                _ => WalletError::QueryServiceError { source: err },
            })
    }

    async fn prove_nullifier_unspent(
        &self,
        root: set_hash::Hash,
        nullifier: Nullifier,
    ) -> Result<SetMerkleProof, WalletError> {
        let (spent, proof) = self
            .as_query_service()
            .nullifier_proof(root, nullifier)
            .await
            .context(QueryServiceWalletError)?;
        if spent {
            Err(WalletError::NullifierAlreadyPublished { nullifier })
        } else {
            Ok(proof)
        }
    }

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
        self.as_validator()
            .submit_transaction(txn)
            .await
            .map_err(|err| match err {
                PhaseLockError::NetworkFault { source } => WalletError::NetworkError { source },
                _ => {
                    // PhaseLock is not supposed to return errors besides NetworkFault
                    WalletError::Failed {
                        msg: format!(
                            "unexpected error from Validator::submit_transaction: {:?}",
                            err
                        ),
                    }
                }
            })
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError> {
        self.as_query_service_mut()
            .post_memos(block_id, txn_id, memos, sig)
            .await
            .context(QueryServiceWalletError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        wallet::Wallet, LWPersistence, MultiXfrRecordSpec, MultiXfrTestState, UNIVERSAL_PARAM,
    };
    use async_std::task::block_on;
    use jf_primitives::jubjub_dsa::KeyPair;
    use jf_txn::{sign_receiver_memos, structs::AssetCode, MerkleTree};
    use phaselock::{
        tc::SecretKeySet,
        traits::storage::memory_storage::MemoryStorage,
        {PhaseLock, PhaseLockConfig},
    };
    use quickcheck::QuickCheck;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use rand_xoshiro::Xoshiro256StarStar;

    #[derive(Debug)]
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
        (
            ValidatorState,
            MerkleTree,
            SetMerkleTree,
            Vec<(ReceiverMemo, u64)>,
        ),
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
        let initial_state = (
            state.validator.clone(),
            state.record_merkle_tree.clone(),
            state.nullifiers.clone(),
            state.unspent_memos(),
        );

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
                        block: Arc::new(vec![block]),
                        state: Arc::new(vec![state]),
                    },
                },
            )));
            let mut qs = PhaseLockQueryService::new(
                events,
                &*UNIVERSAL_PARAM,
                initial_state.0,
                initial_state.1,
                initial_state.2,
                initial_state.3,
            );

            // The first event gives receiver memos for the records in the initial state of the
            // ledger. We can skip that to get to the real events starting at index 1.
            let mut events = qs.subscribe(1).await;
            for (_, hist_block, _, hist_state) in history.iter() {
                match events.next().await.unwrap() {
                    LedgerEvent::Commit { block, .. } => {
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
                        LedgerEvent::Memos { outputs } => {
                            // After successfully posting memos, we should get a Memos event.
                            for ((memo, comm, uid, merkle_path), (expected_memo, expected_comm)) in
                                outputs
                                    .into_iter()
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
                                    comm.to_field_element(),
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
                let LedgerTransition {
                    from_state:
                        LedgerSnapshot {
                            state: qs_state, ..
                        },
                    block: qs_block,
                    ..
                } = qs.get_block(block_id).await.unwrap();
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

    #[test]
    fn test_full_node_wallet_backend_load() {
        block_on(async {
            // Initialize ledger state
            let records = (
                MultiXfrRecordSpec {
                    asset_def_ix: 1,
                    owner_key_ix: 0,
                    asset_amount: 2,
                },
                vec![],
            );
            let mut state = MultiXfrTestState::initialize([0x42u8; 32], 2, 2, records).unwrap();

            // Set up a validator.
            let id = 0;
            let secret_keys = SecretKeySet::random(
                0,
                &mut <Xoshiro256StarStar as phaselock::rand::SeedableRng>::seed_from_u64(
                    state.prng.next_u64(),
                ),
            );
            let secret_key_share = secret_keys.secret_key_share(id);
            let public_keys = secret_keys.public_keys();
            let pub_key = phaselock::PubKey::from_secret_key_set_escape_hatch(&secret_keys, id);
            let port = 10010;
            let network =
                phaselock::networking::w_network::WNetwork::new(pub_key.clone(), port, None)
                    .await
                    .unwrap();
            let (c, sync) = futures::channel::oneshot::channel();
            for task in network.generate_task(c).unwrap() {
                async_std::task::spawn(task);
            }
            sync.await.unwrap();
            let config = PhaseLockConfig {
                total_nodes: 1,
                threshold: 1,
                max_transactions: 100,
                known_nodes: vec![pub_key],
                next_view_timeout: 10000,
                timeout_ratio: (11, 10),
                round_start_delay: 1,
                start_delay: 1,
            };
            let (_, phaselock) = PhaseLock::init(
                ElaboratedBlock::default(),
                public_keys,
                secret_key_share,
                id,
                config,
                state.validator.clone(),
                network,
                MemoryStorage::default(),
                LWPersistence::new("test_full_node_wallet_backend_load"),
            )
            .await;

            // Set up a full node
            let unspent_memos = state.unspent_memos();
            let mut node = FullNode::new(
                phaselock,
                state.univ_setup,
                state.validator,
                state.record_merkle_tree,
                state.nullifiers,
                unspent_memos,
            );

            // Introduce another user whom we will transfer some assets to.
            let mut pub_keys = state.keys;
            let me = pub_keys.remove(0);
            let other = pub_keys.remove(1);
            node.introduce(&other.pub_key()).await.unwrap();

            // Set up a wallet
            node.start_consensus().await;
            let mut wallet = Wallet::new(me, node).await.unwrap();

            // Wait for the wallet to process the initial receiver memos and check that it correctly
            // discovers its initial balance.
            wallet.sync(1).await.unwrap();
            // MultiXfrTestState doubles all the initial records for some reason, so we expect to
            // have 4 coins, not 2.
            assert_eq!(wallet.balance(&state.asset_defs[1].code).await, 4);
            // We start with 2^32 native tokens, but spend 2 minting our two non-native records.
            assert_eq!(wallet.balance(&AssetCode::native()).await, (1u64 << 32) - 2);

            // Transfer 3 of our 4 coins away to another user. We should end up with only 1 coin,
            // which can only happen if
            //  1. our initial 4 coins are put on hold (the transaction is initiated)
            //  2. we receive our 1-coin change record (the transaction is completed)
            wallet
                .transfer(&state.asset_defs[1].code, &[(other.address(), 3)], 1)
                .await
                .unwrap();
            // Wait for 2 more events: the Commit event and the following Memos event.
            wallet.sync(3).await.unwrap();
            assert_eq!(wallet.balance(&state.asset_defs[1].code).await, 1);
            assert_eq!(wallet.balance(&AssetCode::native()).await, (1u64 << 32) - 3);
        });
    }
}
