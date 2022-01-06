use crate::full_persistence::FullPersistence;
pub use crate::state::state_comm::LedgerStateCommitment;
use crate::util::arbitrary_wrappers::*;
use crate::{
    ledger, ser_test,
    set_merkle_tree::*,
    state::{ElaboratedBlock, ElaboratedTransaction, ValidationError, ValidatorState},
    validator_node::*,
};
use arbitrary::Arbitrary;
use async_executors::exec::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::RemoteHandle;
pub use futures::prelude::*;
pub use futures::stream::Stream;
use futures::task::SpawnExt;
use itertools::izip;
use jf_aap::{
    keys::{UserAddress, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment},
    MerklePath, MerkleTree, Signature,
};
use jf_primitives::merkle_tree::FilledMTBuilder;
use ledger::{AAPLedger, Block, Ledger, StateCommitment};
use phaselock::{
    types::error::PhaseLockError,
    types::event::EventType,
    types::handle::{HandleError, PhaseLockHandle},
    BlockContents, H_256,
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
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
    async fn current_state(&self) -> Arc<ValidatorState>;
    fn subscribe(&self) -> EventStream<Self::Event>;
}

pub type LightWeightNode<NET, STORE> = PhaseLockHandle<ValidatorNodeImpl<NET, STORE>, H_256>;

#[async_trait]
impl<NET: PLNet, STORE: PLStore> Validator for LightWeightNode<NET, STORE> {
    type Event = PhaseLockEvent;

    async fn current_state(&self) -> Arc<ValidatorState> {
        self.get_state().await
    }

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

#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct LedgerSummary {
    pub num_blocks: usize,
    pub num_txns: usize,
    pub num_records: usize,
    pub num_events: usize,
}

#[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MerkleTreeWithArbitrary(pub MerkleTree);

impl<'a> Arbitrary<'a> for MerkleTreeWithArbitrary {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut mt = MerkleTree::new(3).unwrap();
        for _ in 0..15 {
            // todo: range restricted random depth and count
            mt.push(u.arbitrary::<ArbitraryBaseField>()?.into());
        }
        Ok(MerkleTreeWithArbitrary(mt))
    }
}

#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerSnapshot {
    pub state: ValidatorState,
    pub state_comm: LedgerStateCommitment,
    pub nullifiers: SetMerkleTree,
    pub records: MerkleTreeWithArbitrary,
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
#[serde(bound = "")]
pub enum LedgerEvent<L: Ledger = AAPLedger> {
    /// A new block was added to the ledger.
    ///
    /// Includes the block contents, the unique identifier for the block, and the new state
    /// commitment.
    Commit {
        block: Block<L>,
        block_id: u64,
        state_comm: StateCommitment<L>,
    },

    /// A proposed block was rejected.
    ///
    /// Includes the block contents and the reason for rejection.
    Reject {
        block: Block<L>,
        error: ValidationError,
    },

    /// Receiver memos were posted for one or more previously accepted transactions.
    ///
    /// For each UTXO corresponding to the posted memos, includes the memo, the record commitment,
    /// the unique identifier for the record, and a proof that the record commitment exists in the
    /// current UTXO set.
    ///
    /// If these memos correspond to a committed transaction, the (block_id, transaction_id) are
    /// included in `transaction`.
    Memos {
        outputs: Vec<(ReceiverMemo, RecordCommitment, u64, MerklePath)>,
        transaction: Option<(u64, u64)>,
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
    async fn get_snapshot(
        &self,
        index: usize,
        sparse_records: bool,
        sparse_nullifiers: bool,
    ) -> Result<LedgerSnapshot, QueryServiceError>;

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

    // TODO !keyao Return commitments and UIDs as well: https://gitlab.com/translucence/systems/system/-/issues/39.
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

    async fn get_users(&self) -> Result<HashMap<UserAddress, UserPubKey>, QueryServiceError>;
    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError>;
}

#[derive(Clone, Debug, Snafu, Serialize, Deserialize)]
pub enum QueryServiceError {
    InvalidNullifierRoot {},
    #[snafu(display("invalid block id {} (only {} blocks)", index, num_blocks))]
    InvalidBlockId {
        index: usize,
        num_blocks: usize,
    },
    InvalidBlockHash {},
    InvalidTxnId {},
    InvalidRecordId {},
    InvalidHistoricalIndex {},
    MemosAlreadyPosted {},
    InvalidSignature {},
    WrongNumberOfMemos {
        expected: usize,
    },
    NoMemosForTxn {},
    InvalidAddress {},
    #[snafu(display("persistence error: {}", msg))]
    PersistenceError {
        msg: String,
    },
}

struct FullState {
    validator: ValidatorState,
    full_persisted: FullPersistence,
    // Sparse record Merkle tree containing leaves only for those records which have been committed
    // but for which memos have not yet been posted. When the memos arrive, we will use this tree
    // to authenticate the new memos to listeners, and then forget them to keep this tree from
    // growing unbounded.
    //todo replace with persistent range-mapping-based Merkle tree
    records_pending_memos: MerkleTree,
    // Map from past nullifier set root hashes to the index of the state in which that root hash
    // occurred.
    //todo replace with persistent key value store
    past_nullifiers: HashMap<set_hash::Hash, usize>,
    // Block IDs indexed by block hash.
    //todo replace with persistent key value store
    block_hashes: HashMap<Vec<u8>, usize>,
    // Total number of committed transactions, aggregated across all blocks.
    num_txns: usize,
    // The last block which was proposed. This is currently used to correllate BadBlock and
    // InconsistentBlock errors from PhaseLock with the block that caused the error. In the future,
    // PhaseLock errors will contain the bad block (or some kind of reference to it, perhaps through
    // persistent storage) and this will not be necessary.
    proposed: ElaboratedBlock,
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
                    // A block has been committed. Update our mirror of the ValidatorState by applying
                    // the new block, and generate a Commit event.

                    match self.validator.validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        block.block.clone(),
                        block.proofs.clone(),
                    ) {
                        // We update our ValidatorState for each block committed by the PhaseLock event
                        // source, so we shouldn't ever get out of sync.
                        Err(_) => panic!("state is out of sync with validator"),
                        Ok(_) if self.validator.commit() != state.commit() => {
                            panic!("state is out of sync with validator")
                        }

                        Ok(mut uids) => {
                            let hist_index = self.full_persisted.state_iter().len();
                            assert!(hist_index > 0);
                            let block_index = hist_index - 1;

                            self.full_persisted.store_for_commit(block, state);
                            self.past_nullifiers
                                .insert(self.validator.nullifiers_root, hist_index);
                            self.block_hashes
                                .insert(Vec::from(block.hash().as_ref()), block_index);
                            let block_uids = block
                                .block
                                .txns
                                .iter()
                                .map(|txn| {
                                    // Split the uids corresponding to this transaction off the front of
                                    // the list of uids for the whole block.
                                    let mut this_txn_uids = uids.split_off(txn.output_len());
                                    std::mem::swap(&mut this_txn_uids, &mut uids);
                                    assert_eq!(this_txn_uids.len(), txn.output_len());
                                    this_txn_uids
                                })
                                .collect::<Vec<_>>();
                            self.full_persisted.store_block_uids(&block_uids);
                            self.full_persisted
                                .store_memos(&vec![None; block.block.txns.len()]);

                            // Add the results of this block to our current state.
                            let mut nullifiers =
                                self.full_persisted.get_latest_nullifier_set().unwrap();
                            for txn in block.block.txns.iter() {
                                for n in txn.nullifiers() {
                                    nullifiers.insert(n);
                                }
                                for o in txn.output_commitments() {
                                    self.records_pending_memos.push(o.to_field_element());
                                }
                            }
                            self.num_txns += block.block.txns.len();
                            assert_eq!(nullifiers.hash(), self.validator.nullifiers_root);
                            assert_eq!(
                                self.records_pending_memos.commitment(),
                                self.validator.record_merkle_commitment
                            );
                            self.full_persisted.store_nullifier_set(&nullifiers);
                            self.full_persisted.commit_accepted();

                            // Notify subscribers of the new block.
                            self.send_event(LedgerEvent::Commit {
                                block: (*block).clone(),
                                block_id: block_index as u64,
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
        let now = self.full_persisted.events_iter().len() as u64;
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
        self.full_persisted.store_event(&event);
        self.full_persisted.commit_events();
    }

    fn subscribe(&mut self, t: u64) -> EventStream<LedgerEvent> {
        let (sender, receiver) = mpsc::unbounded();
        if (t as usize) < self.full_persisted.events_iter().len() {
            // If the start time is in the past, send the subscriber all saved events since the
            // start time and make them an active subscriber starting now.
            self.subscribers.push(sender);
            let past_events = self
                .full_persisted
                .events_iter()
                .skip(t as usize)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            Box::pin(stream::iter(past_events).chain(receiver))
        } else {
            // Otherwise, add the subscriber to the list of pending subscribers to start receiving
            // events at time `t`.
            self.pending_subscribers.entry(t).or_default().push(sender);
            Box::pin(receiver)
        }
    }

    fn get_snapshot(
        &self,
        index: usize,
        sparse_records: bool,
        sparse_nullifiers: bool,
    ) -> Result<LedgerSnapshot, QueryServiceError> {
        let state = self
            .full_persisted
            .state_iter()
            .nth(index)
            .ok_or(QueryServiceError::InvalidHistoricalIndex {})?
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })?;
        let records = if sparse_records {
            // We can reconstruct a sparse Merkle tree out of the commitment stored in the
            // corresponing lightweight state.
            //
            // The records commitment and frontier in `state` have already been validated,
            // so it is safe to unwrap here.
            MerkleTree::restore_from_frontier(
                state.record_merkle_commitment,
                &state.record_merkle_frontier,
            )
            .unwrap()
        } else {
            // To reconstruct a full Merkle tree, we have to actually iterate over all of
            // stored leaves and build up a new tree.
            let mut builder = FilledMTBuilder::new(state.record_merkle_commitment.height).unwrap();
            for leaf in self
                .full_persisted
                .rmt_leaf_iter()
                .take(state.record_merkle_commitment.num_leaves as usize)
            {
                builder.push(
                    leaf.map_err(|err| QueryServiceError::PersistenceError {
                        msg: err.to_string(),
                    })?
                    .0,
                );
            }
            let tree = builder.build();
            assert_eq!(tree.commitment(), state.record_merkle_commitment);
            tree
        };

        let full_nullifiers = self
            .full_persisted
            .nullifier_set_iter()
            .nth(index)
            .ok_or(QueryServiceError::InvalidHistoricalIndex {})?
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })?;
        let nullifiers = if sparse_nullifiers {
            SetMerkleTree::sparse(full_nullifiers.hash())
        } else {
            full_nullifiers
        };

        Ok(LedgerSnapshot {
            state_comm: state.commit(),
            state,
            records: MerkleTreeWithArbitrary(records),
            nullifiers,
        })
    }

    fn get_block(&self, index: usize) -> Result<LedgerTransition, QueryServiceError> {
        let num_blocks = self.full_persisted.block_iter().len();
        if index >= self.full_persisted.block_iter().len() {
            return Err(QueryServiceError::InvalidBlockId { index, num_blocks });
        }

        let from_state = self.get_snapshot(index, true, true)?;
        Ok(LedgerTransition {
            from_state,
            block: self
                .full_persisted
                .block_iter()
                .nth(index)
                .unwrap()
                .map_err(|err| QueryServiceError::PersistenceError {
                    msg: err.to_string(),
                })?,
            memos: self
                .full_persisted
                .memos_iter()
                .nth(index)
                .unwrap()
                .map_err(|err| QueryServiceError::PersistenceError {
                    msg: err.to_string(),
                })?,
            uids: self
                .full_persisted
                .block_uids_iter()
                .nth(index)
                .unwrap()
                .map_err(|err| QueryServiceError::PersistenceError {
                    msg: err.to_string(),
                })?,
        })
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

        // Get the information about the committed block containing the relevant transaction.
        let LedgerTransition {
            block, uids, memos, ..
        } = self.get_block(block_id)?;
        let num_txns = block.block.txns.len();
        assert_eq!(uids.len(), num_txns);
        assert_eq!(block.proofs.len(), num_txns);

        // Validate `txn_id` and get the relevant information for the transaction within `block`.
        if txn_id >= num_txns {
            return Err(QueryServiceError::InvalidTxnId {});
        }
        let txn = &block.block.txns[txn_id];
        let uids = &uids[txn_id];

        // Validate the new memos.
        if memos[txn_id].is_some() {
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

        // Authenticate the validity of the records corresponding to the memos.
        let merkle_tree = &mut self.records_pending_memos;
        let merkle_paths = uids
            .iter()
            .map(|uid| merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path)
            .collect::<Vec<_>>();
        // Once we have generated proofs for the memos, we will not need to generate proofs for
        // these records again (unless specifically requested) so there is no need to keep them in
        // memory.
        for uid in uids {
            merkle_tree.forget(*uid);
        }

        // Store and broadcast the new memos.
        //todo !jeb.bearer update memos in storage
        let event = LedgerEvent::Memos {
            outputs: izip!(
                new_memos,
                txn.output_commitments(),
                uids.iter().cloned(),
                merkle_paths
            )
            .collect(),
            transaction: Some((block_id as u64, txn_id as u64)),
        };
        self.send_event(event);

        Ok(())
    }

    fn introduce(&mut self, pub_key: &UserPubKey) -> Result<(), QueryServiceError> {
        let mut known_nodes = self
            .full_persisted
            .get_latest_known_nodes()
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })?;
        known_nodes.insert(pub_key.address(), pub_key.clone());
        self.full_persisted.update_known_nodes(&known_nodes);
        self.full_persisted.commit_known_nodes();
        Ok(())
    }

    fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        let known_nodes = self
            .full_persisted
            .get_latest_known_nodes()
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })?;
        known_nodes
            .get(address)
            .cloned()
            .ok_or(QueryServiceError::InvalidAddress {})
    }
}

/// A QueryService that aggregates the full ledger state by observing consensus.
pub struct PhaseLockQueryService<'a> {
    _univ_param: &'a jf_aap::proof::UniversalParam,
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
        univ_param: &'a jf_aap::proof::UniversalParam,
        mut validator: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
        mut full_persisted: FullPersistence,
    ) -> Self {
        //todo !jeb.bearer If we are not starting from the genesis of the ledger, query the full
        // state at this point from another full node, like
        //  let state = other_node.full_state(validator.commit());
        // For now, just assume we are starting at the beginning:
        let block_hashes = HashMap::new();
        // Use the unpruned record Merkle tree.
        assert_eq!(
            record_merkle_tree.commitment(),
            validator.record_merkle_commitment
        );

        let record_merkle_commitment = record_merkle_tree.commitment();
        let record_merkle_frontier = record_merkle_tree.frontier();
        // There have not yet been any transactions, so we are not expecting to receive any memos.
        // Therefore, the set of record commitments that are pending the receipt of corresponding
        // memos is the completely sparse merkle tree.
        let records_pending_memos =
            MerkleTree::restore_from_frontier(record_merkle_commitment, &record_merkle_frontier)
                .unwrap();

        validator.record_merkle_commitment = record_merkle_commitment;
        validator.record_merkle_frontier = record_merkle_frontier;

        // Commit the initial state.
        full_persisted.store_initial(&validator, &record_merkle_tree, &nullifiers);

        let state = Arc::new(RwLock::new(FullState {
            validator,
            records_pending_memos,
            full_persisted,
            past_nullifiers: vec![(nullifiers.hash(), 0)].into_iter().collect(),
            num_txns: 0,
            block_hashes,
            proposed: ElaboratedBlock::default(),
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
                                record_merkle_tree
                                    .get_leaf(*uid)
                                    .expect_ok()
                                    .map(|(_, proof)| (proof.leaf.0, proof.path))
                                    .unwrap()
                            })
                            .unzip();
                        let comms = comms
                            .into_iter()
                            .map(RecordCommitment::from_field_element)
                            .collect::<Vec<_>>();
                        state.send_event(LedgerEvent::Memos {
                            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
                            transaction: None,
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
            _univ_param: univ_param,
            state,
            _event_task: Arc::new(task),
        }
    }

    // pub fn load(
    //     event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,
    //     univ_param: &'a jf_aap::proof::UniversalParam,
    //     full_persisted: FullPersistence,
    // ) -> Self {
    //     unimplemented!("loading QueryService")
    // }
}

#[async_trait]
impl<'a> QueryService for PhaseLockQueryService<'a> {
    async fn get_summary(&self) -> Result<LedgerSummary, QueryServiceError> {
        let state = self.state.read().await;
        Ok(LedgerSummary {
            num_blocks: state.full_persisted.block_iter().len(),
            num_txns: state.num_txns,
            num_records: state.full_persisted.rmt_leaf_iter().len(),
            num_events: state.full_persisted.events_iter().len(),
        })
    }

    async fn get_snapshot(
        &self,
        index: usize,
        sparse_records: bool,
        sparse_nullifiers: bool,
    ) -> Result<LedgerSnapshot, QueryServiceError> {
        self.state
            .read()
            .await
            .get_snapshot(index, sparse_records, sparse_nullifiers)
    }

    async fn get_block(&self, index: usize) -> Result<LedgerTransition, QueryServiceError> {
        self.state.read().await.get_block(index)
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
        let index = state
            .past_nullifiers
            .get(&root)
            .ok_or(QueryServiceError::InvalidNullifierRoot {})?;
        let nullifiers = state
            .full_persisted
            .nullifier_set_iter()
            .nth(*index)
            .unwrap()
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })?;
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
        self.state.write().await.introduce(pub_key)
    }

    async fn get_users(&self) -> Result<HashMap<UserAddress, UserPubKey>, QueryServiceError> {
        self.state
            .read()
            .await
            .full_persisted
            .get_latest_known_nodes()
            .map_err(|err| QueryServiceError::PersistenceError {
                msg: err.to_string(),
            })
    }

    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        self.state.read().await.get_user(address)
    }
}

/// A full node is a QueryService running alongside a lightweight validator.
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
        univ_param: &'a jf_aap::proof::UniversalParam,
        state: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
        full_persisted: FullPersistence,
    ) -> Self {
        let query_service = PhaseLockQueryService::new(
            validator.subscribe(),
            univ_param,
            state,
            record_merkle_tree,
            nullifiers,
            unspent_memos,
            full_persisted,
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

    async fn current_state(&self) -> Arc<ValidatorState> {
        self.validator.get_state().await
    }

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

    async fn get_snapshot(
        &self,
        index: usize,
        sparse_records: bool,
        sparse_nullifiers: bool,
    ) -> Result<LedgerSnapshot, QueryServiceError> {
        self.as_query_service()
            .get_snapshot(index, sparse_records, sparse_nullifiers)
            .await
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

    async fn get_users(&self) -> Result<HashMap<UserAddress, UserPubKey>, QueryServiceError> {
        self.as_query_service().get_users().await
    }

    async fn get_user(&self, address: &UserAddress) -> Result<UserPubKey, QueryServiceError> {
        self.as_query_service().get_user(address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        testing::{MultiXfrRecordSpec, MultiXfrTestState, TxnPrintInfo},
        universal_params::UNIVERSAL_PARAM,
    };
    use async_std::task::block_on;
    use jf_aap::{sign_receiver_memos, MerkleLeafProof, MerkleTree};
    use jf_primitives::jubjub_dsa::KeyPair;
    use quickcheck::QuickCheck;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use tempdir::TempDir;

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
            let txns = state
                .generate_transactions(block, TxnPrintInfo::new_no_time(i, num_txs))
                .unwrap();

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
                    .try_add_transaction(
                        &mut blk,
                        txn,
                        ix,
                        owner_memos.clone(),
                        kixs,
                        TxnPrintInfo::new_no_time(i, num_txs),
                    )
                    .is_ok()
                {
                    signed_memos.push((owner_memos, sig));
                }
            }

            let prev_state = state.validator.clone();
            state
                .validate_and_apply(
                    blk.clone(),
                    generation_time,
                    TxnPrintInfo::new_no_time(i, num_txs),
                )
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
        let temp_persisted_dir = TempDir::new("test_query_service").unwrap();

        block_on(async {
            let (initial_state, history) =
                generate_valid_history(txs, nkeys, ndefs, init_rec, init_recs);
            let initial_uid = initial_state.0.record_merkle_commitment.num_leaves;
            assert_eq!(initial_state.0.commit(), history[0].0.commit());
            let events = Box::pin(stream::iter(history.clone().into_iter().map(
                |(_, block, _, state)| MockConsensusEvent {
                    event: EventType::Decide {
                        block: Arc::new(vec![block]),
                        state: Arc::new(vec![state]),
                    },
                },
            )));
            let full_persisted =
                FullPersistence::new(temp_persisted_dir.path(), "full_store").unwrap();
            let mut qs = PhaseLockQueryService::new(
                events,
                &*UNIVERSAL_PARAM,
                initial_state.0,
                initial_state.1,
                initial_state.2,
                initial_state.3,
                full_persisted,
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
                        LedgerEvent::Memos { outputs, .. } => {
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
                                    state.record_merkle_commitment.root_value,
                                    uid,
                                    &MerkleLeafProof::new(comm.to_field_element(), merkle_path),
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
                    // todo !jeb.bearer re-enable this test when persistent memo storage is supported
                    // match qs
                    //     .post_memos(block_id as u64, txn_id as u64, memos.clone(), sig.clone())
                    //     .await
                    // {
                    //     Err(QueryServiceError::MemosAlreadyPosted { .. }) => {}
                    //     res => {
                    //         panic!("Expected error MemosAlreadyPosted, got {:?}", res);
                    //     }
                    // }

                    // We should be able to query the newly posted memos.
                    // todo !jeb.bearer re-enable this test when persistent memo storage is supported
                    // let (queried_memos, sig) =
                    //     qs.get_memos(block_id as u64, txn_id as u64).await.unwrap();
                    // txn.verify_receiver_memos_signature(&queried_memos, &sig)
                    //     .unwrap();
                    // assert_eq!(queried_memos, *memos);
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
}
