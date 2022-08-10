// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

use crate::ser_test;
use crate::update_query_data_source::UpdateQueryDataSource;
use crate::validator_node::*;
use arbitrary::Arbitrary;
use arbitrary_wrappers::*;
use ark_serialize::CanonicalSerialize;
use async_executors::exec::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_trait::async_trait;
use espresso_availability_api::data_source::UpdateAvailabilityData;
use espresso_catchup_api::data_source::UpdateCatchUpData;
use espresso_core::full_persistence::FullPersistence;
pub use espresso_core::state::state_comm::LedgerStateCommitment;
use espresso_core::{
    ledger::EspressoLedger,
    set_merkle_tree::*,
    state::{
        ElaboratedBlock, ElaboratedTransaction, TransactionCommitment, ValidationError,
        ValidatorState,
    },
};
use espresso_metastate_api::data_source::UpdateMetaStateData;
use espresso_status_api::data_source::UpdateStatusData;
pub use futures::prelude::*;
pub use futures::stream::Stream;
use futures::{channel::mpsc, future::RemoteHandle, select, task::SpawnExt};
use hotshot::{traits::BlockContents, types::HotShotHandle, HotShotError, H_256};
use itertools::izip;
use jf_cap::{
    structs::{Nullifier, ReceiverMemo, RecordCommitment},
    MerkleTree, Signature,
};
use jf_primitives::merkle_tree::FilledMTBuilder;
use reef::traits::Transaction;
use seahorse::events::LedgerEvent;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use tracing::{debug, error};

pub type HotShotEventType = hotshot::types::EventType<ElaboratedBlock, ValidatorState, H_256>;
pub type HotShotEvent = hotshot::types::Event<ElaboratedBlock, ValidatorState, H_256>;

pub trait ConsensusEvent {
    fn into_event(self) -> HotShotEventType;
}

impl ConsensusEvent for HotShotEvent {
    fn into_event(self) -> HotShotEventType {
        self.event
    }
}

pub type EventStream<Event> = Pin<Box<dyn Send + Stream<Item = Event>>>;

#[async_trait]
pub trait Validator {
    type Event: ConsensusEvent;
    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), HotShotError>;
    async fn start_consensus(&self);
    async fn current_state(&self) -> Result<Option<ValidatorState>, HotShotError>;
    fn subscribe(&self) -> EventStream<Self::Event>;

    async fn run<F: Send + Future>(self, kill: F)
    where
        Self: Sized + Sync,
    {
        self.start_consensus().await;
        let mut events = self.subscribe().fuse();
        let mut kill = Box::pin(kill.fuse());

        loop {
            select! {
                _ = kill => {
                    debug!("Validator killed");
                    return;
                }
                event = events.next() => match event {
                    None => {
                        debug!("Validator exiting");
                        return;
                    }
                    Some(event) => match event.into_event() {
                        HotShotEventType::Decide { state, block: _, qcs: _ } => {
                            if let Some(state) = state.last() {
                                debug!(". - Committed state {}", state.commit());
                            }
                        }
                        HotShotEventType::ViewTimeout { view_number } => {
                            debug!("  - Round {:?} timed out.", view_number);
                        }
                        HotShotEventType::Error { error } => {
                            error!("  - HotShot error: {}", error);
                        }
                        event => {
                            debug!("EVENT: {:?}", event);
                        }
                    }
                }
            }
        }
    }
}

pub type LightWeightNode<NET, STORE> = HotShotHandle<ValidatorNodeImpl<NET, STORE>, H_256>;

#[async_trait]
impl<NET: PLNet, STORE: PLStore> Validator for LightWeightNode<NET, STORE> {
    type Event = HotShotEvent;

    async fn current_state(&self) -> Result<Option<ValidatorState>, HotShotError> {
        self.get_state().await
    }

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), HotShotError> {
        self.submit_transaction(tx).await
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
                Err(err) => panic!("unexpected error from HotShotHandle::next_event: {:?}", err),
            }
        }))
    }
}

#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerSummary {
    pub num_blocks: usize,
    pub num_txns: usize,
    pub num_records: usize,
    pub num_events: usize,
    pub total_size: usize,
}

#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerSnapshot {
    pub state: ValidatorState,
    pub state_comm: LedgerStateCommitment,
    pub nullifiers: SetMerkleTree,
    pub records: ArbitraryMerkleTree,
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
    // pub memos: Vec<Option<(Vec<ReceiverMemo>, Signature)>>,
    pub uids: Vec<Vec<u64>>,
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
    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent<EspressoLedger>>;

    /// Get the receiver memos for a transaction, if they have been posted to the bulletin board.
    /// The result includes a signature over the contents of the memos using the signing key for the
    /// requested transaction, as proof that these memos are in fact the ones that the sender
    /// intended to associate with this transaction.
    // TODO !keyao Return commitments and UIDs as well: https://gitlab.com/translucence/systems/system/-/issues/39.
    async fn get_memos(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature), QueryServiceError> {
        let LedgerTransition { block, .. } = self.get_block(block_id as usize).await?;
        let memos = block
            .memos
            .get(txn_id as usize)
            .cloned()
            .ok_or(QueryServiceError::InvalidTxnId {})?;
        let sig = block
            .signatures
            .get(txn_id as usize)
            .cloned()
            .ok_or(QueryServiceError::InvalidTxnId {})?;
        Ok((memos, sig))
    }
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

impl<L: reef::Ledger> From<QueryServiceError> for seahorse::KeystoreError<L> {
    fn from(source: QueryServiceError) -> Self {
        Self::Failed {
            msg: source.to_string(),
        }
    }
}

struct FullState {
    validator: ValidatorState,
    full_persisted: FullPersistence,
    // Sparse record Merkle tree containing leaves only for those records which have been committed
    // but for which memos have not yet been posted. When the memos arrive, we will use this tree
    // to authenticate the new memos to listeners, and then forget them to keep this tree from
    // growing unbounded.
    records_pending_memos: MerkleTree,
    // Map from past nullifier set root hashes to the index of the state in which that root hash
    // occurred.
    past_nullifiers: HashMap<set_hash::Hash, usize>,
    // Block IDs indexed by block hash.
    block_hashes: HashMap<Vec<u8>, usize>,
    // Total number of committed transactions, aggregated across all blocks.
    num_txns: usize,
    // Total network/storage representation size of all transactions and nullifier proofs to date,
    // aggregated across all blocks.
    cumulative_size: usize,
    // The last block which was proposed. This is currently used to correllate BadBlock and
    // InconsistentBlock errors from HotShot with the block that caused the error. In the future,
    // HotShot errors will contain the bad block (or some kind of reference to it, perhaps through
    // persistent storage) and this will not be necessary.
    proposed: ElaboratedBlock,
    // The send ends of all channels which are subscribed to events.
    subscribers: Vec<mpsc::UnboundedSender<LedgerEvent<EspressoLedger>>>,
    // Clients which have subscribed to events starting at some time in the future, to be added to
    // `subscribers` when the time comes.
    pending_subscribers: BTreeMap<u64, Vec<mpsc::UnboundedSender<LedgerEvent<EspressoLedger>>>>,
}

impl FullState {
    fn update(&mut self, event: impl ConsensusEvent) {
        match event.into_event() {
            HotShotEventType::Error { error } => {
                if matches!(
                    *error,
                    HotShotError::BadBlock { .. } | HotShotError::InconsistentBlock { .. }
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
                    self.send_event(LedgerEvent::<EspressoLedger>::Reject {
                        block: self.proposed.clone(),
                        error: err,
                    });
                }

                // HotShot errors that don't relate to blocks being rejected (view timeouts,
                // network errors, etc.) do not correspond to LedgerEvents.
            }

            HotShotEventType::Propose { block } => {
                self.proposed = (*block).clone();
            }

            HotShotEventType::Decide {
                block,
                state,
                qcs: _,
            } => {
                for (mut block, state) in block.iter().cloned().zip(state.iter()).rev() {
                    // A block has been committed. Update our mirror of the ValidatorState by applying
                    // the new block, and generate a Commit event.

                    match self.validator.validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        block.block.clone(),
                        block.proofs.clone(),
                    ) {
                        // We update our ValidatorState for each block committed by the HotShot event
                        // source, so we shouldn't ever get out of sync.
                        Err(_) => panic!("state is out of sync with validator"),
                        Ok(_) if self.validator.commit() != state.commit() => {
                            panic!("state is out of sync with validator")
                        }

                        Ok((mut uids, nullifier_proofs)) => {
                            let hist_index = self.full_persisted.state_iter().len();
                            assert!(hist_index > 0);
                            let block_index = hist_index - 1;

                            self.full_persisted.store_for_commit(&block, state);
                            self.past_nullifiers
                                .insert(self.validator.nullifiers_root(), hist_index);
                            self.block_hashes
                                .insert(Vec::from(block.hash().as_ref()), block_index);
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
                                .collect::<Vec<_>>();
                            self.full_persisted.store_block_uids(&block_uids);

                            // Add the results of this block to our current state.
                            let mut nullifiers =
                                self.full_persisted.get_latest_nullifier_set().unwrap();
                            let mut txn_hashes = Vec::new();
                            let mut nullifiers_delta = Vec::new();
                            let mut memo_events = Vec::new();
                            for txn in block.block.0.iter() {
                                for o in txn.output_commitments() {
                                    self.records_pending_memos.push(o.to_field_element());
                                }
                            }

                            for (txn_id, (((txn, proofs), memos), signatures)) in block
                                .block
                                .0
                                .iter()
                                .zip(block.proofs.iter())
                                .zip(block.memos.iter())
                                .zip(block.signatures.iter())
                                .enumerate()
                            {
                                for n in txn.input_nullifiers() {
                                    nullifiers.insert(n);
                                    nullifiers_delta.push(n);
                                }
                                let txn_uids = &block_uids[txn_id];

                                let merkle_tree = &mut self.records_pending_memos;
                                let merkle_paths = txn_uids
                                    .iter()
                                    .map(|uid| {
                                        merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path
                                    })
                                    .collect::<Vec<_>>();
                                // Once we have generated proofs for the memos, we will not need to generate proofs for
                                // these records again (unless specifically requested) so there is no need to keep them in
                                // memory.
                                for uid in txn_uids.iter() {
                                    merkle_tree.forget(*uid);
                                }

                                let hash = ElaboratedTransaction {
                                    txn: txn.clone(),
                                    proofs: proofs.clone(),
                                    memos: memos.clone(),
                                    signature: signatures.clone(),
                                }
                                .hash();
                                txn_hashes.push(TransactionCommitment(hash));
                                let memo_event = LedgerEvent::Memos {
                                    outputs: izip!(
                                        memos.clone(),
                                        txn.output_commitments(),
                                        txn_uids.iter().cloned(),
                                        merkle_paths
                                    )
                                    .collect(),
                                    transaction: Some((
                                        block_index as u64,
                                        txn_id as u64,
                                        hash,
                                        txn.kind(),
                                    )),
                                };
                                memo_events.push(memo_event);
                            }
                            self.num_txns += block.block.0.len();
                            self.cumulative_size += block.serialized_size();
                            assert_eq!(nullifiers.hash(), self.validator.nullifiers_root());
                            assert_eq!(
                                self.records_pending_memos.commitment(),
                                self.validator.record_merkle_commitment
                            );
                            self.full_persisted.store_nullifier_set(&nullifiers);
                            self.full_persisted.commit_accepted();

                            // Update the nullifier proofs in the block so that clients do not have
                            // to worry about out of date nullifier proofs.
                            block.proofs = block
                                .block
                                .0
                                .iter()
                                .map(|txn| {
                                    txn.input_nullifiers()
                                        .into_iter()
                                        .map(|n| nullifier_proofs.contains(n).unwrap().1)
                                        .collect()
                                })
                                .collect();

                            // Notify subscribers of the new block.
                            self.send_event(LedgerEvent::Commit {
                                block,
                                block_id: block_index as u64,
                                state_comm: self.validator.commit(),
                            });
                            for memo_event in memo_events.into_iter() {
                                self.send_event(memo_event);
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }

    fn send_event(&mut self, event: LedgerEvent<EspressoLedger>) {
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

    fn subscribe(&mut self, t: u64) -> EventStream<LedgerEvent<EspressoLedger>> {
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
            records: ArbitraryMerkleTree(records),
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
}

/// A QueryService that aggregates the full ledger state by observing consensus.
pub struct HotShotQueryService<'a> {
    _univ_param: &'a jf_cap::proof::UniversalParam,
    state: Arc<RwLock<FullState>>,
    // When dropped, this handle will cancel and join the event handling task. It is not used
    // explicitly; it is merely stored with the rest of the struct for the auto-generated drop glue.
    _event_task: Arc<RemoteHandle<()>>,
}

impl<'a> HotShotQueryService<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,

        // The current state of the network.
        univ_param: &'a jf_cap::proof::UniversalParam,
        mut validator: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
        mut full_persisted: FullPersistence,
    ) -> Self {
        //todo !jeb.bearer If we are not starting from the genesis of the ledger, query the full
        // state at this point from another full node, like
        //  let state = other_node.full_state(validator.commit());
        // https://github.com/EspressoSystems/espresso/issues/415
        //
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
            cumulative_size: 0,
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
    //     univ_param: &'a jf_cap::proof::UniversalParam,
    //     full_persisted: FullPersistence,
    // ) -> Self {
    //     unimplemented!("loading QueryService")
    // }
}

#[async_trait]
impl<'a> QueryService for HotShotQueryService<'a> {
    async fn get_summary(&self) -> Result<LedgerSummary, QueryServiceError> {
        let state = self.state.read().await;
        Ok(LedgerSummary {
            num_blocks: state.full_persisted.block_iter().len(),
            num_txns: state.num_txns,
            num_records: state.full_persisted.rmt_leaf_iter().len(),
            num_events: state.full_persisted.events_iter().len(),
            total_size: state.cumulative_size,
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

    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent<EspressoLedger>> {
        let mut state = self.state.write().await;
        state.subscribe(i)
    }
}

/// A full node is a QueryService running alongside a lightweight validator.
pub struct FullNode<'a, NET, STORE, CU, AV, MS, ST>
where
    NET: PLNet,
    STORE: PLStore,
    CU: UpdateCatchUpData + Sized + Send + Sync,
    AV: UpdateAvailabilityData + Sized + Send + Sync,
    MS: UpdateMetaStateData + Sized + Send + Sync,
    ST: UpdateStatusData + Sized + Send + Sync,
{
    validator: LightWeightNode<NET, STORE>,
    #[allow(dead_code)]
    data_source_updater: Arc<RwLock<UpdateQueryDataSource<CU, AV, MS, ST>>>,
    query_service: HotShotQueryService<'a>,
}

impl<'a, NET, STORE, CU, AV, MS, ST> FullNode<'a, NET, STORE, CU, AV, MS, ST>
where
    NET: PLNet,
    STORE: PLStore,
    CU: UpdateCatchUpData + Sized + Send + Sync + 'static,
    AV: UpdateAvailabilityData + Sized + Send + Sync + 'static,
    MS: UpdateMetaStateData + Sized + Send + Sync + 'static,
    ST: UpdateStatusData + Sized + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: LightWeightNode<NET, STORE>,

        // The current state of the network.
        univ_param: &'a jf_cap::proof::UniversalParam,
        state: ValidatorState,
        record_merkle_tree: MerkleTree,
        nullifiers: SetMerkleTree,
        unspent_memos: Vec<(ReceiverMemo, u64)>,
        full_persisted: FullPersistence,
        catchup_store: Arc<RwLock<CU>>,
        availability_store: Arc<RwLock<AV>>,
        meta_state_store: Arc<RwLock<MS>>,
        status_store: Arc<RwLock<ST>>,
    ) -> Self {
        let query_service = HotShotQueryService::new(
            validator.subscribe(),
            univ_param,
            state.clone(),
            record_merkle_tree,
            nullifiers,
            unspent_memos,
            full_persisted,
        );
        let data_source_updater = UpdateQueryDataSource::new(
            validator.subscribe(),
            catchup_store,
            availability_store,
            meta_state_store,
            status_store,
            state,
        );
        Self {
            validator,
            data_source_updater,
            query_service,
        }
    }

    fn as_validator(
        &self,
    ) -> &impl Validator<Event = <FullNode<'a, NET, STORE, CU, AV, MS, ST> as Validator>::Event>
    {
        &self.validator
    }

    fn as_query_service(&self) -> &(impl QueryService + 'a) {
        &self.query_service
    }
}

#[async_trait]
impl<'a, NET, STORE, CU, AV, MS, ST> Validator for FullNode<'a, NET, STORE, CU, AV, MS, ST>
where
    NET: PLNet,
    STORE: PLStore,
    CU: UpdateCatchUpData + Sized + Send + Sync + 'static,
    AV: UpdateAvailabilityData + Sized + Send + Sync + 'static,
    MS: UpdateMetaStateData + Sized + Send + Sync + 'static,
    ST: UpdateStatusData + Sized + Send + Sync + 'static,
{
    type Event = <LightWeightNode<NET, STORE> as Validator>::Event;

    async fn current_state(&self) -> Result<Option<ValidatorState>, HotShotError> {
        self.validator.get_state().await
    }

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), HotShotError> {
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
impl<'a, NET, STORE, CU, AV, MS, ST> QueryService for FullNode<'a, NET, STORE, CU, AV, MS, ST>
where
    NET: PLNet,
    STORE: PLStore,
    CU: UpdateCatchUpData + Sized + Send + Sync + 'static,
    AV: UpdateAvailabilityData + Sized + Send + Sync + 'static,
    MS: UpdateMetaStateData + Sized + Send + Sync + 'static,
    ST: UpdateStatusData + Sized + Send + Sync + 'static,
{
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

    async fn subscribe(&self, i: u64) -> EventStream<LedgerEvent<EspressoLedger>> {
        self.as_query_service().subscribe(i).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::EspressoError;
    use async_std::task::block_on;
    use espresso_availability_api::query_data::{BlockQueryData, StateQueryData};
    use espresso_core::{
        testing::{MultiXfrRecordSpec, MultiXfrTestState, TestTxSpec, TxnPrintInfo},
        universal_params::UNIVERSAL_PARAM,
    };
    use hotshot::data::VecQuorumCertificate;
    use jf_cap::{MerkleLeafProof, MerkleTree, Signature};
    use quickcheck::QuickCheck;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use tempdir::TempDir;

    #[derive(Debug)]
    struct MockConsensusEvent {
        event: HotShotEventType,
    }

    impl ConsensusEvent for MockConsensusEvent {
        fn into_event(self) -> HotShotEventType {
            self.event
        }
    }

    fn generate_valid_history(
        txs: Vec<Vec<TestTxSpec>>,
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
            VecQuorumCertificate,
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
            assert_eq!(state.validator.nullifiers_root(), state.nullifiers.hash());
            MultiXfrTestState::update_timer(&mut state.outer_timer, |_| {
                println!(
                    "Block {}/{}, {} candidate txns",
                    i + 1,
                    num_txs,
                    block.len()
                )
            });

            let txns = state
                .generate_transactions(
                    block.into_iter().map(|tx| (tx, false)).collect(),
                    TxnPrintInfo::new_no_time(i, num_txs),
                )
                .unwrap();

            let mut generation_time: f32 = 0.0;
            MultiXfrTestState::update_timer(&mut state.outer_timer, |t| {
                generation_time = t;
                println!("Block {}/{} txns generated: {}s", i + 1, num_txs, t)
            });

            let mut blk = ElaboratedBlock::default();
            let mut signed_memos = vec![];
            for tx in txns {
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in tx.keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                if state
                    .try_add_transaction(
                        &mut blk,
                        tx.transaction,
                        tx.index,
                        owner_memos.clone(),
                        kixs,
                        TxnPrintInfo::new_no_time(i, num_txs),
                    )
                    .is_ok()
                {
                    signed_memos.push((owner_memos, tx.signature));
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
            history.push((
                prev_state,
                blk,
                signed_memos,
                state.validator.clone(),
                // TODO(vko): How do we generate a QC from the given transactions again?
                VecQuorumCertificate::dummy::<H_256>(),
            ));
        }

        (initial_state, history)
    }

    #[derive(Default)]
    struct TestOnlyMockAllStores;

    impl UpdateAvailabilityData for TestOnlyMockAllStores {
        type Error = EspressoError;

        fn append_blocks(
            &mut self,
            _blocks: &mut Vec<BlockQueryData>,
            _states: &mut Vec<StateQueryData>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl UpdateCatchUpData for TestOnlyMockAllStores {
        type Error = EspressoError;
        fn append_events(
            &mut self,
            _events: &mut Vec<LedgerEvent<EspressoLedger>>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn event_count(&self) -> usize {
            0
        }
    }

    impl UpdateMetaStateData for TestOnlyMockAllStores {
        type Error = EspressoError;
        fn append_block_nullifiers(
            &mut self,
            _block_id: u64,
            _nullifiers: Vec<Nullifier>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl UpdateStatusData for TestOnlyMockAllStores {
        type Error = EspressoError;
        fn set_status(
            &mut self,
            _status: espresso_status_api::query_data::ValidatorStatus,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn edit_status<U, F>(&mut self, _op: F) -> Result<(), Self::Error>
        where
            F: FnOnce(&mut espresso_status_api::query_data::ValidatorStatus) -> Result<(), U>,
            Self::Error: From<U>,
        {
            Ok(())
        }
    }

    fn test_query_service(
        txs: Vec<Vec<TestTxSpec>>,
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
        let temp_persisted_dir = TempDir::new("test_query_service").unwrap();

        block_on(async {
            let (initial_state, history) =
                generate_valid_history(txs, nkeys, ndefs, init_rec, init_recs);
            let initial_uid = initial_state.0.record_merkle_commitment.num_leaves;
            assert_eq!(initial_state.0.commit(), history[0].0.commit());
            let events = Box::pin(stream::iter(history.clone().into_iter().map(
                |(_, block, _, state, quorum_certificate)| MockConsensusEvent {
                    event: HotShotEventType::Decide {
                        block: Arc::new(vec![block]),
                        state: Arc::new(vec![state]),
                        qcs: Arc::new(vec![quorum_certificate]),
                    },
                },
            )));
            let full_persisted =
                FullPersistence::new(temp_persisted_dir.path(), "full_store").unwrap();

            let _mock_store = Arc::new(RwLock::new(TestOnlyMockAllStores::default()));
            let qs = HotShotQueryService::new(
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
            let mut expected_uid = initial_uid;
            for (_, hist_block, memos, hist_state, _) in history.iter() {
                match events.next().await.unwrap() {
                    LedgerEvent::Commit { block, .. } => {
                        assert_eq!(block, *hist_block);

                        // We should be able to get inclusion proofs for all the nullifiers in the
                        // new block.
                        for txn in block.block.0 {
                            for n in txn.input_nullifiers() {
                                let (incl, proof) = qs
                                    .nullifier_proof(hist_state.nullifiers_root(), n)
                                    .await
                                    .unwrap();
                                assert!(incl);
                                proof.check(n, &hist_state.nullifiers_root()).unwrap();
                            }
                        }
                    }
                    event => {
                        panic!("Expected Commit event, got {:?}", event);
                    }
                }
                // After commit we should get all the memo events fot he block
                for (txn, (memos, _sig)) in hist_block.block.0.iter().zip(memos) {
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
                                // commitment. This proof is relative to the root hash of when the
                                // the transaction was accepted
                                let state = &hist_state;
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
                }
            }

            for (block_id, (state, block, _, _, _)) in history.into_iter().enumerate() {
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
                let (incl, proof) = qs
                    .nullifier_proof(state.nullifiers_root(), n)
                    .await
                    .unwrap();
                assert!(!incl);
                proof.check(n, &state.nullifiers_root()).unwrap();
            }
        });
    }

    // Runs test_query_service() on a few small transaction sequences taken from the multixfr
    // regression tests from lib.rs.
    #[test]
    fn test_query_service_small() {
        test_query_service(
            vec![vec![
                TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: -2,
                },
                TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: 0,
                },
            ]],
            0,
            0,
            (0, 0, 0),
            vec![(0, 0, 0)],
        );

        test_query_service(
            vec![
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 1,
                    key1: 1,
                    diff: 0,
                }],
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: 0,
                }],
            ],
            1,
            0,
            (0, 0, 0),
            vec![],
        );

        test_query_service(
            vec![
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
            ],
            2,
            1,
            (0, 0, 2),
            vec![],
        );

        test_query_service(
            vec![
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 1,
                    key0: 1,
                    key1: 1,
                    diff: 0,
                }],
                vec![TestTxSpec::OneInput { rec: 5, key: 1 }],
            ],
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
