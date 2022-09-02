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
use crate::update_query_data_source::{UpdateQueryDataSource, UpdateQueryDataSourceTypes};
use crate::validator_node::*;
use arbitrary::Arbitrary;
use arbitrary_wrappers::*;
use ark_serialize::CanonicalSerialize;
use async_executors::exec::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_trait::async_trait;
use espresso_core::full_persistence::FullPersistence;
pub use espresso_core::state::state_comm::LedgerStateCommitment;
use espresso_core::state::{EspressoTransaction, EspressoTxnHelperProofs};
use espresso_core::{
    ledger::EspressoLedger,
    set_merkle_tree::*,
    state::{
        ElaboratedBlock, ElaboratedTransaction, TransactionCommitment, ValidationError,
        ValidationOutputs, ValidatorState,
    },
};
pub use futures::prelude::*;
pub use futures::stream::Stream;
use futures::{channel::mpsc, future::RemoteHandle, select, task::SpawnExt};
use hotshot::{traits::BlockContents, types::HotShotHandle, HotShotError, H_256};
use itertools::izip;
use jf_cap::{
    structs::{Nullifier, ReceiverMemo},
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
        match block
            .memos
            .get(txn_id as usize)
            .ok_or(QueryServiceError::InvalidTxnId {})?
        {
            Some(memos) => Ok(memos.clone()),
            None => Err(QueryServiceError::NoMemosForTxn {}),
        }
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
                for (block, state) in block.iter().cloned().zip(state.iter()).rev() {
                    self.append_block(block, state)
                }
            }

            _ => {}
        }
    }

    fn append_block(&mut self, mut block: ElaboratedBlock, state: &ValidatorState) {
        // A block has been committed. Update our mirror of the ValidatorState by applying the new
        // block, and generate a Commit event.
        match self.validator.validate_and_apply(
            self.validator.prev_commit_time + 1,
            block.block.clone(),
            block.proofs.clone(),
        ) {
            // We update our ValidatorState for each block committed by the HotShot event source, so
            // we shouldn't ever get out of sync.
            Err(_) => panic!("state is out of sync with validator"),
            Ok(_) if self.validator.commit() != state.commit() => {
                panic!("state is out of sync with validator")
            }

            Ok(ValidationOutputs {
                mut uids,
                nullifier_proofs,
                ..
            }) => {
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
                        // Split the uids corresponding to this transaction off the front of the
                        // list of uids for the whole block.
                        let mut this_txn_uids = uids.split_off(txn.output_len());
                        std::mem::swap(&mut this_txn_uids, &mut uids);
                        assert_eq!(this_txn_uids.len(), txn.output_len());
                        this_txn_uids
                    })
                    .collect::<Vec<_>>();
                self.full_persisted.store_block_uids(&block_uids);

                // Add the results of this block to our current state.
                let mut nullifiers = self.full_persisted.get_latest_nullifier_set().unwrap();
                let mut txn_hashes = Vec::new();
                let mut nullifiers_delta = Vec::new();
                let mut memo_events = Vec::new();
                for txn in block.block.0.iter() {
                    for o in txn.output_commitments() {
                        self.records_pending_memos.push(o.to_field_element());
                    }
                }

                for (txn_id, ((txn, proofs), memos)) in block
                    .block
                    .0
                    .iter()
                    .zip(block.proofs.iter())
                    .zip(block.memos.iter())
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
                        .map(|uid| merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path)
                        .collect::<Vec<_>>();
                    // Once we have generated proofs for the memos, we will not need to generate
                    // proofs for these records again (unless specifically requested) so there is no
                    // need to keep them in memory.
                    for uid in txn_uids.iter() {
                        merkle_tree.forget(*uid);
                    }

                    let hash = ElaboratedTransaction {
                        txn: txn.clone(),
                        proofs: proofs.clone(),
                        memos: memos.clone(),
                    }
                    .hash();
                    txn_hashes.push(TransactionCommitment(hash));
                    let memo_event = LedgerEvent::Memos {
                        outputs: izip!(
                            memos.clone().map(|(memos, _)| memos).unwrap_or_default(),
                            txn.output_commitments(),
                            txn_uids.iter().cloned(),
                            merkle_paths
                        )
                        .collect(),
                        transaction: Some((block_index as u64, txn_id as u64, hash, txn.kind())),
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

                // Update the nullifier proofs in the block so that clients do not have to worry
                // about out of date nullifier proofs.
                for (txn, proofs) in block.block.0.iter().zip(block.proofs.iter_mut()) {
                    if let EspressoTransaction::CAP(txn) = txn {
                        *proofs = EspressoTxnHelperProofs::CAP(
                            txn.input_nullifiers()
                                .into_iter()
                                .map(|n| nullifier_proofs.contains(n).unwrap().1)
                                .collect(),
                        );
                    }
                }

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
        genesis: ElaboratedBlock,
        mut full_persisted: FullPersistence,
    ) -> Self {
        let validator = ValidatorState::default();
        let records = MerkleTree::restore_from_frontier(
            validator.record_merkle_commitment,
            &validator.record_merkle_frontier,
        )
        .unwrap();
        let nullifiers = SetMerkleTree::default();

        // Commit the initial state.
        full_persisted.store_initial(&validator, &records, &nullifiers);

        let full_state = Arc::new(RwLock::new(FullState {
            validator,
            records_pending_memos: records,
            full_persisted,
            past_nullifiers: vec![(nullifiers.hash(), 0)].into_iter().collect(),
            num_txns: 0,
            cumulative_size: 0,
            block_hashes: Default::default(),
            proposed: ElaboratedBlock::default(),
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
        }));

        // Spawn event handling task.
        let task = {
            let full_state = full_state.clone();
            let mut event_source = Box::pin(event_source);
            AsyncStd::new()
                .spawn_with_handle(async move {
                    // HotShot does not currently support genesis nicely. It should automatically
                    // commit and broadcast a `Decide` event for the genesis block, but it doesn't.
                    // For now, we broadcast a `Commit` event for the genesis block ourselves.
                    {
                        let mut state = ValidatorState::default();
                        state
                            .validate_and_apply(1, genesis.block.clone(), genesis.proofs.clone())
                            .unwrap();
                        full_state.write().await.append_block(genesis, &state);
                    }

                    // Handle events as they come in from the network.
                    while let Some(event) = event_source.next().await {
                        full_state.write().await.update(event);
                    }
                })
                .unwrap()
        };
        Self {
            _univ_param: univ_param,
            state: full_state,
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
pub struct FullNode<'a, NET, STORE, TYPES>
where
    NET: PLNet,
    STORE: PLStore,
    TYPES: UpdateQueryDataSourceTypes,
{
    validator: LightWeightNode<NET, STORE>,
    #[allow(dead_code)]
    data_source_updater: Arc<RwLock<UpdateQueryDataSource<TYPES>>>,
    query_service: HotShotQueryService<'a>,
}

impl<'a, NET, STORE, TYPES> FullNode<'a, NET, STORE, TYPES>
where
    NET: PLNet,
    STORE: PLStore,
    TYPES: UpdateQueryDataSourceTypes + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: LightWeightNode<NET, STORE>,

        // The current state of the network.
        univ_param: &'a jf_cap::proof::UniversalParam,
        genesis: ElaboratedBlock,
        full_persisted: FullPersistence,
        catchup_store: Arc<RwLock<TYPES::CU>>,
        availability_store: Arc<RwLock<TYPES::AV>>,
        meta_state_store: Arc<RwLock<TYPES::MS>>,
        status_store: Arc<RwLock<TYPES::ST>>,
        event_handler: Arc<RwLock<TYPES::EH>>,
    ) -> Self {
        let query_service =
            HotShotQueryService::new(validator.subscribe(), univ_param, genesis, full_persisted);
        let data_source_updater = UpdateQueryDataSource::new(
            validator.subscribe(),
            catchup_store,
            availability_store,
            meta_state_store,
            status_store,
            event_handler,
            ValidatorState::default(),
        );
        Self {
            validator,
            data_source_updater,
            query_service,
        }
    }

    fn as_validator(
        &self,
    ) -> &impl Validator<Event = <FullNode<'a, NET, STORE, TYPES> as Validator>::Event> {
        &self.validator
    }

    fn as_query_service(&self) -> &(impl QueryService + 'a) {
        &self.query_service
    }
}

#[async_trait]
impl<'a, NET, STORE, TYPES> Validator for FullNode<'a, NET, STORE, TYPES>
where
    NET: PLNet,
    STORE: PLStore,
    TYPES: UpdateQueryDataSourceTypes + 'static,
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
impl<'a, NET, STORE, TYPES> QueryService for FullNode<'a, NET, STORE, TYPES>
where
    NET: PLNet,
    STORE: PLStore,
    TYPES: UpdateQueryDataSourceTypes + 'static,
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
