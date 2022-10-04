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

use std::collections::{BTreeMap, HashMap};
use std::convert::From;
use std::path::Path;

use crate::ApiError;
use async_trait::async_trait;
use atomic_store::{
    append_log::Iter as ALIter, load_store::BincodeLoadStore, AppendLog, AtomicStore,
    AtomicStoreLoader, PersistenceError, RollingLog,
};
use espresso_availability_api::data_source::{
    AvailabilityDataSource, BlockAndAssociated, UpdateAvailabilityData,
};
use espresso_availability_api::query_data::{BlockQueryData, StateQueryData};
use espresso_catchup_api::data_source::{CatchUpDataSource, UpdateCatchUpData};
use espresso_core::ledger::EspressoLedger;
use espresso_core::state::{
    BlockCommitment, ElaboratedTransaction, SetMerkleProof, SetMerkleTree, TransactionCommitment,
};
use espresso_metastate_api::{
    api as metastate,
    data_source::{MetaStateDataSource, UpdateMetaStateData},
};
use espresso_status_api::data_source::{StatusDataSource, UpdateStatusData};
use espresso_status_api::query_data::ValidatorStatus;
use espresso_validator_api::data_source::{ConsensusEvent, ValidatorDataSource};
use hotshot::{data::QuorumCertificate, HotShotError, H_256};
use itertools::izip;
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use postage::{broadcast, sink::Sink};
use seahorse::events::LedgerEvent;
use tracing::warn;

// This should probably be taken from a passed-in configuration, and stored locally.
const CACHED_BLOCKS_COUNT: usize = 50;
const CACHED_EVENTS_COUNT: usize = 500;
const EVENT_CHANNEL_CAPACITY: usize = 500;

pub type Consensus = Box<dyn ValidatorDataSource<Error = HotShotError> + Send + Sync>;

pub struct QueryData {
    cached_blocks_start: usize,
    cached_blocks: Vec<BlockAndAssociated>,
    index_by_block_hash: HashMap<BlockCommitment, u64>,
    index_by_txn_hash: HashMap<TransactionCommitment, (u64, u64)>,
    index_by_last_record_id: BTreeMap<u64, u64>,
    cached_events_start: usize,
    events: Vec<Option<LedgerEvent<EspressoLedger>>>,
    event_sender: broadcast::Sender<(usize, LedgerEvent<EspressoLedger>)>,
    event_receiver: broadcast::Receiver<(usize, LedgerEvent<EspressoLedger>)>,
    cached_nullifier_sets: BTreeMap<u64, SetMerkleTree>,
    node_status: ValidatorStatus,
    query_storage: AtomicStore,
    block_storage: AppendLog<BincodeLoadStore<BlockQueryData>>,
    state_storage: AppendLog<BincodeLoadStore<StateQueryData>>,
    qcert_storage: AppendLog<BincodeLoadStore<QuorumCertificate<H_256>>>,
    event_storage: AppendLog<BincodeLoadStore<LedgerEvent<EspressoLedger>>>,
    status_storage: RollingLog<BincodeLoadStore<ValidatorStatus>>,
    consensus: Consensus,
    location: Option<String>,
}

pub trait Extract<T> {
    fn extract(&self) -> &Option<T>;
}

impl Extract<BlockQueryData> for BlockAndAssociated {
    fn extract(&self) -> &Option<BlockQueryData> {
        &self.0
    }
}
impl Extract<StateQueryData> for BlockAndAssociated {
    fn extract(&self) -> &Option<StateQueryData> {
        &self.1
    }
}
impl Extract<QuorumCertificate<H_256>> for BlockAndAssociated {
    fn extract(&self) -> &Option<QuorumCertificate<H_256>> {
        &self.2
    }
}

pub struct DynamicPersistenceIterator<'a, T, X, LogIter>
where
    LogIter: Iterator<Item = Result<T, PersistenceError>>,
    X: Extract<T>,
{
    index: usize,
    slice_start: usize,
    slice: &'a [X],
    from_fs: LogIter,
}

impl<'a, T, X, LogIter> DynamicPersistenceIterator<'a, T, X, LogIter>
where
    LogIter: Iterator<Item = Result<T, PersistenceError>> + ExactSizeIterator,
    T: Clone,
    X: Extract<T>,
{
    fn impl_nth(&mut self, n: usize) -> Option<Option<T>> {
        self.index += n;
        let got = if self.index >= self.slice_start {
            if self.index < self.slice_start + self.slice.len() {
                self.slice
                    .get(self.index - self.slice_start)
                    .map(|x| x.extract())
                    .cloned()
            } else {
                None
            }
        } else {
            self.from_fs.nth(n).map(|res| {
                if let Err(e) = &res {
                    warn!("failed to load field at position {}: error {}", n, e);
                }
                res.ok()
            })
        };

        self.index += 1;

        got
    }
}

impl<'a, T, X, LogIter> Iterator for DynamicPersistenceIterator<'a, T, X, LogIter>
where
    LogIter: Iterator<Item = Result<T, PersistenceError>> + ExactSizeIterator,
    T: Clone,
    X: Extract<T>,
{
    type Item = Option<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.impl_nth(0)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.from_fs.len();
        (remaining, Some(remaining))
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.impl_nth(n)
    }

    fn count(self) -> usize {
        self.from_fs.len()
    }
}

fn dynamic_persistence_iter<T, X, LogIter>(
    index: usize,
    slice_start: usize,
    slice: &[X],
    from_fs: LogIter,
) -> DynamicPersistenceIterator<T, X, LogIter>
where
    LogIter: Iterator<Item = Result<T, PersistenceError>> + ExactSizeIterator,
    X: Extract<T>,
{
    DynamicPersistenceIterator {
        index,
        slice_start,
        slice,
        from_fs,
    }
}

// We implement [AvailabilityDataSource] for `&'a QueryData`, not `QueryData`, so that we can name
// the lifetime `'a` when defining the associated iterator types. This is a workaround in place of
// GATs. Once GATs stabilize, we can do something like
//
//      type BlockIterType<'a> = &'a [BlockQueryData];
//      fn get_nth_block_iter(&self, n: usize) -> Self::BlockIterType<'_>;
impl<'a> AvailabilityDataSource for &'a QueryData {
    type BlockIterType = DynamicPersistenceIterator<
        'a,
        BlockQueryData,
        BlockAndAssociated,
        ALIter<'a, BincodeLoadStore<BlockQueryData>>,
    >;
    type StateIterType = DynamicPersistenceIterator<
        'a,
        StateQueryData,
        BlockAndAssociated,
        ALIter<'a, BincodeLoadStore<StateQueryData>>,
    >;

    type QCertIterType = DynamicPersistenceIterator<
        'a,
        QuorumCertificate<H_256>,
        BlockAndAssociated,
        ALIter<'a, BincodeLoadStore<QuorumCertificate<H_256>>>,
    >;

    fn get_nth_block_iter(&self, n: usize) -> Self::BlockIterType {
        let mut iter = self.block_storage.iter();
        if n > 0 {
            iter.nth(n - 1);
        }
        dynamic_persistence_iter(n, self.cached_blocks_start, &self.cached_blocks, iter)
    }
    fn get_nth_state_iter(&self, n: usize) -> Self::StateIterType {
        let mut iter = self.state_storage.iter();
        if n > 0 {
            iter.nth(n - 1);
        }
        dynamic_persistence_iter(n, self.cached_blocks_start, &self.cached_blocks, iter)
    }
    fn get_nth_qcert_iter(&self, n: usize) -> Self::QCertIterType {
        let mut iter = self.qcert_storage.iter();
        if n > 0 {
            iter.nth(n - 1);
        }
        dynamic_persistence_iter(n, self.cached_blocks_start, &self.cached_blocks, iter)
    }
    fn get_block_index_by_hash(&self, hash: BlockCommitment) -> Option<u64> {
        self.index_by_block_hash.get(&hash).cloned()
    }
    fn get_txn_index_by_hash(&self, hash: TransactionCommitment) -> Option<(u64, u64)> {
        self.index_by_txn_hash.get(&hash).cloned()
    }
    fn get_record_index_by_uid(&self, uid: u64) -> Option<(u64, u64, u64)> {
        let apply = |block: &BlockQueryData| {
            let mut remainder = uid - block.records_from;
            let mut got_txn_idx = None;
            for (txn_idx, txn) in block.raw_block.block.0.iter().enumerate() {
                let record_count = txn.output_len() as u64;
                if remainder < record_count {
                    got_txn_idx = Some(txn_idx as u64);
                    break;
                } else {
                    remainder -= record_count;
                }
            }
            if let Some(txn_idx) = got_txn_idx {
                Some((block.block_id, txn_idx, remainder))
            } else {
                // This should never happen.
                tracing::error!("QueryData::get_record_index_by_uid encountered bad state for uid {}; found block {} with uid range {}+{}, but transaction outputs did not match", uid, block.block_id, block.records_from, block.record_count);
                None
            }
        };

        if let Some((_, &lower_bound)) = self.index_by_last_record_id.range(uid..).next() {
            let lower_bound = lower_bound as usize;
            if lower_bound >= self.cached_blocks_start {
                if lower_bound >= self.cached_blocks_start + self.cached_blocks.len() {
                    return None;
                }
                if let Some(block) =
                    &self.cached_blocks[lower_bound - self.cached_blocks_start].extract()
                {
                    apply(block)
                } else {
                    None
                }
            } else {
                let qd = self
                    .block_storage
                    .iter()
                    .nth(lower_bound)?
                    .map_err(|err| {
                        warn!("{}", err);
                        err
                    })
                    .ok()?;
                apply(&qd)
            }
        } else {
            None
        }
    }

    fn get_record_merkle_tree_at_block_index(&self, n: usize) -> Option<MerkleTree> {
        let apply = |state: &StateQueryData| {
            let state = &state.state;
            MerkleTree::restore_from_frontier(
                state.record_merkle_commitment,
                &state.record_merkle_frontier,
            )
        };
        if n >= self.cached_blocks_start {
            if n >= self.cached_blocks_start + self.cached_blocks.len() {
                return None;
            }
            if let Some(state) = &self.cached_blocks[n - self.cached_blocks_start].extract() {
                apply(state)
            } else {
                None
            }
        } else {
            let qd = self
                .state_storage
                .iter()
                .nth(n)?
                .map_err(|err| {
                    warn!("{}", err);
                    err
                })
                .ok()?;
            apply(&qd)
        }
    }
}

impl UpdateAvailabilityData for QueryData {
    type Error = ApiError;

    fn append_blocks(&mut self, blocks: Vec<BlockAndAssociated>) -> Result<(), Self::Error> {
        blocks.iter().for_each(|block_and_associated| {
            if let Some(block) = &block_and_associated.0 {
                self.index_by_block_hash
                    .insert(block.block_hash, block.block_id);
                if block.record_count > 0 {
                    self.index_by_last_record_id
                        .insert(block.records_from + block.record_count - 1, block.block_id);
                }
                for (index, txn_hash) in block.txn_hashes.iter().enumerate() {
                    self.index_by_txn_hash
                        .insert(*txn_hash, (block.block_id, index as u64));
                }
                if let Err(e) = self.block_storage.store_resource(block) {
                    warn!("Failed to store block {:?}: Error: {}", block, e);
                }
            }
            if let Some(state) = &block_and_associated.1 {
                if let Err(e) = self.state_storage.store_resource(state) {
                    warn!("Failed to store state {:?}: Error: {}", state, e);
                }
            }
            if let Some(qcert) = &block_and_associated.2 {
                if let Err(e) = self.qcert_storage.store_resource(qcert) {
                    warn!(
                        "Failed to store QuorumCertificate {:?}: Error: {}",
                        qcert, e
                    );
                }
            }
        });
        let mut blocks = blocks;
        self.cached_blocks.append(&mut blocks);
        let cached_blocks_count = self.cached_blocks.len();
        if cached_blocks_count > CACHED_BLOCKS_COUNT {
            let prune_by = cached_blocks_count - CACHED_BLOCKS_COUNT;
            self.cached_blocks_start += prune_by;
            self.cached_blocks.drain(..prune_by);
        }
        Ok(())
    }
}

impl Extract<LedgerEvent<EspressoLedger>> for Option<LedgerEvent<EspressoLedger>> {
    fn extract(&self) -> &Option<LedgerEvent<EspressoLedger>> {
        self
    }
}

// We implement [CatchUpDataSource] for `&'a QueryData`, not `QueryData`, so that we can name the
// lifetime `'a` when defining the associated iterator types. This is a workaround in place of GATs.
// Once GATs stabilize, we can do something like
//
//      type EventIterType<'a> = &'a [LedgerEvent<EspressoLedger>];
//      fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType<'_>;
impl<'a> CatchUpDataSource for &'a QueryData {
    type EventIterType = DynamicPersistenceIterator<
        'a,
        LedgerEvent<EspressoLedger>,
        Option<LedgerEvent<EspressoLedger>>,
        ALIter<'a, BincodeLoadStore<LedgerEvent<EspressoLedger>>>,
    >;
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType {
        let mut iter = self.event_storage.iter();
        if n > 0 {
            iter.nth(n - 1);
        }
        dynamic_persistence_iter(n, self.cached_events_start, &self.events, iter)
    }
    fn len(&self) -> usize {
        self.events.len() + self.cached_events_start
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn subscribe(&self) -> broadcast::Receiver<(usize, LedgerEvent<EspressoLedger>)> {
        self.event_receiver.clone()
    }
}

#[async_trait]
impl UpdateCatchUpData for QueryData {
    type Error = ApiError;

    async fn append_events(
        &mut self,
        events: Vec<Option<LedgerEvent<EspressoLedger>>>,
    ) -> Result<(), Self::Error> {
        for e in events {
            if let Some(e) = &e {
                if let Err(err) = self.event_storage.store_resource(e) {
                    warn!("Failed to store event {:?}, Error: {}", e, err);
                }

                // `send` fails if the channel is full or closed. The channel cannot be full because
                // it is unbounded, and cannot be closed because `self` owns copies of both ends.
                self.event_sender
                    .send((self.event_count(), e.clone()))
                    .await
                    .expect("unexpected failure when broadcasting event");
            }
            self.events.push(e);
        }
        if self.events.len() > CACHED_EVENTS_COUNT {
            let prune_by = self.events.len() - CACHED_EVENTS_COUNT;
            self.cached_events_start += prune_by;
            self.events.drain(..prune_by);
        }
        Ok(())
    }

    fn event_count(&self) -> usize {
        self.events.len() + self.cached_events_start
    }
}

impl QueryData {
    fn with_nullifier_set_at_block<U>(
        &self,
        block_id: u64,
        op: impl FnOnce(&SetMerkleTree) -> U,
    ) -> Result<U, ApiError> {
        if block_id as usize > self.cached_blocks_start + self.cached_blocks.len() {
            tracing::error!(
                "Max block index exceeded; max: {}, queried for {}",
                self.cached_blocks_start + self.cached_blocks.len(),
                block_id
            );
            return Err(metastate::Error::InvalidBlockId { block_id }.into());
        }
        let default_nullifier_set = SetMerkleTree::default();

        // `cached_nullifier_sets` is indexed by `block_id`, the (0-based) index of the block which
        // created each nullifier set. This gives us no way to represent the initial, empty
        // nullifier set (since it's hypothetical block ID would be -1) in the case where we do not
        // have a cached nullifier set earlier than `block_id`. Things will become slightly simpler
        // if we work in terms of block _height_. Then the initial nullifier set (the one we have
        // before applying any blocks) has block height 0, and the nullifier set after the block
        // with ID `n` has block height `n + 1`.
        let block_height = block_id + 1;

        // Get the latest cached nullifier set whose block height is at most the block height of
        // interest.
        let prev_cached_set = self.cached_nullifier_sets.range(..block_height).next_back();
        let (cached_block_height, cached_nullifier_set) =
            if let Some((index, tree)) = prev_cached_set {
                // Remember that `cached_nullifier_sets` is indexed by block _index_, so the block
                // _height_ of the cached nullifier set is `index + 1`.
                (index + 1, tree)
            } else {
                // If we don't have a cached set lower than `block_height`, we use the initial,
                // empty set, which has a block height of 0.
                (0, &default_nullifier_set)
            };
        assert!(cached_block_height <= block_height);
        if cached_block_height == block_height {
            Ok(op(cached_nullifier_set))
        } else {
            // If the cached nullifier set is not the exact one we are interested in, we need to
            // build the nullifier set for `block_height` by adding the nullifiers from each block
            // from `cached_block_height` to `block_height`.
            let mut adjusted_nullifier_set = cached_nullifier_set.clone();
            let iter = self
                .get_nth_block_iter(cached_block_height as usize)
                .take((block_height - cached_block_height) as usize);
            iter.for_each(|block| {
                if let Some(block) = block {
                    for transaction in block.raw_block.block.0.iter() {
                        for nullifier_in in transaction.input_nullifiers() {
                            adjusted_nullifier_set.insert(nullifier_in);
                        }
                    }
                }
            });
            Ok(op(&adjusted_nullifier_set))
        }
    }
}

impl MetaStateDataSource for QueryData {
    fn get_nullifier_proof_for(
        &self,
        block_id: u64,
        nullifier: Nullifier,
    ) -> Option<(bool, SetMerkleProof)> {
        if let Ok(proof) = self.with_nullifier_set_at_block(block_id, |ns| {
            tracing::info!("getting nullifier proof for {} in {}", nullifier, ns.hash());
            ns.contains(nullifier)
        }) {
            proof
        } else {
            None
        }
    }
}

impl UpdateMetaStateData for QueryData {
    type Error = ApiError;
    fn append_block_nullifiers(
        &mut self,
        block_id: u64,
        nullifiers: Vec<Nullifier>,
    ) -> Result<(), Self::Error> {
        let mut nullifier_set = if block_id == 0 {
            SetMerkleTree::default()
        } else {
            self.with_nullifier_set_at_block(block_id - 1, |ns| ns.clone())?
        };
        for nullifier in nullifiers {
            nullifier_set.insert(nullifier);
        }
        self.cached_nullifier_sets.insert(block_id, nullifier_set);
        Ok(())
    }
}

impl StatusDataSource for QueryData {
    fn get_validator_status(&self) -> &ValidatorStatus {
        &self.node_status
    }

    fn get_location(&self) -> &Option<String> {
        &self.location
    }
}

impl UpdateStatusData for QueryData {
    type Error = ApiError;

    fn set_status(&mut self, status: ValidatorStatus) -> Result<(), Self::Error> {
        self.node_status = status;
        if let Err(e) = self.status_storage.store_resource(&self.node_status) {
            warn!(
                "Failed to store status {:?}, Error {}",
                &self.node_status, e
            );
        }
        Ok(())
    }
    fn edit_status<U, F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnOnce(&mut ValidatorStatus) -> Result<(), U>,
        Self::Error: From<U>,
    {
        op(&mut self.node_status).map_err(ApiError::from)?;
        if let Err(e) = self.status_storage.store_resource(&self.node_status) {
            warn!(
                "Failed to store status {:?}, Error {}",
                &self.node_status, e
            );
        }
        Ok(())
    }
}

#[async_trait]
impl ValidatorDataSource for QueryData {
    type Error = HotShotError;

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), Self::Error> {
        self.consensus.submit(txn).await
    }

    async fn next_event(&mut self) -> Result<ConsensusEvent, Self::Error> {
        self.consensus.next_event().await
    }
}

const STATUS_STORAGE_COUNT: u32 = 10u32;

impl QueryData {
    pub fn new(
        store_path: &Path,
        consensus: Consensus,
        location: Option<String>,
    ) -> Result<QueryData, PersistenceError> {
        let key_tag = "query_data_store";
        let blocks_tag = format!("{}_blocks", key_tag);
        let states_tag = format!("{}_states", key_tag);
        let qcerts_tag = format!("{}_qcerts", key_tag);
        let events_tag = format!("{}_events", key_tag);
        let status_tag = format!("{}_status", key_tag);
        let mut loader = AtomicStoreLoader::create(store_path, key_tag)?;
        let block_storage = AppendLog::create(&mut loader, Default::default(), &blocks_tag, 1024)?;
        let state_storage = AppendLog::create(&mut loader, Default::default(), &states_tag, 1024)?;
        let qcert_storage = AppendLog::create(&mut loader, Default::default(), &qcerts_tag, 1024)?;
        let event_storage = AppendLog::create(&mut loader, Default::default(), &events_tag, 1024)?;
        let mut status_storage =
            RollingLog::create(&mut loader, Default::default(), &status_tag, 1024)?;
        // this should be loaded from a config setting...
        status_storage.set_retained_entries(STATUS_STORAGE_COUNT);

        let query_storage = AtomicStore::open(loader)?;

        let (event_sender, event_receiver) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Ok(QueryData {
            cached_blocks_start: 0usize,
            cached_blocks: Vec::new(),
            index_by_block_hash: HashMap::new(),
            index_by_txn_hash: HashMap::new(),
            index_by_last_record_id: BTreeMap::new(),
            cached_events_start: 0usize,
            events: Vec::new(),
            event_sender,
            event_receiver,
            cached_nullifier_sets: BTreeMap::new(),
            node_status: ValidatorStatus::default(),
            query_storage,
            block_storage,
            state_storage,
            qcert_storage,
            event_storage,
            status_storage,
            consensus,
            location,
        })
    }

    pub fn load(
        store_path: &Path,
        consensus: Consensus,
        location: Option<String>,
    ) -> Result<QueryData, PersistenceError> {
        let key_tag = "query_data_store";
        let blocks_tag = format!("{}_blocks", key_tag);
        let states_tag = format!("{}_states", key_tag);
        let qcerts_tag = format!("{}_qcerts", key_tag);
        let events_tag = format!("{}_events", key_tag);
        let status_tag = format!("{}_status", key_tag);
        let mut loader = AtomicStoreLoader::load(store_path, key_tag)?;
        let block_storage = AppendLog::load(&mut loader, Default::default(), &blocks_tag, 1024)?;
        let state_storage = AppendLog::load(&mut loader, Default::default(), &states_tag, 1024)?;
        let qcert_storage = AppendLog::load(&mut loader, Default::default(), &qcerts_tag, 1024)?;
        let event_storage = AppendLog::load(&mut loader, Default::default(), &events_tag, 1024)?;
        let mut status_storage =
            RollingLog::load(&mut loader, Default::default(), &status_tag, 1024)?;
        // this should be loaded from a config setting...
        status_storage.set_retained_entries(STATUS_STORAGE_COUNT);
        let query_storage = AtomicStore::open(loader)?;

        let stored_blocks_len = block_storage.iter().len();
        let cached_blocks_start = if stored_blocks_len > CACHED_BLOCKS_COUNT {
            stored_blocks_len - CACHED_BLOCKS_COUNT
        } else {
            0
        };
        let zipped_iters = izip!(
            block_storage.iter().skip(cached_blocks_start).map(|r| {
                if let Err(e) = &r {
                    warn!("failed to load block. Error: {}", e);
                }
                r.ok()
            }),
            state_storage.iter().skip(cached_blocks_start).map(|r| {
                if let Err(e) = &r {
                    warn!("failed to load state. Error: {}", e);
                }
                r.ok()
            }),
            qcert_storage.iter().skip(cached_blocks_start).map(|r| {
                if let Err(e) = &r {
                    warn!("failed to load QC. Error: {}", e);
                }
                r.ok()
            }),
        );
        let cached_blocks: Vec<BlockAndAssociated> = zipped_iters.collect();
        let mut index_by_txn_hash = HashMap::new();
        let mut index_by_last_record_id = BTreeMap::new();
        let mut cached_nullifier_sets = BTreeMap::new();
        let mut running_nullifier_set = SetMerkleTree::default();
        let index_by_block_hash = block_storage
            .iter()
            .filter_map(|res: Result<BlockQueryData, PersistenceError>| match res {
                Err(e) => {
                    warn!("failed to load block. Error: {}", e);
                    None
                }
                Ok(block) => {
                    block
                        .txn_hashes
                        .iter()
                        .enumerate()
                        .for_each(|(id, txn_hash)| {
                            index_by_txn_hash.insert(*txn_hash, (block.block_id, id as u64));
                        });
                    block.raw_block.block.0.iter().for_each(|txn| {
                        for n in txn.input_nullifiers() {
                            running_nullifier_set.insert(n);
                        }
                    });
                    if Self::calculate_sparse_cache(
                        block.block_id,
                        block_storage.iter().len() as u64,
                    ) {
                        cached_nullifier_sets.insert(block.block_id, running_nullifier_set.clone());
                    }
                    if block.record_count > 0 {
                        index_by_last_record_id
                            .insert(block.records_from + block.record_count - 1, block.block_id);
                    }
                    Some((block.block_hash, block.block_id))
                }
            })
            .collect();

        let (event_sender, event_receiver) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let events_loader = event_storage.iter();
        let events_count = events_loader.len();
        let cached_events_start = if events_count > CACHED_EVENTS_COUNT {
            events_count - CACHED_EVENTS_COUNT
        } else {
            0
        };
        let events = events_loader
            .skip(cached_events_start)
            .map(|ev| {
                if let Err(e) = &ev {
                    warn!("Failed to load event. Error: {}", e);
                }
                ev.ok()
            })
            .collect();
        // Load the last persisted validator status. If there is no existing status (e.g. the user
        // gave us an empty directory, but did not set the reset flag, so we ended up here and not
        // in `new`) we should behave as we do when creating a new store: use the default status.
        let node_status = status_storage.load_latest().unwrap_or_default();

        Ok(QueryData {
            cached_blocks_start,
            cached_blocks,
            index_by_block_hash,
            index_by_txn_hash,
            index_by_last_record_id,
            cached_events_start,
            events,
            event_sender,
            event_receiver,
            cached_nullifier_sets,
            node_status,
            query_storage,
            block_storage,
            state_storage,
            qcert_storage,
            event_storage,
            status_storage,
            consensus,
            location,
        })
    }

    pub fn commit_all(&mut self) {
        if let Err(e) = self.block_storage.commit_version() {
            warn!("Failed to commit block storage: Error {}", e);
        }
        if let Err(e) = self.state_storage.commit_version() {
            warn!("Failed to commit state storage: Error {}", e);
        }
        if let Err(e) = self.qcert_storage.commit_version() {
            warn!("Failed to commit qcert storage: Error {}", e);
        }
        if let Err(e) = self.event_storage.commit_version() {
            warn!("Failed to commit event storage: Error {}", e);
        }
        if let Err(e) = self.status_storage.commit_version() {
            warn!("Failed to commit status storage: Error {}", e);
        }
        if let Err(e) = self.query_storage.commit_version() {
            warn!("Failed to commit query state storage: Error {}", e);
        }
        if let Err(e) = self.status_storage.prune_file_entries() {
            warn!("Failed to prune status storage: Error {}", e);
        }
    }

    fn calculate_sparse_cache(_index: u64, _total_size: u64) -> bool {
        // issue: make this an inverse geometric function, with inflection at ~10%
        true
    }
}

impl crate::update_query_data_source::EventProcessedHandler for QueryData {
    fn on_event_processing_complete(&mut self) {
        self.commit_all();
    }
}
