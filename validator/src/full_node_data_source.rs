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

use atomic_store::{
    load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader, PersistenceError,
    RollingLog,
};
use espresso_availability_api::data_source::{AvailabilityDataSource, UpdateAvailabilityData};
use espresso_availability_api::query_data::{BlockQueryData, StateQueryData};
use espresso_catchup_api::data_source::{CatchUpDataSource, UpdateCatchUpData};
use espresso_core::ledger::EspressoLedger;
use espresso_core::state::{BlockCommitment, SetMerkleProof, SetMerkleTree, TransactionCommitment};
use espresso_metastate_api::data_source::{MetaStateDataSource, UpdateMetaStateData};
use espresso_status_api::data_source::{StatusDataSource, UpdateStatusData};
use espresso_status_api::query_data::ValidatorStatus;
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use seahorse::events::LedgerEvent;
use tracing::warn;
use validator_node::api::EspressoError;
use validator_node::node::QueryServiceError;

pub struct QueryData {
    blocks: Vec<BlockQueryData>,
    states: Vec<StateQueryData>,
    index_by_block_hash: HashMap<BlockCommitment, u64>,
    index_by_txn_hash: HashMap<TransactionCommitment, (u64, u64)>,
    events: Vec<LedgerEvent<EspressoLedger>>,
    event_sender: async_channel::Sender<(usize, LedgerEvent<EspressoLedger>)>,
    event_receiver: async_channel::Receiver<(usize, LedgerEvent<EspressoLedger>)>,
    cached_nullifier_sets: BTreeMap<u64, SetMerkleTree>,
    node_status: ValidatorStatus,
    state_storage: AtomicStore,
    block_storage: AppendLog<BincodeLoadStore<(BlockQueryData, StateQueryData)>>,
    event_storage: AppendLog<BincodeLoadStore<LedgerEvent<EspressoLedger>>>,
    status_storage: RollingLog<BincodeLoadStore<ValidatorStatus>>,
}

// We implement [AvailabilityDataSource] for `&'a QueryData`, not `QueryData`, so that we can name
// the lifetime `'a` when defining the associated iterator types. This is a workaround in place of
// GATs. Once GATs stabilize, we can do something like
//
//      type BlockIterType<'a> = &'a [BlockQueryData];
//      fn get_nth_block_iter(&self, n: usize) -> Self::BlockIterType<'_>;
impl<'a> AvailabilityDataSource for &'a QueryData {
    type BlockIterType = &'a [BlockQueryData];
    type StateIterType = &'a [StateQueryData];

    fn get_nth_block_iter(&self, n: usize) -> Self::BlockIterType {
        self.blocks.split_at(n).1
    }
    fn get_nth_state_iter(&self, n: usize) -> Self::StateIterType {
        self.states.split_at(n).1
    }
    fn get_block_index_by_hash(&self, hash: BlockCommitment) -> Option<u64> {
        self.index_by_block_hash.get(&hash).cloned()
    }
    fn get_txn_index_by_hash(&self, hash: TransactionCommitment) -> Option<(u64, u64)> {
        self.index_by_txn_hash.get(&hash).cloned()
    }
    fn get_record_index_by_uid(&self, uid: u64) -> Option<(u64, u64, u64)> {
        if let Ok(index) = self.blocks.binary_search_by(|bqd| {
            if uid < bqd.records_from {
                std::cmp::Ordering::Greater
            } else if uid >= bqd.records_from + bqd.record_count {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            let block = &self.blocks[index];
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
                Some((index as u64, txn_idx, remainder))
            } else {
                // This should never happen.
                tracing::error!("QueryData::get_record_index_by_uid encountered bad state for uid {}; found block {} with uid range {}+{}, but transaction outputs did not match", uid, index, block.records_from, block.record_count);
                None
            }
        } else {
            None
        }
    }
    fn get_record_merkle_tree_at_block_index(&self, n: usize) -> Option<MerkleTree> {
        let state = &self.states[n].state;
        MerkleTree::restore_from_frontier(
            state.record_merkle_commitment,
            &state.record_merkle_frontier,
        )
    }
}

impl UpdateAvailabilityData for QueryData {
    type Error = EspressoError;

    fn append_blocks(
        &mut self,
        blocks: &mut Vec<BlockQueryData>,
        states: &mut Vec<StateQueryData>,
    ) -> Result<(), Self::Error> {
        if blocks.len() != states.len() {
            // this isn't really supposed to be possible; the calling code for this impl will be
            // in FullState::update, which currently invokes panic! if these lengths differ.
            return Err(EspressoError::from(
                QueryServiceError::InvalidHistoricalIndex {},
            ));
        }
        let start_index = self.blocks.len();
        for (index, block) in blocks.iter().enumerate() {
            let block_index = (index + start_index) as u64;
            self.index_by_block_hash
                .insert(block.block_hash, block_index);
            for (index, txn_hash) in block.txn_hashes.iter().enumerate() {
                self.index_by_txn_hash
                    .insert(*txn_hash, (block_index, index as u64));
            }
        }
        blocks.iter().zip(states.iter()).for_each(|(block, state)| {
            if let Err(e) = self
                .block_storage
                .store_resource(&(block.clone(), state.clone()))
            {
                warn!(
                    "Failed to store block {:?} and state {:?}: Error: {}",
                    block, state, e
                );
            }
        });
        self.blocks.append(blocks);
        self.states.append(states);
        Ok(())
    }
}

// We implement [CatchUpDataSource] for `&'a QueryData`, not `QueryData`, so that we can name the
// lifetime `'a` when defining the associated iterator types. This is a workaround in place of GATs.
// Once GATs stabilize, we can do something like
//
//      type EventIterType<'a> = &'a [LedgerEvent<EspressoLedger>];
//      fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType<'_>;
impl<'a> CatchUpDataSource for &'a QueryData {
    type EventIterType = &'a [LedgerEvent<EspressoLedger>];
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType {
        self.events.split_at(n).1
    }
    fn len(&self) -> usize {
        self.events.len()
    }
    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    fn subscribe(&self) -> async_channel::Receiver<(usize, LedgerEvent<EspressoLedger>)> {
        self.event_receiver.clone()
    }
}

impl UpdateCatchUpData for QueryData {
    type Error = EspressoError;
    fn append_events(
        &mut self,
        events: &mut Vec<LedgerEvent<EspressoLedger>>,
    ) -> Result<(), Self::Error> {
        for e in std::mem::take(events) {
            if let Err(err) = self.event_storage.store_resource(&e) {
                warn!("Failed to store event {:?}, Error: {}", e, err);
            }

            // `try_send` fails if the channel is full or closed. The channel cannot be full because
            // it is unbounded, and cannot be closed because `self` owns copies of both ends.
            self.event_sender
                .try_send((self.events.len(), e.clone()))
                .expect("unexpected failure when broadcasting event");
            self.events.push(e);
        }
        Ok(())
    }

    fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl QueryData {
    fn with_nullifier_set_at_block<U>(
        &self,
        block_id: u64,
        op: impl FnOnce(&SetMerkleTree) -> U,
    ) -> Result<U, EspressoError> {
        if block_id as usize > self.blocks.len() {
            tracing::error!(
                "Max block index exceeded; max: {}, queried for {}",
                self.blocks.len(),
                block_id
            );
            return Err(QueryServiceError::InvalidHistoricalIndex {}.into());
        }
        let default_nullifier_set = SetMerkleTree::default();
        let prev_cached_set = self.cached_nullifier_sets.range(..block_id + 1).next_back();
        let (index, nullifier_set) = if let Some((index, tree)) = prev_cached_set {
            (index, tree)
        } else {
            (&0, &default_nullifier_set)
        };
        if *index == block_id {
            Ok(op(nullifier_set))
        } else {
            let mut adjusted_nullifier_set = nullifier_set.clone();
            let index = *index as usize;
            for last_index in index..block_id as usize {
                let block = &self.blocks[last_index + 1];
                for transaction in block.raw_block.block.0.iter() {
                    for nullifier_in in transaction.input_nullifiers() {
                        adjusted_nullifier_set.insert(nullifier_in);
                    }
                }
            }
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
        if let Ok(proof) = self.with_nullifier_set_at_block(block_id, |ns| ns.contains(nullifier)) {
            proof
        } else {
            None
        }
    }
}

impl UpdateMetaStateData for QueryData {
    type Error = EspressoError;
    fn append_block_nullifiers(
        &mut self,
        block_id: u64,
        nullifiers: Vec<Nullifier>,
    ) -> Result<(), Self::Error> {
        let nullifier_set = self.with_nullifier_set_at_block(block_id - 1, |ns| {
            let mut nullifier_set = ns.clone();
            for nullifier in nullifiers.iter() {
                nullifier_set.insert(*nullifier);
            }
            nullifier_set
        })?;
        self.cached_nullifier_sets.insert(block_id, nullifier_set);
        Ok(())
    }
}

impl StatusDataSource for QueryData {
    fn get_validator_status(&self) -> &ValidatorStatus {
        &self.node_status
    }
}

impl UpdateStatusData for QueryData {
    type Error = EspressoError;

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
        op(&mut self.node_status).map_err(EspressoError::from)?;
        if let Err(e) = self.status_storage.store_resource(&self.node_status) {
            warn!(
                "Failed to store status {:?}, Error {}",
                &self.node_status, e
            );
        }
        Ok(())
    }
}

const STATUS_STORAGE_COUNT: u32 = 10u32;

impl QueryData {
    pub fn new(store_path: &Path) -> Result<QueryData, PersistenceError> {
        let key_tag = "query_data_store";
        let blocks_tag = format!("{}_blocks", key_tag);
        let events_tag = format!("{}_events", key_tag);
        let status_tag = format!("{}_status", key_tag);
        let mut loader = AtomicStoreLoader::create(store_path, key_tag)?;
        let block_storage = AppendLog::create(&mut loader, Default::default(), &blocks_tag, 1024)?;
        let event_storage = AppendLog::create(&mut loader, Default::default(), &events_tag, 1024)?;
        let mut status_storage =
            RollingLog::create(&mut loader, Default::default(), &status_tag, 1024)?;
        // this should be loaded from a config setting...
        status_storage.set_retained_entries(STATUS_STORAGE_COUNT);

        let state_storage = AtomicStore::open(loader)?;

        let (event_sender, event_receiver) = async_channel::unbounded();
        Ok(QueryData {
            blocks: Vec::new(),
            states: Vec::new(),
            index_by_block_hash: HashMap::new(),
            index_by_txn_hash: HashMap::new(),
            events: Vec::new(),
            event_sender,
            event_receiver,
            cached_nullifier_sets: BTreeMap::new(),
            node_status: ValidatorStatus::default(),
            state_storage,
            block_storage,
            event_storage,
            status_storage,
        })
    }

    pub fn load(store_path: &Path) -> Result<QueryData, PersistenceError> {
        let key_tag = "query_data_store";
        let blocks_tag = format!("{}_blocks", key_tag);
        let events_tag = format!("{}_events", key_tag);
        let status_tag = format!("{}_status", key_tag);
        let mut loader = AtomicStoreLoader::load(store_path, key_tag)?;
        let block_storage = AppendLog::load(&mut loader, Default::default(), &blocks_tag, 1024)?;
        let event_storage = AppendLog::load(&mut loader, Default::default(), &events_tag, 1024)?;
        let mut status_storage =
            RollingLog::load(&mut loader, Default::default(), &status_tag, 1024)?;
        // this should be loaded from a config setting...
        status_storage.set_retained_entries(STATUS_STORAGE_COUNT);
        let state_storage = AtomicStore::open(loader)?;

        let (blocks, states): (Vec<BlockQueryData>, Vec<StateQueryData>) =
            block_storage.iter().filter_map(|t| t.ok()).unzip();
        let mut index_by_txn_hash = HashMap::new();
        let mut cached_nullifier_sets = BTreeMap::new();
        let mut running_nullifier_set = SetMerkleTree::default();
        let index_by_block_hash = blocks
            .iter()
            .map(|block| {
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
                if Self::calculate_sparse_cache(block.block_id, blocks.len() as u64) {
                    cached_nullifier_sets.insert(block.block_id, running_nullifier_set.clone());
                }
                (block.block_hash, block.block_id)
            })
            .collect();

        let (event_sender, event_receiver) = async_channel::unbounded();
        let events = event_storage.iter().filter_map(|e| e.ok()).collect();
        let node_status = status_storage.load_latest()?;

        Ok(QueryData {
            blocks,
            states,
            index_by_block_hash,
            index_by_txn_hash,
            events,
            event_sender,
            event_receiver,
            cached_nullifier_sets,
            node_status,
            state_storage,
            block_storage,
            event_storage,
            status_storage,
        })
    }

    pub fn commit_all(&mut self) {
        if let Err(e) = self.block_storage.commit_version() {
            warn!("Failed to commit block storage: Error {}", e);
        }
        if let Err(e) = self.event_storage.commit_version() {
            warn!("Failed to commit event storage: Error {}", e);
        }
        if let Err(e) = self.status_storage.commit_version() {
            warn!("Failed to commit status storage: Error {}", e);
        }
        if let Err(e) = self.state_storage.commit_version() {
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

impl validator_node::update_query_data_source::EventProcessedHandler for QueryData {
    fn on_event_processing_complete(&mut self) {
        self.commit_all();
    }
}
