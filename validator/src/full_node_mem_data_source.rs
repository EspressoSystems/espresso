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
use validator_node::api::EspressoError;
use validator_node::node::QueryServiceError;

#[derive(Default)]
pub struct QueryData {
    blocks: Vec<BlockQueryData>,
    states: Vec<StateQueryData>,
    index_by_block_hash: HashMap<BlockCommitment, u64>,
    index_by_txn_hash: HashMap<TransactionCommitment, (u64, u64)>,
    events: Vec<LedgerEvent<EspressoLedger>>,
    cached_nullifier_sets: BTreeMap<u64, SetMerkleTree>,
    node_status: ValidatorStatus,
}

impl<'a> AvailabilityDataSource for &'a QueryData {
    type BlockIterType = &'a [BlockQueryData];
    type StateIterType = &'a [StateQueryData];

    fn get_nth_block_iter(self, n: usize) -> Self::BlockIterType {
        self.blocks.split_at(n).1
    }
    fn get_nth_state_iter(self, n: usize) -> Self::StateIterType {
        self.states.split_at(n).1
    }
    fn get_block_index_by_hash(self, hash: BlockCommitment) -> Option<u64> {
        self.index_by_block_hash.get(&hash).cloned()
    }
    fn get_txn_index_by_hash(self, hash: TransactionCommitment) -> Option<(u64, u64)> {
        self.index_by_txn_hash.get(&hash).cloned()
    }
    fn get_record_index_by_uid(self, uid: u64) -> Option<(u64, u64, u64)> {
        if let Ok(index) = self.blocks.binary_search_by(|bqd| {
            if uid < bqd.records_from {
                std::cmp::Ordering::Less
            } else if uid >= bqd.records_from + bqd.record_count {
                std::cmp::Ordering::Greater
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
    fn get_record_merkle_tree_at_block_index(self, n: usize) -> Option<MerkleTree> {
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
        self.blocks.append(blocks);
        self.states.append(states);
        Ok(())
    }
}

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
}

impl UpdateCatchUpData for QueryData {
    type Error = EspressoError;
    fn append_events(
        &mut self,
        events: &mut Vec<LedgerEvent<EspressoLedger>>,
    ) -> Result<(), Self::Error> {
        self.events.append(events);
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
                    for nullifier_in in transaction.nullifiers() {
                        adjusted_nullifier_set.insert(nullifier_in);
                    }
                }
            }
            Ok(op(&adjusted_nullifier_set))
        }
    }
}

impl<'a> MetaStateDataSource for &'a QueryData {
    fn get_nullifier_proof_for(
        self,
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

impl<'a> StatusDataSource<'a> for &'a QueryData {
    fn get_validator_status(self) -> &'a ValidatorStatus {
        &self.node_status
    }
}

impl UpdateStatusData for QueryData {
    type Error = EspressoError;

    fn set_status(&mut self, status: ValidatorStatus) -> Result<(), Self::Error> {
        self.node_status = status;
        Ok(())
    }
    fn edit_status<U, F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnOnce(&mut ValidatorStatus) -> Result<(), U>,
        Self::Error: From<U>,
    {
        op(&mut self.node_status).map_err(EspressoError::from)?;
        Ok(())
    }
}

impl QueryData {
    pub fn new() -> QueryData {
        QueryData {
            blocks: Vec::new(),
            states: Vec::new(),
            index_by_block_hash: HashMap::new(),
            index_by_txn_hash: HashMap::new(),
            events: Vec::new(),
            cached_nullifier_sets: BTreeMap::new(),
            node_status: ValidatorStatus::default(),
        }
    }
}
