use std::collections::{BTreeMap, HashMap};

use espresso_availability_api::data_source::AvailabilityDataSource;
use espresso_availability_api::query_data::{BlockQueryData, StateQueryData};
use espresso_catchup_api::data_source::CatchUpDataSource;
use espresso_metastate_api::data_source::MetaStateDataSource;
use espresso_status_api::data_source::StatusDataSource;
use espresso_status_api::query_data::ValidatorStatus;
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use seahorse::events::LedgerEvent;
use zerok_lib::ledger::EspressoLedger;
use zerok_lib::state::{BlockCommitment, ElaboratedTransactionHash, SetMerkleProof, SetMerkleTree};

struct QueryData {
    blocks: Vec<BlockQueryData>,
    states: Vec<StateQueryData>,
    index_by_block_hash: HashMap<BlockCommitment, u64>,
    index_by_txn_hash: HashMap<ElaboratedTransactionHash, (u64, u64)>,
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
    fn get_txn_index_by_hash(self, hash: ElaboratedTransactionHash) -> Option<(u64, u64)> {
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

impl<'a> CatchUpDataSource for &'a QueryData {
    type EventIterType = &'a [LedgerEvent<EspressoLedger>];
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType {
        self.events.split_at(n).1
    }
}

impl<'a> MetaStateDataSource for &'a QueryData {
    fn get_nullifier_proof_for(
        self,
        block_id: u64,
        nullifier: Nullifier,
    ) -> Option<(bool, SetMerkleProof)> {
        if block_id as usize > self.blocks.len() {
            tracing::error!(
                "Max block index exceeded; max: {}, queried for {}",
                self.blocks.len(),
                block_id
            );
            return None;
        }
        let default_nullifier_set = SetMerkleTree::default();
        let prev_cached_set = self.cached_nullifier_sets.range(..block_id + 1).next_back();
        let (index, nullifier_set) = if let Some((index, tree)) = prev_cached_set {
            (index, tree)
        } else {
            (&0, &default_nullifier_set)
        };
        if *index == block_id {
            nullifier_set.contains(nullifier)
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
            adjusted_nullifier_set.contains(nullifier)
        }
    }
}

impl<'a> StatusDataSource<'a> for &'a QueryData {
    fn get_validator_status(self) -> &'a ValidatorStatus {
        &self.node_status
    }
}
