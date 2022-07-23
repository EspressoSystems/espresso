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

use crate::query_data::{BlockQueryData, StateQueryData};
use espresso_core::state::{BlockCommitment, TransactionCommitment};
use jf_cap::MerkleTree;

/// Trait to be implemented on &'a DataSource for lifetime management purposes
pub trait AvailabilityDataSource {
    type BlockIterType: AsRef<[BlockQueryData]>;
    type StateIterType: AsRef<[StateQueryData]>;
    fn get_nth_block_iter(self, n: usize) -> Self::BlockIterType;
    fn get_nth_state_iter(self, n: usize) -> Self::StateIterType;
    fn get_block_index_by_hash(self, hash: BlockCommitment) -> Option<u64>;
    fn get_txn_index_by_hash(self, hash: TransactionCommitment) -> Option<(u64, u64)>;
    fn get_record_index_by_uid(self, uid: u64) -> Option<(u64, u64, u64)>; // None if OOB
                                                                           // it should be possible to implement this one in terms of the above,
                                                                           // leaving more compact and/or performant solutions as optional
    fn get_record_merkle_tree_at_block_index(self, n: usize) -> Option<MerkleTree>;
}

pub trait UpdateAvailabilityData {
    type Error;
    fn append_blocks(
        &mut self,
        blocks: &mut Vec<BlockQueryData>,
        states: &mut Vec<StateQueryData>,
    ) -> Result<(), Self::Error>;
}
