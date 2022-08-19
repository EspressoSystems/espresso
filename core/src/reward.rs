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

use crate::state::CollectedRewardsHash;
use ark_serialize::*;
use core::hash::Hash;
use jf_utils::tagged_blob;

#[tagged_blob("RewardTxn")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectRewardNote {
    block_number: u64, //TODO (fernando) what's the correct type for it?
    merkle_proof: crate::kv_merkle_tree::KVMerkleProof<CollectedRewardsHash>,
    blind_factor: jf_cap::BaseField,
}
