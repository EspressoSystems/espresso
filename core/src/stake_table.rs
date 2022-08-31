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

use crate::state::{CommitableHash, CommitableHashTag, StakingKey};
use crate::tree_hash::KVTreeHash;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use jf_cap::structs::Amount;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

/*
///The StakeTableKey is the key identifying a user who had stake in a given round
#[tagged_blob("STAKEKEY")]
#[derive(Debug, Clone, PartialEq, Hash, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct StakeTableKey(pub(crate) StakingKey);

///The values in the stake table are the amount staked by the holder of the associated StakingTableKey
#[tagged_blob("STAKEVALUE")]
#[derive(Clone, Debug, Copy, PartialEq, Hash, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct StakeTableValue(pub(crate) Amount);
*/

/// HotShot View number
#[derive(
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ViewNumber(pub(crate) u64);

///Identifying tag for a StakeTable
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct StakeTableTag();
impl CommitableHashTag for StakeTableTag {
    fn commitment_diversifier() -> &'static str {
        "Stake Table Input"
    }
}

/// Hash function for the Stake Table
pub type StakeTableHash = CommitableHash<StakingKey, Amount, StakeTableTag>;

/// Identifying tag for a StakeTableCommitment
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct StakeTableCommitmentTag();
impl CommitableHashTag for StakeTableCommitmentTag {
    fn commitment_diversifier() -> &'static str {
        "Stake Table Commitment"
    }
}

/// Stake table commitment type
pub type StakeTableCommitment = <StakeTableHash as KVTreeHash>::Digest;

/// Hash for tree which stores commitment hash of previous rounds' stake tables in (view_number, stake table commitment) kv pairs
pub type StakeTableCommitmentsHash =
    CommitableHash<ViewNumber, <StakeTableHash as KVTreeHash>::Digest, StakeTableCommitmentTag>;

/// Previously collected rewards are recorded in (StakingKey, view_number) pairs
#[tagged_blob("COLLECTED-REWARD")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectedRewards((StakingKey, u64));

/// Identifying tag for CollectedReward
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct CollectedRewardsTag();
impl CommitableHashTag for CollectedRewardsTag {
    fn commitment_diversifier() -> &'static str {
        "Collected rewards"
    }
}

/// Hash for set Merkle tree for all of the previously-collected rewards
pub type CollectedRewardsHash = CommitableHash<CollectedRewards, (), CollectedRewardsTag>;
