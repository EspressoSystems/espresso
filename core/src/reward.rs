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

use crate::kv_merkle_tree::KVMerkleProof;
use crate::stake_table::{
    StakeTableCommitment, StakeTableHash, StakingKey, StakingKeySignature, ViewNumber,
};
use crate::state::{CommitableHash, CommitableHashTag};
use ark_serialize::*;
use core::hash::Hash;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

/// Previously collected rewards are recorded in (StakingKey, view_number) pairs
#[tagged_blob("COLLECTED-REWARD")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectedRewards((StakingKey, ViewNumber));

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

/// Reward Collection Transaction Note
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct CollectRewardNote {
    body: CollectRewardBody,
    signature: StakingKeySignature,
}

/// Reward Collection Transaction Note
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct CollectRewardBody {
    /// Blinding factor for reward record commitment on CAP native asset
    blind_factor: BlindFactor,
    /// Address that owns the reward
    cap_address: UserAddress,
    /// Reward amount
    reward_amount: Amount,
    /// Staking `pub_key`, `view` number and a proof that staking key was selected for committee election on `view`
    vrf_witness: VrfWitness,
}

impl CollectRewardBody {
    pub(crate) fn output_commitment(&self) -> RecordCommitment {
        RecordCommitment::from(&self.output_opening())
    }

    pub(crate) fn output_opening(&self) -> RecordOpening {
        RecordOpening {
            amount: self.reward_amount,
            asset_def: AssetDefinition::native(),
            pub_key: UserPubKey::new(self.cap_address.clone(), Default::default()),
            freeze_flag: FreezeFlag::Unfrozen,
            blind: self.blind_factor,
        }
    }
}

impl CollectRewardNote {
    pub(crate) fn output_commitment(&self) -> RecordCommitment {
        self.body.output_commitment()
    }

    pub(crate) fn output_opening(&self) -> RecordOpening {
        self.body.output_opening()
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
struct VrfWitness {
    /// Staking public key
    staking_key: StakingKey,
    /// View number for which the key was elected
    view_number: ViewNumber,
    /// amount of stake on `view_number`
    stake_amount: Amount, /*
                          /// VRF Proof
                          proof:
                          */
}

/// Auxiliary info and proof for CollectRewardNote
///  * Stake table commitment `comm` on `view_number`
///  * Proof for `staking_pub_key` is eligible for reward:
///  * * Proof `comm` is valid stake table commitment for `view_number`
///  * * Proof for `staking_pub_key` mapped to `stake_amount` on `view_number`
///  *  Proof that reward hasn't been collected
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct RewardNoteProofs {
    /// Stake table commitment for the view number reward
    stake_table_commitment: StakeTableCommitment,
    /// Proof for stake_table_commitment
    stake_table_commitment_proof:
        crate::merkle_tree::MerkleLeafProof<(StakeTableCommitment, Amount)>,
    /// Proof for stake_amount for staking key on that view number
    stake_amount_proof: KVMerkleProof<StakeTableHash>,
    /// Proof that reward hasn't been collected
    uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
}
