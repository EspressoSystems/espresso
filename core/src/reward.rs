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
use crate::kvmt_instances::{
    BlockToViewCommittableHash, CollectedRewardsHash, StakeKeyToStakeAmountCommittableHash,
    StakeTableCommitmentsHash,
};
use crate::state::StakingKey;
use crate::tree_hash::KVTreeHash;
use ark_serialize::*;
use core::hash::Hash;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_utils::tagged_blob;

/// Reward Collection Transaction Note
#[tagged_blob("RewardTxn")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectRewardNote {
    block_number: u64,
    blind_factor: BlindFactor,
    cap_address: UserAddress,
    reward_amount: Amount,
    vrf_witness: VrfWitness,
    auxiliary_info: RewardNoteAuxInfo,
}

impl CollectRewardNote {
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

#[tagged_blob("VrfWitness")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
struct VrfWitness {
    staking_key: StakingKey,
    view_number: u64,
    // proof TODO
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
struct RewardNoteAuxInfo {
    block_number_stake_table_commitment: <StakeTableCommitmentsHash as KVTreeHash>::Digest,
    block_number_to_view_proof: KVMerkleProof<BlockToViewCommittableHash>,
    uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
    block_number_to_stake_table_commitment: KVMerkleProof<StakeTableCommitmentsHash>,
    staking_key_to_staked_amount: KVMerkleProof<StakeKeyToStakeAmountCommittableHash>,
}