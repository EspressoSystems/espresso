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
use espresso_macros::ser_test;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_utils::tagged_blob;

/// Reward Collection Transaction Note
#[tagged_blob("RewardTxn")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectRewardNote {
    /// block number of reward claim
    block_number: u64,
    /// Blinding factor for reward record commitment on CAP native asset
    blind_factor: BlindFactor,
    /// Address that owns the reward
    cap_address: UserAddress,
    /// Reward amount
    reward_amount: Amount,
    /// Staking `pub_key`, `view` number and a proof that staking key was selected for committee election on `view`
    vrf_witness_info: VrfWitness,
    /// Auxiliary info and proof of validity for reward
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
#[ser_test(random(random_for_test))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
struct VrfWitness {
    /// Staking public key
    staking_key: StakingKey,
    /// View number for wich the key was elected
    view_number: u64,
    /// amount of stake on reward to be claimed block
    stake_amount: u64, /*
                       /// VRF Proof
                       proof:
                       */
}

/// Auxiliary info and proof for CollectRewardNote
///  * Stake table commitment `comm` on `block_number`
///  * `pub_key` is eligible for reward
///  * * Proof that block was produced on view `view`
///  * * Proof `comm` is valid commitment for `block_number`
///  * * Proof for `stake_amount` for `pub_key` on `block_number`
///  *  Proof that reward hasn't been collected
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
struct RewardNoteAuxInfo {
    /// Stake table commmitment for the block number reward
    stake_table_commitment: <StakeTableCommitmentsHash as KVTreeHash>::Digest,
    /// Proof for view number matches block number
    block_number_to_view_proof: KVMerkleProof<BlockToViewCommittableHash>,
    /// Proof that reward hasn't been collected
    uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
    /// Proof for stake_table_commitment
    block_number_to_stake_table_commitment: KVMerkleProof<StakeTableCommitmentsHash>,
    /// Proof for stake_amount for staking key on that block number
    staking_key_to_stake_amount: KVMerkleProof<StakeKeyToStakeAmountCommittableHash>,
}
