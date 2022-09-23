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
use crate::merkle_tree::MerkleFrontier;
use crate::stake_table::{
    StakeTableCommitment, StakeTableHash, StakingKey, StakingKeySignature, StakingPrivKey,
    ViewNumber,
};
use crate::state::{CommitableHash, CommitableHashTag, ValidatorState};
use ark_serialize::*;
use ark_std::rand::{CryptoRng, RngCore};
use core::hash::Hash;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

/// Proof for Vrf output
pub type VrfProof = StakingKeySignature;

/// Compute the allowed stake amount given current state (e.g. circulating supply), view_number and stake amount
/// Hard-coded to 0 for FST
pub fn compute_reward_amount(
    _validator_state: &ValidatorState,
    _block_height: u64,
    _stake: Amount,
) -> Amount {
    Amount::from(0u64)
}

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

impl CollectRewardNote {
    /// Generate collect reward transaction note and helper proofs
    /// Return RewardError in case of failure (invalid staking key/view_number, merkle proof not found in validator state, or serialization error signing the body).
    #[allow(clippy::too_many_arguments)]
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        validator_state: &ValidatorState,
        view_number: hotshot_types::data::ViewNumber,
        block_height: u64,
        staking_priv_key: &StakingPrivKey,
        cap_address: UserAddress,
        stake_amount: Amount,
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
        vrf_proof: VrfProof,
    ) -> Result<(Self, RewardNoteProofs), RewardError> {
        let staking_key = StakingKey::from_priv_key(staking_priv_key);
        let (body, proofs) = CollectRewardBody::generate(
            rng,
            validator_state,
            view_number,
            block_height,
            staking_key,
            cap_address,
            stake_amount,
            stake_amount_proof,
            vrf_proof,
        )?;
        let size = CanonicalSerialize::serialized_size(&body);
        let mut bytes = Vec::with_capacity(size);
        CanonicalSerialize::serialize(&body, &mut bytes).map_err(RewardError::from)?;
        let note = CollectRewardNote {
            body,
            signature: StakingKey::sign(staking_priv_key, &bytes),
        };

        Ok((note, proofs))
    }

    /// verified a reward collect note
    pub fn verify(&self) -> Result<(), RewardError> {
        self.body.verify()?;
        let size = CanonicalSerialize::serialized_size(&self.body);
        let mut bytes = Vec::with_capacity(size);
        CanonicalSerialize::serialize(&self.body, &mut bytes).map_err(RewardError::from)?;
        if self
            .body
            .vrf_witness
            .staking_key
            .validate(&self.signature, &bytes)
        {
            Ok(())
        } else {
            Err(RewardError::SignatureError {})
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
    vrf_witness: EligibilityWitness,
}

impl CollectRewardBody {
    /// Generate collect reward transaction body and helper proofs
    /// Return RewardError in case of failure (invalid staking key/view_number, merkle proof not found in validator state).
    #[allow(clippy::too_many_arguments)]
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        validator_state: &ValidatorState,
        view_number: hotshot_types::data::ViewNumber,
        block_height: u64,
        staking_key: StakingKey,
        cap_address: UserAddress,
        stake_amount: Amount,
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
        vrf_proof: VrfProof,
    ) -> Result<(Self, RewardNoteProofs), RewardError> {
        let reward_amount = compute_reward_amount(validator_state, block_height, stake_amount);
        let blind_factor = BlindFactor::rand(rng);
        let rewards_proofs = RewardNoteProofs::generate(
            validator_state,
            view_number,
            &staking_key,
            stake_amount_proof,
        )?;
        let vrf_witness = EligibilityWitness {
            staking_key,
            view_number: view_number.into(),
            stake_amount,
            vrf_proof,
        };
        let body = CollectRewardBody {
            blind_factor,
            cap_address,
            reward_amount,
            vrf_witness,
        };
        Ok((body, rewards_proofs))
    }

    pub fn verify(&self) -> Result<(), RewardError> {
        self.vrf_witness.verify()
    }
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
struct EligibilityWitness {
    /// Staking public key
    staking_key: StakingKey,
    /// View number for which the key was elected
    view_number: ViewNumber,
    /// amount of stake on `view_number`
    stake_amount: Amount,
    /// Cryptographic proof
    vrf_proof: VrfProof,
}

impl EligibilityWitness {
    pub fn verify(&self) -> Result<(), RewardError> {
        if mock_eligibility::is_eligible(self.view_number, &self.staking_key, &self.vrf_proof) {
            Ok(())
        } else {
            Err(RewardError::KeyNotEligible {
                view: self.view_number,
                staking_key: self.staking_key.clone(),
            })
        }
    }
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
    /// Proof for stake table commitment and total stake for view number
    stake_table_commitment_leaf_proof:
        crate::merkle_tree::MerkleLeafProof<(StakeTableCommitment, Amount)>,
    /// Proof for stake_amount for staking key under above stake table commitment
    stake_amount_proof: KVMerkleProof<StakeTableHash>,
    /// Proof that reward hasn't been collected
    uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
}

impl RewardNoteProofs {
    /// Return RewardNoteHelperProofs if view_number is valid and staking_key was elected for it, otherwise return RewardError.
    pub(crate) fn generate(
        validator_state: &ValidatorState,
        view_number: hotshot_types::data::ViewNumber,
        stake_key: &StakingKey,
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
    ) -> Result<Self, RewardError> {
        let stake_table_commitment_leaf_proof =
            Self::get_stake_commitment_total_stake_and_proof(validator_state)?;
        let uncollected_reward_proof =
            Self::proof_uncollected_rewards(validator_state, stake_key, view_number)?;
        Ok(Self {
            stake_table_commitment_leaf_proof,
            stake_amount_proof,
            uncollected_reward_proof,
        })
    }

    /// Returns StakeTable commitment for view number, if view number is valid, otherwise return RewardError::InvalidViewNumber
    fn get_stake_commitment_total_stake_and_proof(
        validator_state: &ValidatorState,
    ) -> Result<crate::merkle_tree::MerkleLeafProof<(StakeTableCommitment, Amount)>, RewardError>
    {
        match validator_state.stake_table_commitments.clone() {
            MerkleFrontier::Empty { .. } => Err(RewardError::EmptyStakeTableCommitmentSet {}),
            MerkleFrontier::Proof(merkle_proof) => Ok(merkle_proof),
        }
    }

    /// Returns proof if reward hasn't been collected, otherwise RewardError::RewardAlreadyCollected
    fn proof_uncollected_rewards(
        validator_state: &ValidatorState,
        staking_key: &StakingKey,
        view_number: hotshot_types::data::ViewNumber,
    ) -> Result<KVMerkleProof<CollectedRewardsHash>, RewardError> {
        let key = CollectedRewards((staking_key.clone(), view_number.into()));
        // if (key, proof) not found, then key is present but not in memory. Hence, reward was collected.
        // if value is found, then reward was also collected
        // if value not found, return proof for it
        let (found, proof) = validator_state
            .collected_rewards
            .lookup(key)
            .ok_or(RewardError::RewardAlreadyCollected {})?;
        if found.is_none() {
            Ok(proof)
        } else {
            Err(RewardError::RewardAlreadyCollected {})
        }
    }
}

/// Reward Transaction Errors.
#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(visibility(pub(crate)))]
pub enum RewardError {
    /// An invalid view number
    InvalidViewNumber { view_number: ViewNumber },

    /// Serialization error
    SerializationError { reason: String },

    /// StakingKeyNotFound
    StakingKeyNotFound {},

    /// Reward has been already collected
    RewardAlreadyCollected {},

    /// No Stake table commitment
    EmptyStakeTableCommitmentSet {},

    /// Proof not in memory
    ProofNotInMemory {},

    /// Staking key not eligible for reward
    KeyNotEligible {
        view: ViewNumber,
        staking_key: StakingKey,
    },

    /// RewardNote failed signature
    SignatureError {},
}

impl From<ark_serialize::SerializationError> for RewardError {
    fn from(source: ark_serialize::SerializationError) -> Self {
        Self::SerializationError {
            reason: source.to_string(),
        }
    }
}

pub mod mock_eligibility {
    // TODO this is only mock implementation (and totally insecure as Staking keys (VRF keys) are not currently bls signature keys)
    // eligibility will be implemented in hotshot repo from a pro
    use super::*;
    use sha3::{Digest, Sha3_256};

    /// check weather a staking key is elegible for rewards
    pub fn is_eligible(
        view_number: ViewNumber,
        staking_key: &StakingKey,
        proof: &VrfProof,
    ) -> bool {
        // 1. compute vrf value = Hash ( vrf_proof)
        let mut hasher = Sha3_256::new();
        hasher.update(&bincode::serialize(proof).unwrap());
        let vrf_value = hasher.finalize();
        // 2. validate proof
        let data = bincode::serialize(&view_number).unwrap();
        if !staking_key.validate(proof, &data[..]) {
            return false;
        }
        // mock eligibility return true ~10% of times
        vrf_value[0] < 25
    }

    /// Prove that staking key is eligible for reward on view number. Return None if key is not eligible
    pub fn prove_eligibility(
        view_number: ViewNumber,
        staking_priv_key: &StakingPrivKey,
    ) -> Option<VrfProof> {
        // 1. compute vrf proof
        let data = bincode::serialize(&view_number).unwrap();
        let proof = StakingKey::sign(staking_priv_key, &data[..]);
        let pub_key = StakingKey::from_priv_key(staking_priv_key);
        // 2. check eligibility
        if is_eligible(view_number, &pub_key, &proof) {
            Some(proof)
        } else {
            None
        }
    }
    #[cfg(test)]
    mod test_eligibility {
        use crate::reward::mock_eligibility::{is_eligible, prove_eligibility};
        use crate::stake_table::{StakingKey, StakingPrivKey};
        use std::ops::Add;

        #[test]
        fn test_reward_eligibility() {
            let mut view_number = hotshot_types::data::ViewNumber::genesis();
            let priv_key = StakingPrivKey::generate();
            let bad_pub_key = StakingKey::from_priv_key(&StakingPrivKey::generate());
            let pub_key = StakingKey::from_priv_key(&priv_key);
            let mut found = 0;
            for _ in 0..600 {
                // with 600 runs we get ~2^{-100} failure pbb
                if let Some(proof) = prove_eligibility(view_number.into(), &priv_key) {
                    assert!(is_eligible(view_number.into(), &pub_key, &proof));
                    assert!(!is_eligible(view_number.into(), &bad_pub_key, &proof));
                    found += 1;
                }
                view_number = view_number.add(1);
            }
            assert_ne!(found, 0, "Staking key was never eligible");
            println!(
                "Staking key was found {} times out of 600: {:0.2}%, view_number:{:?}",
                found,
                (found as f64) / 6.0,
                view_number
            )
        }
    }
}
