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

use crate::kv_merkle_tree::{KVMerkleProof, KVMerkleTree};
use crate::merkle_tree::MerkleFrontier;
use crate::stake_table::{
    StakeTableCommitment, StakeTableHash, StakeTableSetFrontier, StakingKey, StakingKeySignature,
    StakingPrivKey,
};
use crate::state::{
    CommitableHash, CommitableHashTag, ConsensusTime, ValidationError, ValidatorState, VrfSeed,
};
use crate::tree_hash::KVTreeHash;
pub use crate::util::canonical;
use ark_serialize::*;
use ark_std::rand::{CryptoRng, RngCore};
use commit::Committable;
use core::fmt::Debug;
use core::hash::Hash;
use hotshot::types::SignatureKey;
use jf_cap::keys::UserPubKey;
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_primitives::signatures::bls::BLSSignature;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{HashMap, HashSet, VecDeque};
use std::iter::once;
use std::num::NonZeroU64;

/// Proof for Vrf output
#[tagged_blob("VRFPROOF")]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfProof(BLSSignature<ark_bls12_381::Parameters>);
impl Debug for VrfProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}
impl PartialEq for VrfProof {
    fn eq(&self, other: &Self) -> bool {
        canonical::serialize(self).unwrap() == canonical::serialize(other).unwrap()
    }
}

impl Eq for VrfProof {}

impl Hash for VrfProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Hash::hash(&canonical::serialize(self).unwrap(), state)
    }
}

/// Compute the allowed stake amount given committee size, view_number and number of votes
/// Hard-coded to 0 for FST
//TODO: !kaley add block fees to compute_reward_amount
pub fn compute_reward_amount(_block_height: u64, _votes: u64, _committee_size: u64) -> Amount {
    Amount::from(1000u64)
}

/// Previously collected rewards are recorded in (StakingKey, view_number) pairs
#[tagged_blob("COLLECTED-REWARD")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectedRewards {
    /// Staking key eligible for reward
    pub staking_key: StakingKey,
    /// Time at which `staking key` was eligible for reward
    pub time: ConsensusTime,
}

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
        historical_stake_tables_frontier: &StakeTableSetFrontier,
        historical_stake_tables_num_leaves: u64,
        committee_size: u64,
        block_height: u64,
        staking_priv_key: &StakingPrivKey,
        cap_pub_key: UserPubKey,
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
        uncollected_reward_proof: CollectedRewardsProof,
        eligibility_witness: EligibilityWitness,
    ) -> Result<(Self, RewardNoteProofs), RewardError> {
        let (body, proofs) = CollectRewardBody::generate(
            rng,
            historical_stake_tables_frontier,
            historical_stake_tables_num_leaves,
            committee_size,
            block_height,
            cap_pub_key,
            stake_amount_proof,
            uncollected_reward_proof,
            eligibility_witness,
        )?;
        let size = CanonicalSerialize::serialized_size(&body);
        let mut bytes = Vec::with_capacity(size);
        CanonicalSerialize::serialize(&body, &mut bytes).map_err(RewardError::from)?;
        let note = CollectRewardNote {
            body,
            signature: StakingKey::sign(staking_priv_key, &bytes).into(),
        };

        Ok((note, proofs))
    }

    /// verifies a reward collect note
    pub fn verify(
        &self,
        committee_size: u64,
        vrf_seed: VrfSeed,
        stake_amount: Amount,
        total_stake: NonZeroU64,
    ) -> Result<(), RewardError> {
        self.body
            .verify(committee_size, vrf_seed, stake_amount, total_stake)?;
        let size = CanonicalSerialize::serialized_size(&self.body);
        let mut bytes = Vec::with_capacity(size);
        CanonicalSerialize::serialize(&self.body, &mut bytes).map_err(RewardError::from)?;
        if self
            .body
            .eligibility_witness
            .staking_key
            .validate(self.signature.as_ref(), &bytes)
        {
            Ok(())
        } else {
            Err(RewardError::SignatureError {})
        }
    }

    /// returns staking for which reward is being claimed
    pub fn staking_key(&self) -> StakingKey {
        self.body.eligibility_witness.staking_key.clone()
    }

    /// returns number of votes validator had for reward being claimed
    pub fn num_votes(&self) -> u64 {
        self.body.eligibility_witness.num_seats
    }

    /// returns time for which reward is being claimed
    pub fn time(&self) -> ConsensusTime {
        self.body.eligibility_witness.time
    }

    /// returns amount claimed for reward
    pub fn reward_amount(&self) -> Amount {
        self.body.reward_amount
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
    cap_pub_key: UserPubKey,
    /// Reward amount
    reward_amount: Amount,
    /// Staking `pub_key`, `view` number and a proof that staking key was selected for committee election on `view`
    eligibility_witness: EligibilityWitness,
}

impl CollectRewardBody {
    /// Generate collect reward transaction body and helper proofs
    /// Return RewardError in case of failure (invalid staking key/view_number, merkle proof not found in validator state).
    #[allow(clippy::too_many_arguments)]
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        historical_stake_tables_frontier: &StakeTableSetFrontier,
        historical_stake_tables_num_leaves: u64,
        committee_size: u64,
        block_height: u64,
        cap_pub_key: UserPubKey,
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
        uncollected_reward_proof: CollectedRewardsProof,
        eligibility_witness: EligibilityWitness,
    ) -> Result<(Self, RewardNoteProofs), RewardError> {
        let allowed_reward =
            compute_reward_amount(block_height, eligibility_witness.num_seats, committee_size);
        let blind_factor = BlindFactor::rand(rng);
        let rewards_proofs = {
            // assemble reward proofs
            match &historical_stake_tables_frontier {
                MerkleFrontier::Proof(merkle_proof) => RewardNoteProofs {
                    stake_tables_set_leaf_proof: merkle_proof.clone(),
                    stake_amount_proof,
                    uncollected_reward_proof,
                    leaf_proof_pos: historical_stake_tables_num_leaves - 1,
                },
                MerkleFrontier::Empty { .. } => {
                    return Err(RewardError::EmptyStakeTableCommitmentSet {});
                }
            }
        };
        let body = CollectRewardBody {
            blind_factor,
            cap_pub_key,
            reward_amount: allowed_reward, // TODO allow fees, need to subtract fee from reward_amount
            eligibility_witness,
        };
        Ok((body, rewards_proofs))
    }

    pub fn verify(
        &self,
        committee_size: u64,
        vrf_seed: VrfSeed,
        stake_amount: Amount,
        total_stake: NonZeroU64,
    ) -> Result<(), RewardError> {
        self.eligibility_witness
            .verify(committee_size, vrf_seed, stake_amount, total_stake)
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
            pub_key: self.cap_pub_key.clone(),
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
pub struct EligibilityWitness {
    /// Staking public key
    staking_key: StakingKey,
    /// View number for which the key was elected for reward
    time: ConsensusTime,
    /// Cryptographic proof
    vrf_proof: VrfProof,
    /// Number of committee seats
    num_seats: u64,
}

impl EligibilityWitness {
    pub fn verify(
        &self,
        committee_size: u64,
        vrf_seed: VrfSeed,
        stake_amount: Amount,
        total_stake: NonZeroU64,
    ) -> Result<(), RewardError> {
        if eligibility::check_eligibility(
            committee_size,
            vrf_seed,
            self.time,
            stake_amount,
            total_stake,
            self,
        ) {
            Ok(())
        } else {
            Err(RewardError::KeyNotEligible {
                view: self.time,
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
    stake_tables_set_leaf_proof:
        crate::merkle_tree::MerkleLeafProof<(StakeTableCommitment, Amount, ConsensusTime)>,
    /// Proof for stake_amount for staking key under above stake table commitment
    stake_amount_proof: KVMerkleProof<StakeTableHash>,
    /// Proof that reward hasn't been collected
    uncollected_reward_proof: CollectedRewardsProof,
    /// Index of relevant stake table commitment in MerkleTree
    leaf_proof_pos: u64,
}

impl RewardNoteProofs {
    /// Checks proofs in RewardNoteProofs against ValidatorState
    /// On success, return RewardProofExtractedData
    pub fn verify(
        &self,
        validator_state: &ValidatorState,
        claimed_reward: CollectedRewards, // staking key and time t
    ) -> Result<(CollectedRewardsDigest, Amount), ValidationError> {
        let stake_table_commitment = self.stake_tables_set_leaf_proof.leaf.0 .0;
        let time_in_proof = self.stake_tables_set_leaf_proof.leaf.0 .2;
        // 0. check public input matched proof data
        // 0.i) stake table proof leaf should contain correct commitment, total staked, and time.
        //   Only time needs to be checked against claimed reward's time,
        //   Commitment in proof is used to check stake amount, and the total stake is returned for caller use.
        if claimed_reward.time != time_in_proof {
            return Err(ValidationError::BadCollectedRewardProof {});
        }

        // 0.ii) staking key must be checked against claimed reward's staking key
        let (staking_key_in_proof, key_staked_amount) = self
            .stake_amount_proof
            .get_leaf()
            .ok_or(ValidationError::BadCollectedRewardProof {})?;
        if staking_key_in_proof != claimed_reward.staking_key {
            return Err(ValidationError::BadCollectedRewardProof {});
        }

        // 1. Check reward hasn't been collected, retrieve merkle root of collected reward set that checked
        let root = {
            let recently_collected_rewards =
                validator_state.collected_rewards.recent_collected_rewards();
            validator_state
                .collected_rewards
                .check_uncollected_rewards(
                    &recently_collected_rewards,
                    &self.uncollected_reward_proof,
                    claimed_reward.clone(),
                )?
        };

        // 2. Validate stake table commitments inclusion proof
        {
            let mut found = false;
            for root_value in once(
                validator_state
                    .historical_stake_tables_commitment
                    .root_value,
            )
            .chain(
                validator_state
                    .past_historial_stake_table_merkle_roots
                    .0
                    .iter()
                    .copied(),
            ) {
                if crate::merkle_tree::MerkleTree::check_proof(
                    root_value,
                    self.leaf_proof_pos,
                    &self.stake_tables_set_leaf_proof,
                )
                .is_ok()
                {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(ValidationError::BadStakeTableCommitmentsProof {});
            }
        }

        // 3. Check stake amount proof
        {
            let (option_value, _derived_stake_amount_root) = self
                .stake_amount_proof
                .check(
                    claimed_reward.staking_key,
                    stake_table_commitment.0, // this is stake table commitment in stake table set inclusion proof
                )
                .unwrap(); // safe unwrap, check never returns None
            option_value.ok_or(ValidationError::BadStakeTableProof {})?;
        }

        Ok((root, key_staked_amount))
    }

    /// retrieves proof that reward hasn't been collected
    pub fn get_uncollected_reward_proof(&self) -> CollectedRewardsProof {
        self.uncollected_reward_proof.clone()
    }

    /// returns total staked amount from stake table commitment proof
    pub fn total_stake(&self) -> Amount {
        self.stake_tables_set_leaf_proof.leaf.0 .1
    }
}

/// Reward Transaction Errors.
#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(visibility(pub(crate)))]
pub enum RewardError {
    /// An invalid view number
    InvalidViewNumber { view_number: ConsensusTime },

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
        view: ConsensusTime,
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

pub mod eligibility {
    use super::*;
    use crate::{
        stake_table::Election,
        state::{amount_to_nonzerou64, VrfSeed},
    };

    /// check whether a staking key is eligible for rewards
    pub fn check_eligibility(
        sortition_parameter: u64,
        vrf_seed: VrfSeed,
        view_number: ConsensusTime,
        stake_amount: Amount,
        total_stake: NonZeroU64,
        proof: &EligibilityWitness,
    ) -> bool {
        let vrf_check = Election::check_sortition_proof(
            proof.staking_key.as_ref(),
            &(),
            &proof.vrf_proof.0,
            total_stake,
            amount_to_nonzerou64(stake_amount),
            NonZeroU64::new(sortition_parameter).unwrap(),
            NonZeroU64::new(proof.num_seats).unwrap(),
            vrf_seed.as_ref(),
            view_number,
        );
        match vrf_check {
            Ok(res) => res,
            _ => false,
        }
    }

    /// Prove that staking key is eligible for reward on view number. Return None if key is not eligible
    pub fn prove_eligibility(
        sortition_parameter: u64,
        vrf_seed: VrfSeed,
        view_number: ConsensusTime,
        private_key: &StakingPrivKey,
        stake_amount: Amount,
        total_stake: NonZeroU64,
    ) -> Option<EligibilityWitness> {
        let vrf_elibigility = Election::get_sortition_proof(
            &private_key.0,
            &(),
            vrf_seed.as_ref(),
            view_number,
            total_stake,
            amount_to_nonzerou64(stake_amount),
            NonZeroU64::new(sortition_parameter).unwrap(),
        );
        match vrf_elibigility {
            Ok((proof, Some(sortition))) => Some(EligibilityWitness {
                staking_key: StakingKey::from_private(private_key),
                vrf_proof: VrfProof(proof),
                time: view_number,
                num_seats: sortition.into(),
            }),
            _ => None,
        }
    }
}

pub type CollectedRewardsSet = KVMerkleTree<CollectedRewardsHash>;
pub type CollectedRewardsDigest = <CollectedRewardsHash as KVTreeHash>::Digest;
pub type CollectedRewardsProof = KVMerkleProof<CollectedRewardsHash>;

/// CollectedRewards proofs, organized by the root hash for which they are valid.
pub type CollectedRewardsProofs = Vec<(
    CollectedRewards,
    CollectedRewardsProof,
    CollectedRewardsDigest,
)>;

/// Sliding window for reward collection
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CollectedRewardsHistory {
    current: CollectedRewardsDigest,
    history: VecDeque<(CollectedRewardsSet, Vec<CollectedRewards>)>,
}

impl Default for CollectedRewardsHistory {
    fn default() -> Self {
        Self {
            current: CollectedRewardsSet::EmptySubtree.hash(),
            history: VecDeque::with_capacity(ValidatorState::HISTORY_SIZE),
        }
    }
}

impl CollectedRewardsHistory {
    pub fn current_root(&self) -> CollectedRewardsDigest {
        self.current
    }

    pub fn recent_collected_rewards(&self) -> HashSet<CollectedRewards> {
        self.history
            .iter()
            .flat_map(|(_, collected_rewards)| collected_rewards)
            .cloned()
            .collect()
    }

    /// Check if a claimed reward has been collected.
    ///
    /// This function succeeds if `proof` is valid relative to some recent collected reward set (less than
    /// [HISTORY_SIZE](ValidatorState::HISTORY_SIZE) blocks old) and proves that `claimed_reward` was not
    /// in the set at that time, and if `claimed_reward` has not been spent since that historical state.
    ///
    /// `recent_collected_rewards` must be the result of calling [Self::recent_collected_rewards]; that is, it
    /// should contain all of the claimed rewards which have been collected during the historical window
    /// represented by this object.
    ///
    /// If successful, it returns the root hash of the collected_reward set for which `proof` is valid.
    ///
    /// # Errors
    ///
    /// Fails if `proof` is not valid relative to any recent collected reward set, if `proof` proves that
    /// `claimed_reward` _was_ in the set at the time `proof` was generated, or if `claimed_reward` has been
    /// collected since `proof` was generated.
    pub fn check_uncollected_rewards(
        &self,
        recent_collected_rewards: &HashSet<CollectedRewards>,
        proof: &CollectedRewardsProof,
        claimed_reward: CollectedRewards,
    ) -> Result<CollectedRewardsDigest, ValidationError> {
        // Make sure the claimed reward has not been spent during the sliding window of historical
        // snapshots. If it hasn't, then it must be unspent as long as `proof` proves it unspent
        // relative to any of our historical snapshots.
        if recent_collected_rewards.contains(&claimed_reward) {
            return Err(ValidationError::RewardAlreadyCollected {
                reward: claimed_reward,
            });
        }

        // Find a historical collected_reward set root hash which validates the proof.
        for root in once(self.current).chain(self.history.iter().map(|(tree, _)| tree.hash())) {
            let (option_value, computed_root) = proof.check(claimed_reward.clone(), root).unwrap();
            if computed_root == root {
                match option_value {
                    None => {
                        return Ok(root);
                    }
                    Some(_) => {
                        return Err(ValidationError::RewardAlreadyCollected {
                            reward: claimed_reward,
                        })
                    }
                }
            }
        }

        // The collected_reward proof didn't check against any of the past root hashes.
        Err(ValidationError::BadCollectedRewardProof {})
    }

    /// Append a block with new collected rewards to the set.
    ///
    /// `inserts` is a list of collected_rewards to insert, in order, along with their proofs and the
    /// historical root hash which their proof should be validated against. Note that inserting
    /// rewards in different orders may yield different [CollectedRewardsHistory]s, so `inserts` must be
    /// given in a canonical order -- the order in which the claimed rewards appear in the block. Each
    /// collected reward and proof in `inserts` should be labeled with the [Hash](CollectedRewardsHash::Digest) that was
    /// returned from [check_uncollected_rewards](Self::check_uncollected_rewards) when validating that proof. In addition,
    /// [append_block](Self::append_block) must not have been called since any of the relevant calls
    /// to [check_uncollected_rewards](Self::check_uncollected_rewards).
    ///
    /// This method uses the historical sparse [KVMerkleTree] snapshots to update each of the given
    /// proofs to a proof relative to the current collected rewards set, constructing a sparse view of the
    /// current set which includes paths to leaves for each of the collected_rewards to be inserted. From
    /// there, the new claimed rewards can be directly inserted into the sparse [KVMerkleTree], which
    /// can then be used to derive a new root hash.
    ///
    /// If the collected rewards proofs are successfully updated, this function may remove the oldest entry
    /// from the history in order to keep the size of the history below
    /// [HISTORY_SIZE](ValidatorState::HISTORY_SIZE).
    ///
    /// If successful, returns updated non-membership proofs for each claimed rewards in `inserts`, in the
    /// form of a sparse representation of a [KVMerkleTree].
    ///
    /// # Errors
    ///
    /// This function fails if any of the proofs in `inserts` are invalid relative to the
    /// corresponding [Hash](CollectedRewardsHash::Digest).
    pub fn append_block(
        &mut self,
        inserts: CollectedRewardsProofs,
    ) -> Result<CollectedRewardsSet, ValidationError> {
        let (snapshot, new_hash, rewards) = self.apply_block(inserts)?;

        // Update the state: append the new historical snapshot, prune an old snapshot if necessary,
        // and update the current hash.
        if self.history.len() >= ValidatorState::HISTORY_SIZE {
            self.history.pop_back();
        }
        self.history.push_front((snapshot.clone(), rewards));
        self.current = new_hash;

        Ok(snapshot)
    }

    /// Update a set of historical collected rewards non-membership proofs.
    ///
    /// `inserts` is a list of new collected rewards along with their proofs and the historical root hash
    /// which their proof should be validated against. [update_proofs](Self::update_proofs) will
    /// compute a sparse [KVMerkleTree] containing non-membership proofs for each collected reward in
    /// `inserts`, updated so that the root hash of each new proof is the latest root hash in
    /// `self`.
    ///
    /// Each collected reward and proof in `inserts` should be labeled with the [Hash](CollectedRewardsHash::Digest) that
    /// was returned from [check_uncollected_rewards](Self::check_uncollected_rewards) when validating that proof. In
    /// addition, [append_block](Self::append_block) must not have been called since any of the
    /// relevant calls to [check_uncollected_rewards](Self::check_uncollected_rewards).
    ///
    /// # Errors
    ///
    /// This function fails if any of the proofs in `inserts` are invalid relative to the
    /// corresponding [Hash](CollectedRewardsHash::Digest).
    pub fn update_proofs(
        &self,
        inserts: CollectedRewardsProofs,
    ) -> Result<CollectedRewardsSet, ValidationError> {
        Ok(self.apply_block(inserts)?.0)
    }

    fn apply_block(
        &self,
        inserts: CollectedRewardsProofs,
    ) -> Result<
        (
            CollectedRewardsSet,
            CollectedRewardsDigest,
            Vec<CollectedRewards>,
        ),
        ValidationError,
    > {
        let collected_rewards = inserts
            .iter()
            .map(|(n, _, _)| n.clone())
            .collect::<Vec<_>>();

        // A map from a historical root hash to the proofs which are to be validated against that
        // hash
        let mut proofs_by_root = HashMap::<CollectedRewardsDigest, Vec<_>>::new();
        for (n, proof, root) in inserts {
            proofs_by_root.entry(root).or_default().push((n, proof));
        }

        // Get a sparse representation of the oldest set in the history. We will use this
        // accumulator to incrementally build up a sparse representation of the current set that
        // includes all of the necessary Merkle paths.
        let mut accum = if let Some((oldest_tree, _)) = self.history.back() {
            oldest_tree.clone()
        } else {
            CollectedRewardsSet::sparse(self.current)
        };

        // For each snapshot in the history, add the paths for each collected reward in the delta to
        // `accum`, add the paths for each collected reward in `inserts` whose proof is relative to this
        // snapshot, and then advance `accum` to the next historical state by inserting the
        // collected rewards from the delta.
        for (tree, delta) in self.history.iter().rev() {
            assert_eq!(accum.hash(), tree.hash());
            // Add Merkle paths for new collected reward whose proofs correspond to this snapshot.
            for (n, proof) in proofs_by_root.remove(&tree.hash()).unwrap_or_default() {
                accum
                    .remember(n, proof)
                    .map_err(|_| ValidationError::BadCollectedRewardProof {})?;
            }
            // Insert collected reward from `delta`, advancing `accum` to the next historical state while
            // updating all of the Merkle paths it currently contains.
            accum
                .multi_insert(
                    delta
                        .iter()
                        .map(|n| (n.clone(), (), tree.lookup(n.clone()).unwrap().1)),
                )
                .unwrap();
        }

        // Finally, add Merkle paths for any collected reward whose proofs were already current.
        for (n, proof) in proofs_by_root.remove(&accum.hash()).unwrap_or_default() {
            accum
                .remember(n, proof)
                .map_err(|_| ValidationError::BadCollectedRewardProof {})?;
        }

        // At this point, `accum` contains Merkle paths for each of the new collected rewards
        // as well as all of the historical collected rewards. We want to do two different things with this
        // tree:
        //  * Insert the new collected rewards to derive the next collected rewards set commitment. We can do this
        //    directly.
        //  * Create a sparse representation that _only_ contains paths for the new collected rewards.
        //    Unfortunately, this is more complicated. We cannot simply `forget` the historical
        //    collected rewards, because the new ones are not actually in the set, which means they
        //    don't necessarily correspond to unique leaves, and therefore forgetting other
        //    collected rewards may inadvertently cause us to forget part of a path corresponding to a new
        //    rewards. Instead, we will create a new sparse representation of the current set by
        //    starting with the current commitment and remembering paths only for the rewards we
        //    care about. We can get the paths from `accum`.
        assert_eq!(accum.hash(), self.current);
        let mut current = CollectedRewardsSet::sparse(self.current);
        for n in &collected_rewards {
            current
                .remember(n.clone(), accum.lookup(n.clone()).unwrap().1)
                .unwrap();
        }

        // Now that we have created a sparse snapshot of the current collected rewards set, we can insert
        // the new ones into `accum` to derive the new commitment.
        for n in &collected_rewards {
            accum.insert(n.clone(), ()).unwrap();
        }

        Ok((current, accum.hash(), collected_rewards))
    }
}

impl Committable for CollectedRewardsHistory {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("Collected Rewards Hist Comm")
            .field("current", self.current)
            .constant_str("history")
            .u64(self.history.len() as u64);
        for (tree, delta) in self.history.iter() {
            ret = ret
                .field("root", tree.hash())
                .var_size_bytes(&crate::util::canonical::serialize(delta).unwrap())
        }
        ret.finalize()
    }
}
