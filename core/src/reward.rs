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
use crate::state::{
    CommitableHash, CommitableHashTag, KVMerkleTree, ValidationError, ValidatorState,
};
use crate::tree_hash::KVTreeHash;
use ark_serialize::*;
use ark_std::rand::{CryptoRng, RngCore};
use commit::Committable;
use core::hash::Hash;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::structs::{
    Amount, AssetDefinition, BlindFactor, FreezeFlag, RecordCommitment, RecordOpening,
};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{HashMap, HashSet, VecDeque};
use std::iter::once;

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
pub struct CollectedRewards(pub (StakingKey, ViewNumber));

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
        uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
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
            uncollected_reward_proof,
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

    pub fn staking_key(&self) -> StakingKey {
        self.body.vrf_witness.staking_key.clone()
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
        uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
        vrf_proof: VrfProof,
    ) -> Result<(Self, RewardNoteProofs), RewardError> {
        let reward_amount = compute_reward_amount(validator_state, block_height, stake_amount);
        let blind_factor = BlindFactor::rand(rng);
        let rewards_proofs = RewardNoteProofs::generate(
            validator_state,
            stake_amount_proof,
            uncollected_reward_proof,
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
        stake_amount_proof: KVMerkleProof<StakeTableHash>,
        uncollected_reward_proof: KVMerkleProof<CollectedRewardsHash>,
    ) -> Result<Self, RewardError> {
        let stake_table_commitment_leaf_proof =
            Self::get_stake_commitment_total_stake_and_proof(validator_state)?;
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
