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

use crate::merkle_tree::{MerkleFrontier, MerkleLeafProof, MerkleTree, NodeValue};
use crate::state::{CommitableHash, CommitableHashTag};
use crate::tree_hash::KVTreeHash;
use crate::util::canonical;
use crate::{PrivKey, PubKey};

use crate::kv_merkle_tree::KVMerkleTree;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use commit::{Commitment, Committable};
use espresso_macros::*;
use hotshot_types::traits::signature_key::{EncodedSignature, SignatureKey};
use jf_cap::structs::Amount;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ops::Deref;

/// PubKey used for stake table key
#[tagged_blob("STAKING_KEY")]
#[ser_test(random(random_for_test))]
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct StakingKey(pub(crate) PubKey);

impl StakingKey {
    /// Derive Staking Public key from Staking Private Key
    pub fn from_priv_key(priv_key: &StakingPrivKey) -> Self {
        Self(PubKey::from_private(&priv_key.0))
    }

    /// Sign a message using StakingPrivate Key
    pub fn sign(priv_key: &StakingPrivKey, msg: &[u8]) -> StakingKeySignature {
        StakingKeySignature(PubKey::sign(&priv_key.0, msg))
    }
}

/// Staking Private Key
pub struct StakingPrivKey(pub(crate) PrivKey);

impl StakingPrivKey {
    pub fn generate() -> Self {
        Self(PrivKey::generate())
    }
}

/// PubKey used for stake table key
#[tagged_blob("STAKING_KEY_SIGNATURE")]
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct StakingKeySignature(pub(crate) EncodedSignature);

impl StakingKey {
    #[cfg(test)]
    fn random_for_test(_rng: &mut rand_chacha::ChaChaRng) -> Self {
        StakingKey(PubKey::from_private(&PrivKey::generate()))
    }

    /// validate a signature
    pub fn validate(&self, signature: &StakingKeySignature, data: &[u8]) -> bool {
        self.0.validate(&signature.0, data)
    }
}

// cannot derive CanonicalSerialize because PubKey does not implement it
impl CanonicalSerialize for StakingKey {
    fn serialize<W: ark_serialize::Write>(
        &self,
        mut w: W,
    ) -> Result<(), ark_serialize::SerializationError> {
        let bytes = bincode::serialize(&self.0.to_bytes()).unwrap();
        CanonicalSerialize::serialize(&bytes, &mut w)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        bincode::serialize(&self.0.to_bytes()).unwrap().len()
    }
}
impl CanonicalDeserialize for StakingKey {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let bytes: Vec<u8> = CanonicalDeserialize::deserialize(&mut r)?;
        let pubkey = bincode::deserialize(&bytes).unwrap();
        Ok(Self(PubKey::from_bytes(&pubkey).unwrap()))
    }
}

impl commit::Committable for StakingKey {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("Staking Key")
            .var_size_bytes(&canonical::serialize(self).unwrap())
            .finalize()
    }
}

// cannot derive CanonicalSerialize because PubKey does not implement it
impl CanonicalSerialize for StakingKeySignature {
    fn serialize<W: ark_serialize::Write>(
        &self,
        mut w: W,
    ) -> Result<(), ark_serialize::SerializationError> {
        CanonicalSerialize::serialize(&self.0 .0, &mut w)?;
        Ok(())
    }
    fn serialized_size(&self) -> usize {
        self.0 .0.len()
    }
}
impl CanonicalDeserialize for StakingKeySignature {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let bytes: Vec<u8> = CanonicalDeserialize::deserialize(&mut r)?;
        Ok(Self(EncodedSignature(bytes)))
    }
}

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
pub struct ConsensusTime(pub(crate) u64);

impl From<hotshot_types::data::ViewNumber> for ConsensusTime {
    fn from(number: hotshot_types::data::ViewNumber) -> Self {
        ConsensusTime(*number.deref())
    }
}

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

/// Stake table commitment type
#[tagged_blob("STAKETABLE")]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, CanonicalDeserialize, CanonicalSerialize)]
pub struct StakeTableCommitment(pub <StakeTableHash as KVTreeHash>::Digest);

impl Committable for StakeTableCommitment {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("Stake Table Commitment")
            .var_size_bytes(&canonical::serialize(&self.0).unwrap())
            .finalize()
    }
}

/// KeyValue Merkle tree alias for Stake Table
pub type StakeTableMap = KVMerkleTree<StakeTableHash>;

/// Alias for Merkle Tree of set of historical Stake tables, holding commitment stake table, its the total staked amount, and the time at which it was valid.
pub type StakeTableSetMT = MerkleTree<(StakeTableCommitment, Amount, ConsensusTime)>;

/// Alias Merkle Frontier for historical stake tables
pub type StakeTableSetFrontier = MerkleFrontier<(StakeTableCommitment, Amount, ConsensusTime)>;

/// Alias for commitment to historical stake tables set
pub type StakeTableSetCommitment = crate::merkle_tree::MerkleCommitment;

/// Committable Wrapper around commitment to historical stable tables set
#[derive(Clone, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommittableStakeTableSetCommitment(pub(crate) StakeTableSetCommitment);

impl Committable for CommittableStakeTableSetCommitment {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("StakeTableCommitmentsCommitment")
            .var_size_bytes(&canonical::serialize(self).unwrap())
            .finalize()
    }
}

/// Committable Wrapper around stake table set frontier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittableStakeTableSetFrontier(pub StakeTableSetFrontier);

impl Committable for CommittableStakeTableSetFrontier {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("Stake Table Commitments Frontier");
        match &self.0 {
            MerkleFrontier::Empty { height } => {
                ret = ret.constant_str("empty height").u64(*height as u64);
            }
            MerkleFrontier::Proof(MerkleLeafProof { leaf, path }) => {
                ret = ret
                    .constant_str("leaf")
                    .var_size_bytes(&canonical::serialize(&leaf.0).unwrap())
                    .constant_str("path");
                for step in path.nodes.iter() {
                    ret = ret.var_size_bytes(&canonical::serialize(step).unwrap())
                }
            }
        }
        ret.finalize()
    }
}

/// Sliding window Stake Table checks
///
/// We keep a fixed number of recent Merkle root hashes here to allow
/// validation of transactions built against recent but not most
/// recent ledger state commitments.
///
/// The Merkle root hash that a transaction was built against is
/// listed in the transaction, so that validators can compare it with
/// the current root hash. Since the Ctake Table Commitment Merkle tree is append
/// only, a proof that a record is included remains valid for any
/// state after the one for which the proof was
/// constructed. Therefore, validators only need to check that the
/// transaction was built against some past Merkle root. By
/// remembering a fixed number of recent Merkle roots, validators can
/// validate slightly old transactions while maintaining constant
/// space requirements for validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeTableSetHistory(pub VecDeque<NodeValue>);

impl Committable for StakeTableSetHistory {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("STC Hist Comm")
            .constant_str("roots")
            .u64(self.0.len() as u64);
        for n in self.0.iter() {
            ret = ret.var_size_bytes(&crate::util::canonical::serialize(n).unwrap())
        }
        ret.finalize()
    }
}
