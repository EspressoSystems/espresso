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
use crate::state::{CommitableHash, CommitableHashTag, ConsensusTime};
use crate::tree_hash::KVTreeHash;
use crate::util::canonical;

use crate::kv_merkle_tree::KVMerkleTree;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use commit::{Commitment, Committable};
use derive_more::{AsRef, From, Into};
use hotshot::traits::election::vrf;
use hotshot_types::traits::signature_key::{EncodedPublicKey, EncodedSignature, SignatureKey};
use jf_cap::structs::Amount;
use jf_primitives::signatures::{BLSSignatureScheme, SignatureScheme as _};
use jf_utils::tagged_blob;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{Digest, Update},
    Sha3_256,
};
use std::collections::VecDeque;

pub use ark_bls12_381::Parameters as VrfParam;

type SignatureScheme = BLSSignatureScheme<VrfParam>;
type VrfPubKey = vrf::VRFPubKey<SignatureScheme>;

#[tagged_blob("STAKINGKEY")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, AsRef)]
pub struct StakingKey(VrfPubKey);

/// Staking Private Key
pub type StakingPrivKey = <VrfPubKey as SignatureKey>::PrivateKey;

impl SignatureKey for StakingKey {
    type PrivateKey = StakingPrivKey;

    fn validate(&self, signature: &EncodedSignature, data: &[u8]) -> bool {
        self.0.validate(signature, data)
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> EncodedSignature {
        <VrfPubKey as SignatureKey>::sign(private_key, data)
    }

    fn from_private(private_key: &Self::PrivateKey) -> Self {
        <VrfPubKey as SignatureKey>::from_private(private_key).into()
    }

    fn to_bytes(&self) -> EncodedPublicKey {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &EncodedPublicKey) -> Option<Self> {
        <VrfPubKey as SignatureKey>::from_bytes(bytes).map(Self::from)
    }

    fn generated_from_seed_indexed(seed: [u8; 32], index: u64) -> (Self, Self::PrivateKey) {
        // Generate a new seed which is deterministic but sensitive to `seed` and `index`:
        // SHA256(seed || index).
        let index_seed = Sha3_256::new_with_prefix(&seed)
            .chain(index.to_le_bytes())
            .finalize()
            .into();
        // Generate a key from the indexed seed.
        let sk = SignatureScheme::key_gen(&(), &mut ChaChaRng::from_seed(index_seed)).unwrap();
        (Self::from_private(&sk), sk)
    }
}

impl From<&StakingPrivKey> for StakingKey {
    fn from(pk: &StakingPrivKey) -> Self {
        Self::from_private(pk)
    }
}

impl StakingKey {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> (Self, StakingPrivKey) {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        Self::generated_from_seed_indexed(seed, 0)
    }
}

/// PubKey used for stake table key
#[tagged_blob("STAKING_KEY_SIGNATURE")]
#[derive(Debug, Clone, PartialEq, Hash, Eq, From, Into, AsRef)]
pub struct StakingKeySignature(pub(crate) EncodedSignature);

// cannot derive CanonicalSerialize because PubKey does not implement it
impl CanonicalSerialize for StakingKey {
    fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        let bytes = self.to_bytes().0;
        CanonicalSerialize::serialize(&bytes, &mut w)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.to_bytes().0.serialized_size()
    }
}
impl CanonicalDeserialize for StakingKey {
    fn deserialize<R>(mut r: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let bytes: Vec<u8> = CanonicalDeserialize::deserialize(&mut r)?;
        Self::from_bytes(&EncodedPublicKey(bytes)).ok_or(SerializationError::InvalidData)
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
    fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        CanonicalSerialize::serialize(&self.0 .0, &mut w)?;
        Ok(())
    }
    fn serialized_size(&self) -> usize {
        self.0 .0.len()
    }
}
impl CanonicalDeserialize for StakingKeySignature {
    fn deserialize<R>(mut r: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let bytes: Vec<u8> = CanonicalDeserialize::deserialize(&mut r)?;
        Ok(Self(EncodedSignature(bytes)))
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
