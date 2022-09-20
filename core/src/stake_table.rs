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

use crate::state::{CommitableHash, CommitableHashTag};
use crate::tree_hash::KVTreeHash;
use crate::util::canonical;
use crate::{PrivKey, PubKey};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use espresso_macros::*;
use hotshot_types::traits::signature_key::{EncodedSignature, SignatureKey};
use jf_cap::structs::Amount;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

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

/// PubKey used for stake table key
#[tagged_blob("STAKING_KEY_SIGNATURE")]
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct StakingKeySignature(pub(crate) EncodedSignature);

impl StakingKey {
    #[cfg(test)]
    fn random_for_test(_rng: &mut rand_chacha::ChaChaRng) -> Self {
        StakingKey(PubKey::from_private(&PrivKey::generate()))
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
pub struct ViewNumber(pub(crate) u64);

impl commit::Committable for ViewNumber {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("View Number")
            .var_size_bytes(&canonical::serialize(&self.0).unwrap())
            .finalize()
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

/// Identifying tag for a StakeTableCommitment
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct StakeTableCommitmentTag();
impl CommitableHashTag for StakeTableCommitmentTag {
    fn commitment_diversifier() -> &'static str {
        "Stake Table Commitment"
    }
}

/// Stake table commitment type
#[tagged_blob("STAKETABLE")]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, CanonicalDeserialize, CanonicalSerialize)]

pub struct StakeTableCommitment(pub <StakeTableHash as KVTreeHash>::Digest);

impl commit::Committable for StakeTableCommitment {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("Stake Table Commitment")
            .var_size_bytes(&canonical::serialize(&self.0).unwrap())
            .finalize()
    }
}

/// Hash for tree which stores commitment hash of previous rounds' stake tables in (view_number, stake table commitment) kv pairs
pub type StakeTableCommitmentsHash =
    CommitableHash<ViewNumber, StakeTableCommitment, StakeTableCommitmentTag>;

pub struct StakeTableCommitmentsCommitment(pub <StakeTableCommitmentsHash as KVTreeHash>::Digest);
impl commit::Committable for StakeTableCommitmentsCommitment {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("Stake Table Commitments Commitment")
            .var_size_bytes(&canonical::serialize(&self.0).unwrap())
            .finalize()
    }
}
