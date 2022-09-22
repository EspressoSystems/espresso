#![deny(warnings)]
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

use espresso_macros::*;
use jf_cap::structs::{Amount, ReceiverMemo};
use jf_cap::Signature;

pub use crate::full_persistence::FullPersistence;
pub use crate::kv_merkle_tree::*;
pub use crate::lw_persistence::LWPersistence;
use crate::reward::{CollectRewardNote, RewardNoteProofs};
pub use crate::set_merkle_tree::*;
pub use crate::tree_hash::committable_hash::*;
pub use crate::tree_hash::*;
pub use crate::util::canonical;
pub use crate::{PrivKey, PubKey};

use crate::genesis::GenesisNote;
use crate::reward::CollectedRewardsHash;
use crate::stake_table::{StakeTableCommitment, StakeTableHash};
use crate::universal_params::{MERKLE_HEIGHT, VERIF_CRS};
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use canonical::deserialize_canonical_bytes;
use canonical::CanonicalBytes;
use commit::{Commitment, Committable};
use core::fmt::Debug;
use hotshot::{
    data::{BlockHash, LeafHash, TransactionHash},
    traits::{BlockContents, State, Transaction as TransactionTrait},
    H_256,
};
use jf_cap::{
    errors::TxnApiError, structs::Nullifier, txn_batch_verify, MerkleCommitment, MerkleFrontier,
    MerkleLeafProof, MerkleTree, NodeValue, TransactionNote,
};
use jf_primitives::merkle_tree::FilledMTBuilder;
use jf_utils::tagged_blob;
use key_set::VerifierKeySet;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::iter::once;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A transaction tht can be either a CAP transaction or a collect reward transaction
pub enum EspressoTransaction {
    Genesis(GenesisNote),
    CAP(TransactionNote),
    Reward(Box<CollectRewardNote>),
}

impl CanonicalSerialize for EspressoTransaction {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            Self::CAP(txn) => {
                let flag = 0;
                writer.write_all(&[flag])?;
                <TransactionNote as CanonicalSerialize>::serialize(txn, &mut writer)
            }
            Self::Reward(reward_note) => {
                let flag = 1;
                writer.write_all(&[flag])?;
                <CollectRewardNote as CanonicalSerialize>::serialize(reward_note, &mut writer)
            }
            Self::Genesis(genesis_note) => {
                let flag = 2;
                writer.write_all(&[flag])?;
                <GenesisNote as CanonicalSerialize>::serialize(genesis_note, &mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        match self {
            Self::CAP(txn) => txn.serialized_size() + 1,
            Self::Reward(reward) => reward.serialized_size() + 1,
            Self::Genesis(genesis) => genesis.serialized_size() + 1,
        }
    }
}

impl CanonicalDeserialize for EspressoTransaction {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(Self::CAP(
                <TransactionNote as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            1 => Ok(Self::Reward(Box::new(
                <CollectRewardNote as CanonicalDeserialize>::deserialize(&mut r)?,
            ))),
            2 => Ok(Self::Genesis(
                <GenesisNote as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

#[tagged_blob("EspressoTxnAuxProofs")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EspressoTxnHelperProofs {
    Genesis,
    CAP(Vec<SetMerkleProof>),
    Reward(Box<RewardNoteProofs>),
}

impl CanonicalSerialize for EspressoTxnHelperProofs {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            Self::CAP(nulls_pfs) => {
                let flag = 0;
                writer.write_all(&[flag])?;
                <Vec<SetMerkleProof> as CanonicalSerialize>::serialize(nulls_pfs, &mut writer)
            }
            Self::Reward(reward_proofs) => {
                let flag = 1;
                writer.write_all(&[flag])?;
                <RewardNoteProofs as CanonicalSerialize>::serialize(reward_proofs, &mut writer)
            }
            Self::Genesis => {
                writer.write_all(&[2])?;
                Ok(())
            }
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match &self {
            Self::CAP(merkle_proofs) => merkle_proofs.serialized_size(),
            Self::Reward(reward_proofs) => reward_proofs.serialized_size(),
            Self::Genesis => 0,
        }
    }
}

impl CanonicalDeserialize for EspressoTxnHelperProofs {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(Self::CAP(
                <Vec<SetMerkleProof> as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            1 => Ok(Self::Reward(Box::new(
                <RewardNoteProofs as CanonicalDeserialize>::deserialize(&mut r)?,
            ))),
            2 => Ok(Self::Genesis),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

/// A transaction with nullifier non-inclusion proofs
///
/// Validation involves checking proofs that unspent records are unspent.
/// The proofs are large and only needed during validation, so we don't
/// carry them everywhere. The association between records in the transaction
/// note and the proofs is based on parallel arrays; the first input record
/// corresponds to the first proof, and so on.
///
/// A proof that a record is unspent is a Merkle path relative to the
/// latest nullifier set root hash. Informally, the proof says, if
/// this record were spent, there would be a non-empty node 'here',
/// but this path shows there isn't. The leaf of the path has a key
/// equal to the hash of the record's nullifier and an empty value,
/// which demonstrates that the unspent record is not in the nullifier
/// set rooted at the path's root hash.
#[derive(
    Debug,
    Clone,
    CanonicalSerialize,
    CanonicalDeserialize,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ElaboratedTransaction {
    pub txn: EspressoTransaction,
    pub proofs: EspressoTxnHelperProofs,
    pub memos: Option<(Vec<ReceiverMemo>, Signature)>,
}

impl TransactionTrait<H_256> for ElaboratedTransaction {}

/// A collection of transactions
///
/// A Block is the collection of transactions to be validated. Usually,
/// the entire block will be committed to the ledger or rejected, though
/// it is possible to drop individual invalid transactions.
#[ser_test]
#[derive(
    Default,
    Debug,
    Clone,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct Block(pub Vec<EspressoTransaction>);

/// A block of transactions with proofs
///
/// The proofs demonstrate that the nullifiers for the transaction's
/// input records were not present in the nullifier set when the
/// transaction was built. When a nullifier is present in the set, it
/// indicates that the corresponding asset record was spent, and thus
/// "nullified". Only the owner or freezer of a record has the secret
/// information to create a nullifier for the record, but validators
/// can check nullifiers are not already present in the ledger without
/// the secret information.
#[ser_test]
#[derive(
    Default,
    Debug,
    Clone,
    CanonicalSerialize,
    CanonicalDeserialize,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ElaboratedBlock {
    pub block: Block,
    pub proofs: Vec<EspressoTxnHelperProofs>,
    pub memos: Vec<Option<(Vec<ReceiverMemo>, Signature)>>,
}

impl ElaboratedBlock {
    pub fn genesis(txn: GenesisNote) -> Self {
        Self {
            block: Block(vec![EspressoTransaction::Genesis(txn)]),
            proofs: vec![EspressoTxnHelperProofs::Genesis],
            memos: vec![None],
        }
    }
}

impl Committable for ElaboratedBlock {
    /// Get a commitment to an elaborated block.
    //
    // The Committable trait allows us to designate the information to
    // extract from a structure to hash into a cryptographic commitment.
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("ElaboratedBlock")
            .field("Block contents", self.block.commit())
            .var_size_field("Block proofs", &canonical::serialize(&self.proofs).unwrap())
            .var_size_field("Block memos", &canonical::serialize(&self.memos).unwrap())
            .finalize()
    }
}

impl Committable for ElaboratedTransaction {
    /// Get a commitment to an elaborated transaction.
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("ElaboratedTransaction")
            .field("Txn contents", self.txn.commit())
            .var_size_field("Txn proofs", &canonical::serialize(&self.proofs).unwrap())
            .var_size_field("Txn memos", &canonical::serialize(&self.memos).unwrap())
            .finalize()
    }
}

/// Allow an elaborated block to be used by the [HotShot](https://hotshot.docs.espressosys.com/hotshot/) consensus protocol.
impl BlockContents<H_256> for ElaboratedBlock {
    type Transaction = ElaboratedTransaction;
    type Error = ValidationError;

    /// Add an elaborated transaction to a block.
    ///
    /// Preventing double spending is essential. When adding a transaction
    /// to a block, an error is generated if a duplicate nullifier is
    /// used. This is an internal consistency check, not a check
    /// against nullifiers already committed to the ledger.
    ///
    /// # Errors
    /// - [ValidationError::ConflictingNullifiers]
    fn add_transaction_raw(&self, txn: &ElaboratedTransaction) -> Result<Self, ValidationError> {
        let mut ret = self.clone();

        let mut nulls = self
            .block
            .0
            .iter()
            .flat_map(|x| x.input_nullifiers().into_iter())
            .collect::<HashSet<_>>();
        for n in txn.txn.input_nullifiers().iter() {
            if nulls.contains(n) {
                return Err(ValidationError::ConflictingNullifiers {});
            }
            nulls.insert(*n);
        }

        ret.block.0.push(txn.txn.clone());
        ret.proofs.push(txn.proofs.clone());
        ret.memos.push(txn.memos.clone());

        Ok(ret)
    }

    /// A cryptographic hash of an elaborated block
    fn hash(&self) -> BlockHash<H_256> {
        BlockHash::<H_256>::from_array(self.commit().try_into().unwrap())
    }

    /// A cryptographic hash of the given bytes
    fn hash_leaf(bytes: &[u8]) -> LeafHash<H_256> {
        // TODO: fix this hack, it is specifically working around the
        // misuse-preventing `T: Committable` on `RawCommitmentBuilder`
        let ret = commit::RawCommitmentBuilder::<Block>::new("HotShot bytes")
            .var_size_bytes(bytes)
            .finalize();
        LeafHash::<H_256>::from_array(ret.try_into().unwrap())
    }

    /// A cryptographic hash of an elaborated transaction
    fn hash_transaction(txn: &ElaboratedTransaction) -> TransactionHash<H_256> {
        TransactionHash::<H_256>::from_array(txn.commit().try_into().unwrap())
    }
}

/// Validation errors.
#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(visibility(pub(crate)))]
pub enum ValidationError {
    /// A record was already spent.
    NullifierAlreadyExists {
        nullifier: Nullifier,
    },
    /// An invalid nullifier proof.
    BadNullifierProof {},
    MissingNullifierProof {},
    /// The transaction being added to a block contains a nullifier
    /// already present in another transaction in the block.
    ConflictingNullifiers {},
    /// A generic failure.
    Failed {},
    /// An incorrect Merkle path length.
    BadMerkleLength {},
    /// An invalid Merkle leaf.
    BadMerkleLeaf {},
    /// An incorrect Merkle root.
    BadMerkleRoot {},
    /// An invalid Merkle path.
    BadMerklePath {},
    /// An error from the Jellyfish library
    ///
    /// *Note*: This is used to wrap [TxnApiError] because it cannot
    /// be serialized. TxnApiError cannot be serialized because it
    /// depends on many foreign error types which do not implement the
    /// Serialize trait. Instead, if we have to serialize this
    /// variant, we will serialize Ok(err) to Err(format(err)), and
    /// when we deserialize we will at least preserve the variant
    /// CryptoError and a String representation of the underlying
    /// error.
    CryptoError {
        #[serde(with = "ser_display")]
        err: Result<TxnApiError, String>,
    },
    /// The transfer transaction has an unsupported number of inputs or outputs.
    ///
    /// *Note*: For transactions with fewer inputs or outputs than
    /// supported, the transaction should be padded with dummy
    /// transactions. If transactions with a greater number of inputs
    /// or outputs are required, then the universal parameter set for
    /// the ledger must be updated.
    UnsupportedTransferSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    /// The freeze transaction has an unsupported number of inputs or outputs.
    ///
    /// *Note*: For transactions with fewer inputs or outputs than
    /// supported, the transaction should be padded with dummy
    /// transactions. If transactions with a greater number of inputs
    /// or outputs are required, then the universal parameter set for
    /// the ledger must be updated.
    UnsupportedFreezeSize {
        num_inputs: usize,
    },

    /// Block transaction order doesn't match helper proofs
    InconsistentHelperProofs,

    /// A genesis transaction was included in a non-genesis block
    UnexpectedGenesis,
}

pub(crate) mod ser_display {
    use serde::de::{Deserialize, Deserializer};
    use serde::ser::{Serialize, Serializer};
    use std::fmt::Display;

    pub fn serialize<S: Serializer, T: Display>(
        v: &Result<T, String>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let string = match v {
            Ok(v) => format!("{}", v),
            Err(string) => string.clone(),
        };
        Serialize::serialize(&string, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(d: D) -> Result<Result<T, String>, D::Error> {
        Ok(Err(Deserialize::deserialize(d)?))
    }
}

/// Adapter because [TxnApiError] doesn't implement Clone
impl Clone for ValidationError {
    /// Clone all errors except CryptoError which gets mapped to a
    /// generic Failed error
    fn clone(&self) -> Self {
        use ValidationError::*;
        match self {
            NullifierAlreadyExists { nullifier } => NullifierAlreadyExists {
                nullifier: *nullifier,
            },
            BadNullifierProof {} => BadNullifierProof {},
            MissingNullifierProof {} => MissingNullifierProof {},
            ConflictingNullifiers {} => ConflictingNullifiers {},
            Failed {} => Failed {},
            BadMerkleLength {} => BadMerkleLength {},
            BadMerkleLeaf {} => BadMerkleLeaf {},
            BadMerkleRoot {} => BadMerkleRoot {},
            BadMerklePath {} => BadMerklePath {},
            CryptoError { .. } => Failed {},
            UnsupportedTransferSize {
                num_inputs,
                num_outputs,
            } => UnsupportedTransferSize {
                num_inputs: *num_inputs,
                num_outputs: *num_outputs,
            },
            UnsupportedFreezeSize { num_inputs } => UnsupportedFreezeSize {
                num_inputs: *num_inputs,
            },
            InconsistentHelperProofs => InconsistentHelperProofs,
            UnexpectedGenesis => UnexpectedGenesis,
        }
    }
}

/// A cryptographic commitment to a block
#[ser_test(arbitrary)]
#[tagged_blob("BLOCK")]
#[derive(
    Arbitrary, Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct BlockCommitment(pub commit::Commitment<Block>);

// Implements From<CanonicalBytes>. See serialize.rs in Jellyfish.
deserialize_canonical_bytes!(BlockCommitment);

impl Committable for Block {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("Block Comm")
            .array_field(
                "txns",
                &self.0.iter().map(|x| x.commit()).collect::<Vec<_>>(),
            )
            .finalize()
    }
}

/// A cryptographic commitment to a transaction
#[ser_test(arbitrary)]
#[tagged_blob("TXN")]
#[derive(
    Arbitrary, Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct TransactionCommitment(pub commit::Commitment<EspressoTransaction>);

// Implements From<CanonicalBytes>. See serialize.rs in Jellyfish.
deserialize_canonical_bytes!(TransactionCommitment);

/// Sliding window for transaction freshness
///
/// We keep a fixed number of recent Merkle root hashes here to allow
/// validation of transactions built against recent but not most
/// recent ledger state commitments.
///
/// The Merkle root hash that a transaction was built against is
/// listed in the transaction, so that validators can compare it with
/// the current root hash. Since the records Merkle tree is append
/// only, a proof that a record is included remains valid for any
/// state after the one for which the proof was
/// constructed. Therefore, validators only need to check that the
/// transaction was built against some past Merkle root. By
/// remembering a fixed number of recent Merkle roots, validators can
/// validate slightly old transactions while maintaining constant
/// space requirements for validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordMerkleHistory(pub VecDeque<NodeValue>);

impl Committable for RecordMerkleHistory {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("Hist Comm")
            .constant_str("roots")
            .u64(self.0.len() as u64);
        for n in self.0.iter() {
            ret = ret.var_size_bytes(&canonical::serialize(n).unwrap())
        }
        ret.finalize()
    }
}

/// A type wrapper for [MerkleCommitment]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordMerkleCommitment(pub MerkleCommitment);

impl Committable for RecordMerkleCommitment {
    fn commit(&self) -> commit::Commitment<Self> {
        commit::RawCommitmentBuilder::new("RMT Comm")
            .constant_str("height")
            .u64(self.0.height as u64)
            .constant_str("num_leaves")
            .u64(self.0.num_leaves)
            .constant_str("root_value")
            .var_size_bytes(&canonical::serialize(&self.0.root_value).unwrap())
            .finalize()
    }
}

/// Jellyfish [MerkleFrontier] enables efficient batch updates
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordMerkleFrontier(pub MerkleFrontier);

impl Committable for RecordMerkleFrontier {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("RMFrontier");
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

/// Sliding window for transaction freshness
///
/// We keep a fixed number of recent nullifier root hashes and recently added nullifiers to allow
/// validation of transactions built against recent but not most recent nullifier set commitments.
///
/// [NullifierHistory] contains the current nullifier set root hash, as well as the previous
/// [HISTORY_SIZE](ValidatorState::HISTORY_SIZE) root hashes and the nullifiers that were appended
/// to each root hash. To check a nullifier non-membership proof, we can walk backwards in time
/// starting from the most recent root hash until we find a root hash against which the proof is
/// valid. We must also check that the nullifier is not in the set of nullifiers which have been
/// added since the proof was valid. To do this, we check that the nullifier is not in any of the
/// deltas associated with each historical snapshot, which we can check efficiently using
/// [recent_nullifiers](Self::recent_nullifiers).
///
/// [NullifierHistory] also includes, for each historical root hash, nullifier non-membership proofs
/// for each of the nullifiers which were appended to that root hash. This makes it possible to
/// iteratively update proofs which were generated against a historical root hash to work with the
/// most recent root hash. These non-membership proofs are saved in the form of sparse
/// representations of a [SetMerkleTree] at each point in history; thus, the historical root hashes
/// and non-membership proofs are stored together using the [SetMerkleTree] data structure.
///
/// The ability to update historical proofs also means we can insert new nullifiers into the latest
/// nullifier set given only historical proofs. The method [append_block](Self::append_block) does
/// this in batch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NullifierHistory {
    current: set_hash::Hash,
    history: VecDeque<(SetMerkleTree, Vec<Nullifier>)>,
}

impl Default for NullifierHistory {
    fn default() -> Self {
        Self {
            current: SetMerkleTree::default().hash(),
            history: VecDeque::with_capacity(ValidatorState::HISTORY_SIZE),
        }
    }
}

impl NullifierHistory {
    pub fn current_root(&self) -> set_hash::Hash {
        self.current
    }

    pub fn recent_nullifiers(&self) -> HashSet<Nullifier> {
        self.history
            .iter()
            .flat_map(|(_, nulls)| nulls)
            .cloned()
            .collect()
    }

    /// Check if a nullifier has been spent.
    ///
    /// This function succeeds if `proof` is valid relative to some recent nullifier set (less than
    /// [HISTORY_SIZE](ValidatorState::HISTORY_SIZE) blocks old) and proves that `nullifier` was not
    /// in the set at that time, and if `nullifier` has not been spent since that historical state.
    ///
    /// `recent_nullifiers` must be the result of calling [Self::recent_nullifiers]; that is, it
    /// should contain all of the nullifiers which have been spent during the historical window
    /// represented by this object.
    ///
    /// If successful, it returns the root hash of the nullifier set for which `proof` is valid.
    ///
    /// # Errors
    ///
    /// Fails if `proof` is not valid relative to any recent nullifier set, if `proof` proves that
    /// `nullifier` _was_ in the set at the time `proof` was generated, or if `nullifier` has been
    /// spent since `proof` was generated.
    pub fn check_unspent(
        &self,
        recent_nullifiers: &HashSet<Nullifier>,
        proof: &SetMerkleProof,
        nullifier: Nullifier,
    ) -> Result<set_hash::Hash, ValidationError> {
        // Make sure the nullifier has not been spent during the sliding window of historical
        // snapshots. If it hasn't, then it must be unspent as long as `proof` proves it unspent
        // relative to any of our historical snapshots.
        if recent_nullifiers.contains(&nullifier) {
            return Err(ValidationError::NullifierAlreadyExists { nullifier });
        }

        // Find a historical nullifier set root hash which validates the proof.
        for root in once(self.current).chain(self.history.iter().map(|(tree, _)| tree.hash())) {
            if let Ok(res) = proof.check(nullifier, &root) {
                return if res {
                    Err(ValidationError::NullifierAlreadyExists { nullifier })
                } else {
                    Ok(root)
                };
            }
        }

        // The nullifier proof didn't check against any of the past root hashes.
        Err(ValidationError::BadNullifierProof {})
    }

    /// Append a block of new nullifiers to the set.
    ///
    /// `inserts` is a list of nullifiers to insert, in order, along with their proofs and the
    /// historical root hash which their proof should be validated against. Note that inserting
    /// nullifiers in different orders may yield different [NullifierHistory]s, so `inserts` must be
    /// given in a canonical order -- the order in which the nullifiers appear in the block. Each
    /// nullifier and proof in `inserts` should be labeled with the [Hash](set_hash::Hash) that was
    /// returned from [check_unspent](Self::check_unspent) when validating that proof. In addition,
    /// [append_block](Self::append_block) must not have been called since any of the relevant calls
    /// to [check_unspent](Self::check_unspent).
    ///
    /// This method uses the historical sparse [SetMerkleTree] snapshots to update each of the given
    /// proofs to a proof relative to the current nullifiers set, constructing a sparse view of the
    /// current set which includes paths to leaves for each of the nullifiers to be inserted. From
    /// there, the new nullifiers can be directly inserted into the sparse [SetMerkleTree], which
    /// can then be used to derive a new root hash.
    ///
    /// If the nullifier proofs are successfully updated, this function may remove the oldest entry
    /// from the history in order to keep the size of the history below
    /// [HISTORY_SIZE](ValidatorState::HISTORY_SIZE).
    ///
    /// If successful, returns updated non-membership proofs for each nullifier in `inserts`, in the
    /// form of a sparse representation of a [SetMerkleTree].
    ///
    /// # Errors
    ///
    /// This function fails if any of the proofs in `inserts` are invalid relative to the
    /// corresponding [Hash](set_hash::Hash).
    pub fn append_block(
        &mut self,
        inserts: NullifierProofs,
    ) -> Result<SetMerkleTree, ValidationError> {
        let (snapshot, new_hash, nulls) = self.apply_block(inserts)?;

        // Update the state: append the new historical snapshot, prune an old snapshot if necessary,
        // and update the current hash.
        if self.history.len() >= ValidatorState::HISTORY_SIZE {
            self.history.pop_back();
        }
        self.history.push_front((snapshot.clone(), nulls));
        self.current = new_hash;

        Ok(snapshot)
    }

    /// Update a set of historical nullifier non-membership proofs.
    ///
    /// `inserts` is a list of new nullifiers along with their proofs and the historical root hash
    /// which their proof should be validated against. [update_proofs](Self::update_proofs) will
    /// compute a sparse [SetMerkleTree] containing non-membership proofs for each nullifier in
    /// `inserts`, updated so that the root hash of each new proof is the latest root hash in
    /// `self`.
    ///
    /// Each nullifier and proof in `inserts` should be labeled with the [Hash](set_hash::Hash) that
    /// was returned from [check_unspent](Self::check_unspent) when validating that proof. In
    /// addition, [append_block](Self::append_block) must not have been called since any of the
    /// relevant calls to [check_unspent](Self::check_unspent).
    ///
    /// # Errors
    ///
    /// This function fails if any of the proofs in `inserts` are invalid relative to the
    /// corresponding [Hash](set_hash::Hash).
    pub fn update_proofs(
        &self,
        inserts: NullifierProofs,
    ) -> Result<SetMerkleTree, ValidationError> {
        Ok(self.apply_block(inserts)?.0)
    }

    fn apply_block(
        &self,
        inserts: NullifierProofs,
    ) -> Result<(SetMerkleTree, set_hash::Hash, Vec<Nullifier>), ValidationError> {
        let nulls = inserts.iter().map(|(n, _, _)| *n).collect::<Vec<_>>();

        // A map from a historical root hash to the proofs which are to be validated against that
        // hash
        let mut proofs_by_root = HashMap::<set_hash::Hash, Vec<_>>::new();
        for (n, proof, root) in inserts {
            proofs_by_root.entry(root).or_default().push((n, proof));
        }

        // Get a sparse representation of the oldest set in the history. We will use this
        // accumulator to incrementally build up a sparse representation of the current set that
        // includes all of the necessary Merkle paths.
        let mut accum = if let Some((oldest_tree, _)) = self.history.back() {
            oldest_tree.clone()
        } else {
            SetMerkleTree::sparse(self.current)
        };

        // For each snapshot in the history, add the paths for each nullifier in the delta to
        // `accum`, add the paths for each nullifier in `inserts` whose proof is relative to this
        // snapshot, and then advance `accum` to the next historical state by inserting the
        // nullifiers from the delta.
        for (tree, delta) in self.history.iter().rev() {
            assert_eq!(accum.hash(), tree.hash());
            // Add Merkle paths for new nullifiers whose proofs correspond to this snapshot.
            for (n, proof) in proofs_by_root.remove(&tree.hash()).unwrap_or_default() {
                accum
                    .remember(n, proof)
                    .map_err(|_| ValidationError::BadNullifierProof {})?;
            }
            // Insert nullifiers from `delta`, advancing `accum` to the next historical state while
            // updating all of the Merkle paths it currently contains.
            accum
                .multi_insert(delta.iter().map(|n| (*n, tree.contains(*n).unwrap().1)))
                .unwrap();
        }

        // Finally, add Merkle paths for any nullifiers whose proofs were already current.
        for (n, proof) in proofs_by_root.remove(&accum.hash()).unwrap_or_default() {
            accum
                .remember(n, proof)
                .map_err(|_| ValidationError::BadNullifierProof {})?;
        }

        // At this point, `accum` contains Merkle paths for each of the new nullifiers in `nulls`
        // as well as all of the historical nullifiers. We want to do two different things with this
        // tree:
        //  * Insert the new nullifiers to derive the next nullifier set commitment. We can do this
        //    directly.
        //  * Create a sparse representation that _only_ contains paths for the new nullifiers.
        //    Unfortunately, this is more complicated. We cannot simply `forget` the historical
        //    nullifiers, because the new nullifiers are not actually in the set, which means they
        //    don't necessarily correspond to unique leaves, and therefore forgetting other
        //    nullifiers may inadvertently cause us to forget part of a path corresponding to a new
        //    nullifier. Instead, we will create a new sparse representation of the current set by
        //    starting with the current commitment and remembering paths only for the nullifiers we
        //    care about. We can get the paths from `accum`.
        assert_eq!(accum.hash(), self.current);
        let mut current = SetMerkleTree::sparse(self.current);
        for n in &nulls {
            current.remember(*n, accum.contains(*n).unwrap().1).unwrap();
        }

        // Now that we have created a sparse snapshot of the current nullifiers set, we can insert
        // the new nullifiers into `accum` to derive the new commitment.
        for n in &nulls {
            accum.insert(*n).unwrap();
        }

        Ok((current, accum.hash(), nulls))
    }
}

impl Committable for NullifierHistory {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut ret = commit::RawCommitmentBuilder::new("Nullifier Hist Comm")
            .field("current", self.current.into())
            .constant_str("history")
            .u64(self.history.len() as u64);
        for (tree, delta) in self.history.iter() {
            ret = ret
                .field("root", tree.hash().into())
                .var_size_bytes(&canonical::serialize(delta).unwrap())
        }
        ret.finalize()
    }
}

/// The ledger state commitment
///
/// Fundamental to a distributed ledger is the notion of a state
/// commitment which provides a succinct fingerprint of the entire
/// history of the ledger and an indication of consensus. All
/// essential ledger information is hashed in a canonical way by all
/// the validators, so that all agree. Any discrepency in the history
/// would produce a disagreement.
pub mod state_comm {
    use super::*;
    use jf_utils::tagged_blob;
    use net::Hash;

    #[ser_test(arbitrary)]
    #[tagged_blob("STATE")]
    #[derive(
        Arbitrary, Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Hash,
    )]
    pub struct LedgerStateCommitment(pub Commitment<LedgerCommitmentOpening>);

    impl From<Commitment<LedgerCommitmentOpening>> for LedgerStateCommitment {
        fn from(x: Commitment<LedgerCommitmentOpening>) -> Self {
            Self(x)
        }
    }

    impl From<LedgerStateCommitment> for Commitment<LedgerCommitmentOpening> {
        fn from(x: LedgerStateCommitment) -> Self {
            x.0
        }
    }

    impl AsRef<[u8]> for LedgerStateCommitment {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl From<LedgerStateCommitment> for Hash {
        fn from(c: LedgerStateCommitment) -> Self {
            Self::from(commit::Commitment::<_>::from(c))
        }
    }

    /// The essential state of the ledger
    ///
    /// Note that many elements of the state are represented
    /// succinctly as cryptographic commitments.
    #[derive(Debug)]
    pub struct LedgerCommitmentOpening {
        pub chain: Commitment<ChainVariables>,
        pub prev_commit_time: u64,
        pub block_height: u64,
        pub prev_state: Option<state_comm::LedgerStateCommitment>,
        pub record_merkle_commitment: Commitment<RecordMerkleCommitment>,
        pub record_merkle_frontier: Commitment<RecordMerkleFrontier>,
        /// We need to include all the cached past record Merkle roots
        /// in the state commitment, even though they are not part of
        /// the current ledger state, because they affect validation:
        /// two validators with different caches will be able to
        /// validate different blocks.
        ///
        /// This requires correct validators to agree on the number of
        /// cached past root hashes, since all the cached hashes are
        /// included in the state commitment and are thus part of the
        /// observable state of the ledger. This prevents heavyweight
        /// validators from caching extra past roots and thereby
        /// making it easier to verify transactions, but because root
        /// hashes are small, it should be possible to find a value of
        /// HISTORY_SIZE which strikes a balance between
        /// small space requirements (so that lightweight validators
        /// can keep up with the cache) and covering enough of history
        /// to make it easy for clients. If this is not possible,
        /// lightweight validators could also store a sparse history,
        /// and when they encounter a root hash that they do not have
        /// cached, they could ask a full validator for a proof that
        /// that hash was once the root of the record Merkle tree.
        pub past_record_merkle_roots: Commitment<RecordMerkleHistory>,
        pub past_nullifiers: Commitment<NullifierHistory>,
        pub prev_block: Commitment<Block>,
    }

    impl Committable for LedgerCommitmentOpening {
        fn commit(&self) -> Commitment<Self> {
            commit::RawCommitmentBuilder::new("Ledger Comm")
                .field("chain", self.chain)
                .u64_field("prev_commit_time", self.prev_commit_time)
                .u64_field("block_height", self.block_height)
                .array_field(
                    "prev_state",
                    &self
                        .prev_state
                        .iter()
                        .cloned()
                        .map(Commitment::<Self>::from)
                        .collect::<Vec<_>>(),
                )
                .field("record_merkle_commitment", self.record_merkle_commitment)
                .field("record_merkle_frontier", self.record_merkle_frontier)
                .field("past_record_merkle_roots", self.past_record_merkle_roots)
                .field("past_nullifiers", self.past_nullifiers)
                .field("prev_block", self.prev_block)
                .finalize()
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationOutputs {
    /// UID for each new record created by this block.
    pub uids: Vec<u64>,
    /// Sparse [SetMerkleTree] containing up-to-date non-membership proofs for every nullifier in
    /// this block, relative to the nullifier set root hash just before applying this block.
    pub nullifier_proofs: SetMerkleTree,
    /// Sparse [MerkleTree] containing membership profos for each new record created by this block,
    /// relative to the record set root hash after applying this block.
    pub record_proofs: MerkleTree,
}

/// Serializable [Arc]
///
/// Ark-serialize doesn't work out of the box for [Arc], even if the underlying type is
/// serializable. This wrapper around [Arc] provides a simple implementation of [ark_serialize]
/// traits that simply delegates to the implementations for `T`.
#[derive(
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    Deserialize,
    Serialize,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
)]
pub struct ArcSer<T>(Arc<T>);

impl<T: CanonicalSerialize> CanonicalSerialize for ArcSer<T> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        (*self.0).serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        (*self.0).serialized_size()
    }
}

impl<T: CanonicalDeserialize> CanonicalDeserialize for ArcSer<T> {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(Self(Arc::new(T::deserialize(reader)?)))
    }
}

/// Global variables for an Espresso blockchain.
#[ser_test(ark(false))]
#[derive(Clone, Debug, Serialize, Deserialize, CanonicalDeserialize, CanonicalSerialize)]
pub struct ChainVariables {
    /// The version of the protocol this chain is currently using.
    ///
    /// The protocol version can be changed by committing an update transaction.
    pub protocol_version: (u16, u16, u16),

    /// A unique identifier for this chain, to prevent cross-chain replay attacks.
    ///
    /// The chain ID is set at genesis and never changes.
    pub chain_id: u16,

    /// Plonk verifier keys.
    pub verif_crs: ArcSer<VerifierKeySet>,
}

impl Default for ChainVariables {
    fn default() -> Self {
        Self::new(0, VERIF_CRS.clone())
    }
}

impl Committable for ChainVariables {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("ChainVariables")
            .u64_field("protocol_version_major", self.protocol_version.0 as u64)
            .u64_field("protocol_version_minor", self.protocol_version.1 as u64)
            .u64_field("protocol_version_patch", self.protocol_version.2 as u64)
            .u64_field("chain_id", self.chain_id as u64)
            .var_size_bytes(&canonical::serialize(&self.verif_crs).unwrap())
            .finalize()
    }
}

impl PartialEq for ChainVariables {
    fn eq(&self, other: &Self) -> bool {
        self.commit() == other.commit()
    }
}

impl Eq for ChainVariables {}

impl Hash for ChainVariables {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.commit(), state)
    }
}

impl ChainVariables {
    pub fn new(chain_id: u16, verif_crs: Arc<VerifierKeySet>) -> Self {
        Self {
            protocol_version: (
                env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            ),
            chain_id,
            verif_crs: verif_crs.into(),
        }
    }
}

/// KeyValue Merkle tree alias for StakeTable
pub type StakeTableMap = KVMerkleTree<StakeTableHash>;

/// Merkle Tree for Stake table commitments merkle tree
pub type StakeTableCommMT = crate::merkle_tree::MerkleTree<(StakeTableCommitment, Amount)>;

/// Merkle Frontier for Stake table commitments
pub type StakeTableCommFrontier =
    crate::merkle_tree::MerkleFrontier<(StakeTableCommitment, Amount)>;

/// Merkle Frontier for Stake table commitments
pub type StakeTableCommCommitment = crate::merkle_tree::MerkleCommitment;

/// The working state of the ledger
///
/// Only the previous state is represented as a commitment. Other
/// values are present in full.
#[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorState {
    pub chain: ChainVariables,
    /// The consensus time at which this state was created.
    ///
    /// "Consensus time" is an opaque notion of time which is meaningful in the consensus layer.
    /// From outside the consensus protocol, it can be treated as a monotonically (but possibly
    /// non-consecutively) increasing counter.
    pub prev_commit_time: u64,
    /// The number of blocks in the chain which led to this state.
    ///
    /// This field can also be used to determine the index of the block which created this state or
    /// the next block to be appended to this state. The 0-based index of a block appended to a
    /// chain of `n` blocks is `n`, so `block_height` is the index of the next block to be appended,
    /// and `block_height - 1` is the index of the previous block, which created this state. (The
    /// default, pre-genesis state has `block_height == 0`, since it was not created by any block.)
    pub block_height: u64,
    pub prev_state: Option<state_comm::LedgerStateCommitment>,
    /// The current record Merkle commitment
    pub record_merkle_commitment: MerkleCommitment,
    /// The current frontier of the record Merkle tree
    pub record_merkle_frontier: MerkleFrontier,
    /// A list of recent record Merkle root hashes for validating slightly out-of-date transactions
    pub past_record_merkle_roots: RecordMerkleHistory,
    /// Nullifiers from recent blocks, which allows validating slightly out-of-date-transactions
    pub past_nullifiers: NullifierHistory,
    pub prev_block: BlockCommitment,
    /// Staking table. For fixed-stake, this will be the same each round
    pub stake_table: StakeTableMap,
    /// Keeps track of previous stake tables and their total stake
    pub stake_table_commitments: StakeTableCommFrontier,
    /// Commitment to stake table commitments set
    pub stake_table_commitments_commitment: StakeTableCommCommitment,
    /// Track already-collected rewards via (staking_key, block number) tuples
    pub collected_rewards: KVMerkleTree<CollectedRewardsHash>,
}

/// Nullifier proofs, organized by the root hash for which they are valid.
pub type NullifierProofs = Vec<(Nullifier, SetMerkleProof, set_hash::Hash)>;

impl Default for ValidatorState {
    fn default() -> Self {
        Self::new(
            ChainVariables::default(),
            MerkleTree::new(MERKLE_HEIGHT).unwrap(),
            StakeTableMap::EmptySubtree,
            StakeTableCommMT::new(MERKLE_HEIGHT).unwrap(),
        )
    }
}

impl ValidatorState {
    /// The number of recent record Merkle tree root hashes the
    /// validator should remember
    ///
    /// Transactions can be validated without resubmitting or regenerating the ZKPs as long as they
    /// were generated using a validator state that is in the last HISTORY_SIZE states.
    pub const HISTORY_SIZE: usize = 10;

    pub fn new(
        chain: ChainVariables,
        record_merkle_frontier: MerkleTree,
        stake_table_map: StakeTableMap,
        stake_table_commitments_mt: StakeTableCommMT,
    ) -> Self {
        Self {
            chain,
            prev_commit_time: 0u64,
            block_height: 0u64,
            prev_state: None,
            record_merkle_commitment: record_merkle_frontier.commitment(),
            record_merkle_frontier: record_merkle_frontier.frontier(),
            past_record_merkle_roots: RecordMerkleHistory(VecDeque::with_capacity(
                Self::HISTORY_SIZE,
            )),
            past_nullifiers: NullifierHistory::default(),
            prev_block: BlockCommitment(Block::default().commit()),
            //KALEY: ask about stake table initialization
            stake_table: stake_table_map,
            stake_table_commitments: stake_table_commitments_mt.frontier(),
            stake_table_commitments_commitment: stake_table_commitments_mt.commitment(),
            collected_rewards: KVMerkleTree::<CollectedRewardsHash>::EmptySubtree,
        }
    }

    /// Cryptographic commitment to the validator state
    pub fn commit(&self) -> state_comm::LedgerStateCommitment {
        let inputs = state_comm::LedgerCommitmentOpening {
            chain: self.chain.commit(),
            prev_commit_time: self.prev_commit_time,
            block_height: self.block_height,
            prev_state: self.prev_state,
            record_merkle_commitment: RecordMerkleCommitment(self.record_merkle_commitment)
                .commit(),
            record_merkle_frontier: RecordMerkleFrontier(self.record_merkle_frontier.clone())
                .commit(),
            past_record_merkle_roots: self.past_record_merkle_roots.commit(),

            past_nullifiers: self.past_nullifiers.commit(),
            prev_block: self.prev_block.0,
        };
        inputs.commit().into()
    }

    pub fn nullifiers_root(&self) -> set_hash::Hash {
        self.past_nullifiers.current_root()
    }

    /// Validate a block of elaborated transactions
    ///
    /// Checks the following
    /// - None of the nullifiers are used more than once
    /// - Keys are available for the numbers of transaction inputs and
    ///   outputs
    /// - The Merkle roots are recent enough
    /// - The zero knowledge proofs in each of the transactions verifies
    ///
    /// If valid, return the input transactions and proofs, otherwise
    /// return a validation error. A future implementation may return
    /// only the valid transactions and proofs.
    ///
    /// # Errors
    /// - [ValidationError::BadMerkleRoot]
    /// - [ValidationError::BadNullifierProof]
    /// - [ValidationError::CryptoError]
    /// - [ValidationError::NullifierAlreadyExists]
    /// - [ValidationError::UnsupportedFreezeSize]
    /// - [ValidationError::UnsupportedTransferSize]
    pub fn validate_block_check(
        &self,
        now: u64,
        txns: Block,
        txns_helper_proofs: Vec<EspressoTxnHelperProofs>,
    ) -> Result<(Block, NullifierProofs), ValidationError> {
        // Check if this is a genesis block. If it is, validation is trivial and we can skip the
        // rest of this. If it is not, then we will reject the block later if it contains any
        // genesis transactions.
        if let Some(EspressoTransaction::Genesis(_)) = txns.0.get(0) {
            if self.prev_commit_time != 0 || txns.0.len() != 1 {
                // A genesis transaction is only allowed in the genesis block, which is a block at
                // height 0 containing only a single genesis transaction.
                return Err(ValidationError::UnexpectedGenesis);
            }
            // An acceptable genesis block is always valid, regardless of the contents, and it has
            // no nullifier proofs.
            return Ok((txns, vec![]));
        }

        let mut cap_txns = vec![];
        let mut reward_txns = vec![];
        let mut cap_nulls_proofs = vec![];
        let mut rewards_proofs = vec![];
        for (txn, helper_proofs) in txns.0.into_iter().zip(txns_helper_proofs.into_iter()) {
            match (txn, helper_proofs) {
                (EspressoTransaction::CAP(cap_txn), EspressoTxnHelperProofs::CAP(cap_nuls_pfs)) => {
                    cap_txns.push(cap_txn);
                    cap_nulls_proofs.push(cap_nuls_pfs);
                }
                (
                    EspressoTransaction::Reward(reward_txn),
                    EspressoTxnHelperProofs::Reward(reward_pfs),
                ) => {
                    reward_txns.push(reward_txn);
                    rewards_proofs.push(reward_pfs);
                }
                (EspressoTransaction::Genesis(_), _) => {
                    return Err(ValidationError::UnexpectedGenesis)
                }
                _ => return Err(ValidationError::InconsistentHelperProofs),
            }
        }

        let mut nullifiers_proofs = NullifierProofs::new();
        {
            // verify cap_txns
            let mut nulls = HashSet::new();
            use ValidationError::*;

            let recent_nullifiers = self.past_nullifiers.recent_nullifiers();
            for (pf, n) in cap_nulls_proofs
                .into_iter()
                .zip(cap_txns.iter())
                .flat_map(|(pfs, txn)| pfs.into_iter().zip(txn.nullifiers().into_iter()))
            {
                if nulls.contains(&n) {
                    return Err(NullifierAlreadyExists { nullifier: n });
                }

                let root = self
                    .past_nullifiers
                    .check_unspent(&recent_nullifiers, &pf, n)?;
                nullifiers_proofs.push((n, pf, root));
                nulls.insert(n);
            }

            let verif_keys = cap_txns
                .iter()
                .map(|txn| match txn {
                    TransactionNote::Mint(_) => Ok(&self.chain.verif_crs.mint),
                    TransactionNote::Transfer(note) => {
                        let num_inputs = note.inputs_nullifiers.len();
                        let num_outputs = note.output_commitments.len();
                        self.chain
                            .verif_crs
                            .xfr
                            .key_for_size(num_inputs, num_outputs)
                            .ok_or(UnsupportedTransferSize {
                                num_inputs,
                                num_outputs,
                            })
                    }
                    TransactionNote::Freeze(note) => {
                        let num_inputs = note.input_nullifiers.len();
                        let num_outputs = note.output_commitments.len();
                        self.chain
                            .verif_crs
                            .freeze
                            .key_for_size(num_inputs, num_outputs)
                            .ok_or(UnsupportedFreezeSize { num_inputs })
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut merkle_roots = vec![];
            for cap_note in cap_txns.iter() {
                let note_mt_root = cap_note.merkle_root();
                if self.record_merkle_commitment.root_value == note_mt_root
                    || self.past_record_merkle_roots.0.contains(&note_mt_root)
                {
                    merkle_roots.push(note_mt_root)
                } else {
                    return Err(BadMerkleRoot {});
                }
            }
            // cap transactions validates first
            if !cap_txns.is_empty() {
                txn_batch_verify(&cap_txns[..], &merkle_roots, now, &verif_keys)
                    .map_err(|err| CryptoError { err: Ok(err) })?;
            }
        }
        {
            //TODO (fernando) verify CollectRewards
        }
        // assemble Block
        let txns: Vec<_> = cap_txns
            .into_iter()
            .map(EspressoTransaction::CAP)
            .chain(reward_txns.into_iter().map(EspressoTransaction::Reward))
            .collect();

        Ok((Block(txns), nullifiers_proofs))
    }

    /// Performs validation for a block, updating the ValidatorState.
    ///
    /// If successful, returns
    /// * the UIDs of the newly created records
    /// * updated nullifier non-membership proofs for all of the nullifiers in `txns`, relative to
    ///   the nullifier set at the time this function was invoked, in the form of a sparse
    ///   reperesentation of a [SetMerkleTree]
    ///
    /// # Errors
    /// - [ValidationError::BadNullifierProof]
    /// - [ValidationError::BadMerklePath]
    /// # Panics
    /// Panics if the record Merkle commitment is inconsistent with the record Merkle frontier.
    pub fn validate_and_apply(
        &mut self,
        now: u64,
        txns: Block,
        proofs: Vec<EspressoTxnHelperProofs>,
    ) -> Result<ValidationOutputs, ValidationError> {
        let (txns, null_pfs) = self.validate_block_check(now, txns, proofs)?;
        // If the block successfully validates, and the nullifier proofs apply correctly, the
        // remaining (mutating) operations cannot fail, as this would result in an inconsistent
        // state. No operations after the first assignement to a member of self have a possible
        // error; this must remain true if code changes.
        let comm = self.commit();
        self.prev_commit_time = now;
        self.block_height += 1;
        self.prev_block = BlockCommitment(txns.commit());
        let null_pfs = self
            .past_nullifiers
            .append_block(null_pfs)
            .expect("failed to append nullifiers after validation");

        // If this is a genesis block, apply system parameter updates.
        if let Some(EspressoTransaction::Genesis(txn)) = txns.0.get(0) {
            self.chain = txn.chain.clone()
        }

        let mut record_merkle_builder = FilledMTBuilder::from_frontier(
            &self.record_merkle_commitment,
            &self.record_merkle_frontier,
        )
        .expect("failed to restore MerkleTree from frontier");
        let mut uids = vec![];
        let mut uid = self.record_merkle_commitment.num_leaves;
        for o in txns
            .0
            .iter()
            .flat_map(|x| x.output_commitments().into_iter())
        {
            record_merkle_builder.push(o.to_field_element());
            uids.push(uid);
            uid += 1;
        }
        let record_merkle_frontier = record_merkle_builder.build();
        assert_eq!(uid, record_merkle_frontier.num_leaves());

        if self.past_record_merkle_roots.0.len() >= Self::HISTORY_SIZE {
            self.past_record_merkle_roots.0.pop_back();
        }
        self.past_record_merkle_roots
            .0
            .push_front(self.record_merkle_commitment.root_value);
        self.record_merkle_commitment = record_merkle_frontier.commitment();
        self.record_merkle_frontier = record_merkle_frontier.frontier();
        self.prev_state = Some(comm);
        Ok(ValidationOutputs {
            uids,
            nullifier_proofs: null_pfs,
            record_proofs: record_merkle_frontier,
        })
    }

    pub fn update_nullifier_proofs(
        &self,
        txns: &[EspressoTransaction],
        proofs: Vec<EspressoTxnHelperProofs>,
    ) -> Result<SetMerkleTree, ValidationError> {
        let recent_nullifiers = self.past_nullifiers.recent_nullifiers();
        let proofs = proofs
            .into_iter()
            .zip(txns)
            .filter_map(|(pf, txn)| {
                if let EspressoTxnHelperProofs::CAP(pfs) = pf {
                    Some((pfs, txn))
                } else {
                    None
                }
            })
            .flat_map(|(pfs, txn)| pfs.into_iter().zip(txn.input_nullifiers()))
            .map(|(pf, n)| {
                let root = self
                    .past_nullifiers
                    .check_unspent(&recent_nullifiers, &pf, n)?;
                Ok((n, pf, root))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.past_nullifiers.update_proofs(proofs)
    }

    pub fn update_records_frontier(&self, txns: &[EspressoTransaction]) -> MerkleTree {
        let mut record_merkle_builder = FilledMTBuilder::from_frontier(
            &self.record_merkle_commitment,
            &self.record_merkle_frontier,
        )
        .expect("failed to restore MerkleTree from frontier");

        for o in txns.iter().flat_map(|t| t.output_commitments()) {
            record_merkle_builder.push(o.to_field_element());
        }
        record_merkle_builder.build()
    }
}

/// The Arbitrary trait is used for randomized (fuzz) testing.
impl<'a> Arbitrary<'a> for ValidatorState {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(crate::testing::MultiXfrTestState::initialize(
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            (u.arbitrary()?, u.arbitrary()?),
        )
        .unwrap()
        .validator)
    }
}

/// States are equivalent if their commitments match.
impl PartialEq for ValidatorState {
    fn eq(&self, other: &ValidatorState) -> bool {
        self.commit() == other.commit()
    }
}

impl Eq for ValidatorState {}

impl Hash for ValidatorState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <Commitment<_> as Hash>::hash(&self.commit().0, state);
    }
}

impl State<H_256> for ValidatorState {
    type Error = ValidationError;

    type Block = ElaboratedBlock;

    fn next_block(&self) -> Self::Block {
        Self::Block::default()
    }

    /// Validate a block for consensus
    fn validate_block(&self, block: &Self::Block) -> bool {
        self.validate_block_check(
            self.prev_commit_time + 1,
            block.block.clone(),
            block.proofs.clone(),
        )
        .is_ok()
    }

    /// Append a new block on successful validation
    ///
    /// # Errors
    /// See validate_and_apply.
    fn append(&self, block: &Self::Block) -> Result<Self, Self::Error> {
        let mut state = self.clone();
        state.validate_and_apply(
            state.prev_commit_time + 1,
            block.block.clone(),
            block.proofs.clone(),
        )?;
        Ok(state)
    }

    fn on_commit(&self) {}
}
