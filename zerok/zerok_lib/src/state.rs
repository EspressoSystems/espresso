#![deny(warnings)]

use espresso_macros::*;

pub use crate::full_persistence::FullPersistence;
pub use crate::lw_persistence::LWPersistence;
pub use crate::set_merkle_tree::*;
pub use crate::util::canonical;
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use canonical::deserialize_canonical_bytes;
use canonical::CanonicalBytes;
use commit::{Commitment, Committable};
use core::fmt::Debug;
use jf_cap::{
    errors::TxnApiError,
    structs::{Nullifier, RecordCommitment},
    txn_batch_verify, MerkleCommitment, MerkleFrontier, MerkleLeafProof, MerkleTree, NodeValue,
    TransactionNote,
};
use jf_utils::tagged_blob;
use key_set::VerifierKeySet;
use phaselock::{
    data::{BlockHash, LeafHash, TransactionHash},
    traits::{BlockContents, State},
    H_256,
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::Read;

/// Height of the Merkle tree
pub const MERKLE_HEIGHT: u8 = 20 /*H*/;

/// TODO Unused type wrapper
pub struct LedgerRecordCommitment(pub RecordCommitment);

/// TODO Unused type wrapper. Transaction is also defined in ledger.rs and
/// imported from reef in wallet/testing/mocks.rs
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Hash)]
pub struct Transaction(pub TransactionNote);

/// A transaction with proofs
///
/// Validation involves checking proofs that unspent records are unspent.
/// The proofs are large and only needed during validation, so we don't
/// carry them everywhere. The association between records in the transaction
/// note and the proofs is based on parallel arrays; the first input record
/// corresponds to the first proof, and so on.
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
    pub txn: TransactionNote,
    pub proofs: Vec<SetMerkleProof>,
}

/// Compute a cryptographic hash committing to an elaborated transaction.
impl ElaboratedTransaction {
    pub(crate) fn etxn_hash(&self) -> ElaboratedTransactionHash {
        ElaboratedTransactionHash(self.commit())
    }
}

/// A user-visible notation for a transaction hash, like TXN~bbb
///
/// The tagged_blob pragma informs
/// [TaggedBase64](https://github.com/EspressoSystems/tagged-base64/)
/// to use TXN as the tag when serializing.
#[ser_test(arbitrary)]
#[tagged_blob("TXN")]
#[derive(
    Arbitrary, Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct ElaboratedTransactionHash(pub(crate) Commitment<ElaboratedTransaction>);

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
pub struct Block(pub Vec<TransactionNote>);

/// A block of transactions with proofs
///
/// A block with nullifier set non-membership proofs. A nullifiers is
/// zero knowledge proofs that a record has not been spent.
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
    pub proofs: Vec<Vec<SetMerkleProof>>,
}

/// Get a commitment to an elaborated block.
///
/// The Committable trait allows us to designate the information to
/// extract from a structure to hash into a cryptographic commitment.
impl Committable for ElaboratedBlock {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("ElaboratedBlock")
            .field("Block contents", self.block.commit())
            .var_size_field("Block proofs", &canonical::serialize(&self.proofs).unwrap())
            .finalize()
    }
}

/// Get a commitment for an elaborated transaction.
impl Committable for ElaboratedTransaction {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("ElaboratedTransaction")
            .field("Txn contents", self.txn.commit())
            .var_size_field("Txn proofs", &canonical::serialize(&self.proofs).unwrap())
            .finalize()
    }
}

/// Allow an elaborated block to be used by our consensus protocol.
impl BlockContents<H_256> for ElaboratedBlock {
    type Transaction = ElaboratedTransaction;
    type Error = ValidationError;

    /// Add an elaborated transaction to a block.
    ///
    /// Preventing double spending is essential. When adding a transaction
    /// to a block, an error is generated if a duplicate nullifier is used.
    ///
    /// # Errors
    /// - [ValidationError::ConflictingNullifiers]
    fn add_transaction_raw(&self, txn: &ElaboratedTransaction) -> Result<Self, ValidationError> {
        let mut ret = self.clone();

        let mut nulls = self
            .block
            .0
            .iter()
            .flat_map(|x| x.nullifiers().into_iter())
            .collect::<HashSet<_>>();
        for n in txn.txn.nullifiers().iter() {
            if nulls.contains(n) {
                return Err(ValidationError::ConflictingNullifiers {});
            }
            nulls.insert(*n);
        }

        ret.block.0.push(txn.txn.clone());
        ret.proofs.push(txn.proofs.clone());

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
        let ret = commit::RawCommitmentBuilder::<Block>::new("PhaseLock bytes")
            .var_size_bytes(bytes)
            .finalize();
        LeafHash::<H_256>::from_array(ret.try_into().unwrap())
    }

    /// A cryptographic hash of an elaborated transaction
    fn hash_transaction(txn: &ElaboratedTransaction) -> TransactionHash<H_256> {
        TransactionHash::<H_256>::from_array(txn.commit().try_into().unwrap())
    }
}

/// Validation errors. Note: Wraps [TxnApiError] because it cannot be serialized.
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
    /// A transaction or block of transactions cannot consume a record more than once.
    ConflictingNullifiers {},
    /// A generic failure.
    Failed {},
    /// An incorrect Merkle length.
    BadMerkleLength {},
    /// An invalid Merkle leaf.
    BadMerkleLeaf {},
    /// An incorrect Merkle root.
    BadMerkleRoot {},
    /// An invalid Merkle path.
    BadMerklePath {},
    /// An error from the Jellyfish library
    CryptoError {
        // TxnApiError cannot be serialized, and, since it depends on many foreign error types which
        // are not Serialize, it is infeasible to make it serializable. Instead, if we have to
        // serialize this variant, we will serialize Ok(err) to Err(format(err)), and when we
        // deserialize we will at least preserve the variant CryptoError and a String representation
        // of the underlying error.
        #[serde(with = "ser_display")]
        err: Result<TxnApiError, String>,
    },
    /// Only certain predefined numbers of inputs and outputs are supported.
    UnsupportedTransferSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    /// Only certain predefined numbers of inputs and outputs are supported.
    UnsupportedFreezeSize {
        num_inputs: usize,
    },
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

pub(crate) mod ser_debug {
    use serde::de::{Deserialize, Deserializer};
    use serde::ser::{Serialize, Serializer};
    use std::fmt::Debug;

    pub fn serialize<S: Serializer, T: Debug>(
        v: &Result<T, String>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let string = match v {
            Ok(v) => format!("{:?}", v),
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

/// Sliding window for transaction freshness
///
/// We keep several Jellyfish node values here to allow validation of
/// transactions built against recent but not most recent ledger state
/// commitments.
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

    /// The essential state of the ledger
    ///
    /// Note that many elements of the state are represented
    /// succinctly as cryptographic commitments.
    #[derive(Debug)]
    pub struct LedgerCommitmentOpening {
        pub prev_commit_time: u64,
        pub prev_state: Option<state_comm::LedgerStateCommitment>,
        pub verif_crs: Commitment<VerifierKeySet>,
        pub record_merkle_commitment: Commitment<RecordMerkleCommitment>,
        pub record_merkle_frontier: Commitment<RecordMerkleFrontier>,
        pub past_record_merkle_roots: Commitment<RecordMerkleHistory>,
        pub nullifiers: set_hash::Hash,
        pub prev_block: Commitment<Block>,
    }

    impl Committable for LedgerCommitmentOpening {
        fn commit(&self) -> Commitment<Self> {
            commit::RawCommitmentBuilder::new("Ledger Comm")
                .u64_field("prev_commit_time", self.prev_commit_time)
                .array_field(
                    "prev_state",
                    &self
                        .prev_state
                        .iter()
                        .cloned()
                        .map(Commitment::<Self>::from)
                        .collect::<Vec<_>>(),
                )
                .field("verif_crs", self.verif_crs)
                .field("record_merkle_commitment", self.record_merkle_commitment)
                .field("record_merkle_frontier", self.record_merkle_frontier)
                .field("past_record_merkle_roots", self.past_record_merkle_roots)
                .field("nullifiers", self.nullifiers.into())
                .field("prev_block", self.prev_block)
                .finalize()
        }
    }
}

/// The working state of the ledger
///
/// Only the previous state is represented as a commitment. Other
/// values are present in full.
#[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorState {
    pub prev_commit_time: u64,
    pub prev_state: Option<state_comm::LedgerStateCommitment>,
    pub verif_crs: VerifierKeySet,
    /// The current record Merkle commitment
    pub record_merkle_commitment: MerkleCommitment,
    /// The current frontier of the record Merkle tree
    pub record_merkle_frontier: MerkleFrontier,
    /// A list of recent record Merkle root hashes for validating slightly out-of-date transactions
    pub past_record_merkle_roots: RecordMerkleHistory,
    pub nullifiers_root: set_hash::Hash,
    pub prev_block: BlockCommitment,
}

impl ValidatorState {
    /// The number recent record Merkle tree root hashes the validator should remember
    ///
    /// Transactions can be validated without resubmitting or regenerating the ZKPs as long as they
    /// were generated using a validator state that is in the last RECORD_ROOT_HISTORY_SIZE states.
    pub const RECORD_ROOT_HISTORY_SIZE: usize = 10;

    pub fn new(verif_crs: VerifierKeySet, record_merkle_frontier: MerkleTree) -> Self {
        let nullifiers: SetMerkleTree = Default::default();

        Self {
            prev_commit_time: 0u64,
            prev_state: None,
            verif_crs,
            record_merkle_commitment: record_merkle_frontier.commitment(),
            record_merkle_frontier: record_merkle_frontier.frontier(),
            past_record_merkle_roots: RecordMerkleHistory(VecDeque::with_capacity(
                Self::RECORD_ROOT_HISTORY_SIZE,
            )),
            nullifiers_root: nullifiers.hash(),
            prev_block: BlockCommitment(Block::default().commit()),
        }
    }

    /// Cryptographic commitment to the validator state
    pub fn commit(&self) -> state_comm::LedgerStateCommitment {
        let inputs = state_comm::LedgerCommitmentOpening {
            prev_commit_time: self.prev_commit_time,
            prev_state: self.prev_state,
            verif_crs: self.verif_crs.commit(),
            record_merkle_commitment: RecordMerkleCommitment(self.record_merkle_commitment)
                .commit(),
            record_merkle_frontier: RecordMerkleFrontier(self.record_merkle_frontier.clone())
                .commit(),
            /// We need to include all the cached past record Merkle roots in the state commitment,
            /// even though they are not part of the current ledger state, because they affect
            /// validation: two validators with different caches will be able to validate different
            /// blocks.
            ///
            /// Note that this requires correct validators to agree on the number of cached past root
            /// hashes, since all the cached hashes are included in the state commitment and are thus
            /// part of the observable state of the ledger. This prevents heavyweight validators from
            /// caching extra past roots and thereby making it easier to verify transactions, but
            /// because root hashes are small, it should be possible to find a value of
            /// RECORD_ROOT_HISTORY_SIZE which strikes a balance between small space requirements (so
            /// that lightweight validators can keep up with the cache) and covering enough of
            /// history to make it easy for clients. If this is not possible, lightweight validators
            /// could also store a sparse history, and when they encounter a root hash that they do
            /// not have cached, they could ask a full validator for a proof that that hash was once
            /// the root of the record Merkle tree.
            past_record_merkle_roots: self.past_record_merkle_roots.commit(),

            nullifiers: self.nullifiers_root,
            prev_block: self.prev_block.0,
        };
        inputs.commit().into()
    }

    /// Validate a block of elaborated transactions
    ///
    /// Checks the following
    /// - None of the nullifiers are used more than once
    /// - Keys are available for the  numbers of transaction inputs and
    ///   outputs
    /// - The Merkle roots are recent enough
    /// - The batch of transactions verifies
    ///
    /// If valid, return the input transactions and proofs, otherwise return a validation error.
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
        null_pfs: Vec<Vec<SetMerkleProof>>,
    ) -> Result<(Block, Vec<Vec<SetMerkleProof>>), ValidationError> {
        let mut nulls = HashSet::new();
        use ValidationError::*;
        for (pf, n) in null_pfs
            .iter()
            .zip(txns.0.iter())
            .flat_map(|(pfs, txn)| pfs.iter().zip(txn.nullifiers().into_iter()))
        {
            if nulls.contains(&n)
                || pf
                    .check(n, &self.nullifiers_root)
                    .map_err(|_| BadNullifierProof {})?
            {
                return Err(NullifierAlreadyExists { nullifier: n });
            }

            nulls.insert(n);
        }

        let verif_keys = txns
            .0
            .iter()
            .map(|txn| match txn {
                TransactionNote::Mint(_) => Ok(&self.verif_crs.mint),
                TransactionNote::Transfer(note) => {
                    let num_inputs = note.inputs_nullifiers.len();
                    let num_outputs = note.output_commitments.len();
                    self.verif_crs
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
                    self.verif_crs
                        .freeze
                        .key_for_size(num_inputs, num_outputs)
                        .ok_or(UnsupportedFreezeSize { num_inputs })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if !txns.0.is_empty() {
            txn_batch_verify(
                &txns.0,
                &txns
                    .0
                    .iter()
                    .map(|note| {
                        // Only validate transactions if we can confirm that the record Merkle root
                        // they were generated with is a valid previous or current ledger state.
                        if self.record_merkle_commitment.root_value == note.merkle_root()
                            || self
                                .past_record_merkle_roots
                                .0
                                .contains(&note.merkle_root())
                        {
                            Ok(note.merkle_root())
                        } else {
                            Err(BadMerkleRoot {})
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                now,
                &verif_keys,
            )
            .map_err(|err| CryptoError { err: Ok(err) })?;
        }

        Ok((txns, null_pfs))
    }

    /// Performs validation for a block, updating the ValidatorState.
    ///
    /// For a given instance of ValidatorState, all calls to validate_and_apply must pass the
    /// same remember_commitments value. This identity holds for clones of the original as well.
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
        null_pfs: Vec<Vec<SetMerkleProof>>,
    ) -> Result<Vec<u64> /* new uids */, ValidationError> {
        // If the block successfully validates, and the nullifier proofs apply correctly,
        // the remaining (mutating) operations cannot fail, as this would result in an
        // inconsistent state. No operations after the first assignement to a member
        // of self have a possible error; this must remain true if code changes.
        let (txns, _null_pfs) = self.validate_block_check(now, txns, null_pfs.clone())?;
        let comm = self.commit();
        self.prev_commit_time = now;
        self.prev_block = BlockCommitment(txns.commit());

        let nullifiers = txns
            .0
            .iter()
            .zip(null_pfs.into_iter())
            .flat_map(|(txn, null_pfs)| txn.nullifiers().into_iter().zip(null_pfs.into_iter()))
            .collect();

        self.nullifiers_root = set_merkle_lw_multi_insert(nullifiers, self.nullifiers_root)
            .map_err(|_| ValidationError::BadNullifierProof {})?
            .0;

        let mut record_merkle_frontier = MerkleTree::restore_from_frontier(
            self.record_merkle_commitment,
            &self.record_merkle_frontier,
        )
        .ok_or(ValidationError::BadMerklePath {})?;
        let mut ret = vec![];
        let mut uid = self.record_merkle_commitment.num_leaves;
        for o in txns
            .0
            .iter()
            .flat_map(|x| x.output_commitments().into_iter())
        {
            record_merkle_frontier.push(o.to_field_element());
            if uid > 0 {
                record_merkle_frontier.forget(uid - 1).expect_ok().unwrap();
            }
            ret.push(uid);
            uid += 1;
            assert_eq!(uid, record_merkle_frontier.num_leaves());
        }

        if self.past_record_merkle_roots.0.len() >= Self::RECORD_ROOT_HISTORY_SIZE {
            self.past_record_merkle_roots.0.pop_back();
        }
        self.past_record_merkle_roots
            .0
            .push_front(self.record_merkle_commitment.root_value);
        self.record_merkle_commitment = record_merkle_frontier.commitment();
        self.record_merkle_frontier = record_merkle_frontier.frontier();
        self.prev_state = Some(comm);
        Ok(ret)
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
