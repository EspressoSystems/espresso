///////////////////////////////////////////////////////////////////////////////
// Rust interface for the query API
//
// All data structures returned by query API endpoints correspond directly to
// Rust data structures via the serde serialization and deserialization
// interfaces. For query responses which do not directly correspond to data
// structures elsewhere in this crate or in Jellyfish, data structures are
// defined in this module which can be serialized to and from the API
// responses.
//
// Types which must be embeddable in URLs (e.g. hashes and identifiers) and
// binary blob types are serialized as tagged base 64 strings. Other
// structures use derived serde implementations, which allows them to
// serialize as human-readable JSON objects or as binary strings, depending
// on the serializer used. This makes it easy for the API to support multiple
// content types in its responses, as long as each endpoint handler returns an
// object with the appropriate Serialize implementation.
//

use crate::{Block, ElaboratedBlock, ElaboratedTransaction, SetMerkleProof};
use ark_serialize::*;
use fmt::{Display, Formatter};
use generic_array::{ArrayLength, GenericArray};
use jf_txn::{
    structs::{ReceiverMemo, RecordCommitment},
    Signature, TransactionNote,
};
use jf_utils::{tagged_blob, Tagged};
use phaselock::BlockHash;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::fmt;
use tagged_base64::TaggedBase64;

#[tagged_blob("HASH")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct Hash(pub Vec<u8>);

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_string(self, f)
    }
}

impl<const N: usize> From<BlockHash<N>> for Hash {
    fn from(h: BlockHash<N>) -> Self {
        Self(h.as_ref().to_vec())
    }
}

impl<U: ArrayLength<u8>> From<GenericArray<u8, U>> for Hash {
    fn from(a: GenericArray<u8, U>) -> Self {
        Self((&*a).to_vec())
    }
}

#[tagged_blob("BK")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct BlockId(pub usize);

impl Display for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_string(self, f)
    }
}

#[tagged_blob("TX")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct TransactionId(pub BlockId, pub usize);

impl Display for TransactionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_string(self, f)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedBlock {
    pub id: BlockId,
    pub index: usize,
    pub hash: Hash,
    pub state_commitment: Hash,
    pub transactions: Vec<CommittedTransaction>,
}

impl Display for CommittedBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_object(self, f)
    }
}

impl From<CommittedBlock> for ElaboratedBlock {
    fn from(b: CommittedBlock) -> Self {
        let (txs, proofs) = b
            .transactions
            .into_iter()
            .map(|tx| (tx.data, tx.proofs))
            .unzip();
        Self {
            block: Block(txs),
            proofs,
        }
    }
}

impl From<&CommittedBlock> for ElaboratedBlock {
    fn from(b: &CommittedBlock) -> Self {
        let (txs, proofs) = b
            .transactions
            .iter()
            .map(|tx| (tx.data.clone(), tx.proofs.clone()))
            .unzip();
        Self {
            block: Block(txs),
            proofs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedTransaction {
    pub id: TransactionId,
    pub data: TransactionNote,
    pub proofs: Vec<SetMerkleProof>,
    pub output_uids: Vec<u64>,
    pub output_memos: Option<Vec<ReceiverMemo>>,
    pub memos_signature: Option<Signature>,
}

impl From<CommittedTransaction> for ElaboratedTransaction {
    fn from(tx: CommittedTransaction) -> Self {
        Self {
            txn: tx.data,
            proofs: tx.proofs,
        }
    }
}

impl From<&CommittedTransaction> for ElaboratedTransaction {
    fn from(tx: &CommittedTransaction) -> Self {
        Self {
            txn: tx.data.clone(),
            proofs: tx.proofs.clone(),
        }
    }
}

impl Display for CommittedTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_object(self, f)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnspentRecord {
    pub commitment: RecordCommitment,
    pub uid: u64,
    pub memo: Option<ReceiverMemo>,
}

impl Display for UnspentRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_using_json_object(self, f)
    }
}

// Helper trait with a blanket implementation allowing us to convert TaggedBase64 to any type which
// implements Tagged and CanonicalDeserialize.
pub trait TaggedBlob: Sized + Tagged + CanonicalDeserialize {
    fn from_tagged_blob(b64: &TaggedBase64) -> Result<Self, TaggedBlobError>;
}

#[derive(Debug, Snafu)]
pub enum TaggedBlobError {
    SerError { source: SerializationError },
    TagMismatch { actual: String, expected: String },
}

impl<T: Tagged + CanonicalDeserialize> TaggedBlob for T {
    fn from_tagged_blob(b64: &TaggedBase64) -> Result<Self, TaggedBlobError> {
        if b64.tag() == Self::tag() {
            Self::deserialize(&*b64.value()).context(SerError)
        } else {
            Err(TaggedBlobError::TagMismatch {
                actual: b64.tag(),
                expected: Self::tag(),
            })
        }
    }
}

// Display implementation for types which serialize to a JSON string. Displays as just the contents
// of the string, without the enclosing quotation marks. For base 64 strings, this makes the Display
// impl suitable for embedding in URLs.
fn fmt_using_json_string<T: Serialize>(v: &T, f: &mut Formatter<'_>) -> fmt::Result {
    let quoted_string = serde_json::to_string(v).map_err(|_| fmt::Error)?;
    write!(f, "{}", &quoted_string[1..quoted_string.len() - 1])
}

// Display implementation for types which serialize to JSON. Displays as a valid JSON object.
fn fmt_using_json_object<T: Serialize>(v: &T, f: &mut Formatter<'_>) -> fmt::Result {
    let string = serde_json::to_string(v).map_err(|_| fmt::Error)?;
    write!(f, "{}", string)
}
