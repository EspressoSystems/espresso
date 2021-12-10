#![deny(warnings)]

use zerok_macros::*;

use crate::commit;
pub use crate::full_persistence::FullPersistence;
pub use crate::lw_persistence::LWPersistence;
pub use crate::set_merkle_tree::*;
pub use crate::util::canonical;
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use canonical::deserialize_canonical_bytes;
use commit::{Commitment, Committable};
use core::fmt::Debug;
use jf_txn::{
    errors::TxnApiError,
    proof::{freeze::FreezeProvingKey, mint::MintProvingKey, transfer::TransferProvingKey},
    structs::{Nullifier, RecordCommitment},
    txn_batch_verify, MerkleCommitment, MerkleFrontier, MerkleLeafProof, MerkleTree, NodeValue,
    TransactionNote, TransactionVerifyingKey,
};
use jf_utils::tagged_blob;
use phaselock::{traits::state::State, BlockContents, H_256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use snafu::Snafu;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::iter::FromIterator;
use std::ops::Bound::*;

pub const CAPE_MERKLE_HEIGHT: u8 = 20 /*H*/;
pub const CAPE_BURN_MAGIC_BYTES: &str = "TRICAPE burn";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapeTransaction {
    AAP(TransactionNote),
    Burn {
        xfr: TransferNote,
        ro: RecordOpening,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Erc20Code([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumAddr([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapeOperation {
    SubmitBlock(Vec<CapeTransaction>),
    RegisterErc20 {
        erc20Code: Erc20Code,
        sponsor_addr: EthereumAddr,
    },
    WrapERC20 {
        erc20Code: Erc20Code,
        ro: RecordOpening,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapeEthEffects {
    ReceiveErc20 {
        erc20Code: Erc20Code,
        amount: u64,
        src_addr: EthereumAddr,
    },
    CheckErc20Exists {
        erc20Code: Erc20Code,
    },
    SendErc20 {
        erc20Code: Erc20Code,
        amount: u64,
        dst_addr: EthereumAddr,
    },
}

// TODO details
#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(visibility = "pub(crate)")]
pub enum CapeValidationError {
    NullifierAlreadyExists {
        nullifier: Nullifier,
    },
    BadNullifierProof {},
    MissingNullifierProof {},
    ConflictingNullifiers {},
    Failed {},
    BadMerkleLength {},
    BadMerkleLeaf {},
    BadMerkleRoot {},
    BadMerklePath {},
    CryptoError {
        // TxnApiError cannot be serialized, and, since it depends on many foreign error types which
        // are not Serialize, it is infeasible to make it serializable. Instead, if we have to
        // serialize this variant, we will serialize Ok(err) to Err(format(err)), and when we
        // deserialize we will at least preserve the variant CryptoError and a String representation
        // of the underlying error.
        #[serde(with = "ser_display")]
        err: Result<TxnApiError, String>,
    },
    UnsupportedTransferSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    UnsupportedFreezeSize {
        num_inputs: usize,
    },
}

// TxnApiError doesn't implement Clone :/
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapeLedgerState {
    pub state_number: u64, // "block height"
    // The current record Merkle commitment
    pub record_merkle_commitment: MerkleCommitment,
    // The current frontier of the record Merkle tree
    pub record_merkle_frontier: MerkleFrontier,
    // A list of recent record Merkle root hashes for validating slightly-out- of date transactions.
    pub past_record_merkle_roots: RecordMerkleHistory,

    // TODO: should we include these?
    // pub prev_state: Option<StateCommitment>,
    // pub prev_block: BlockCommitment,
}

pub struct CapeContractState {
    pub ledger: CapeLedgerState,
    pub verif_crs: VerifierKeySet, // hard-coded
    pub nullifiers: HashSet<Nullifier>,
    pub erc20_registrar: HashMap<AssetDefinition, Erc20Code>,
    pub erc20_deposited: HashMap<Erc20Code,u128>,
    pub erc20_deposits: Vec<RecordCommitment>,
}

impl CapeContractState {
    // How many previous record Merkle tree root hashes the validator should remember.
    pub const RECORD_ROOT_HISTORY_SIZE: usize = 10;

    pub fn new(verif_crs: VerifierKeySet, record_merkle_frontier: MerkleTree) -> Self {
        Self {
            ledger: CapeLedgerState {
                state_number: 0u64,
                record_merkle_commitment: record_merkle_frontier.commitment(),
                record_merkle_frontier: record_merkle_frontier.frontier(),
                past_record_merkle_roots: RecordMerkleHistory(VecDeque::with_capacity(
                    Self::RECORD_ROOT_HISTORY_SIZE,
                )),
            },
            verif_crs,
            nullifiers: HashSet::new(),
            erc20_registrar: HashMap::new(),
            erc20_deposited: HashMap::new(),
            erc20_deposits: Vec::new(),
        }
    }

    pub fn submit_operations(&self, ops: Vec<CapeOperation>) -> Result<(Self,Vec<CapeEthEffects>),CapeValidationError> {
        unimplemented!()
    }

}

