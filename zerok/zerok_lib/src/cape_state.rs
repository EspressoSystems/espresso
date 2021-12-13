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

impl CapeTransaction {
    fn nullifiers(&self) -> Vec<Nullifier> {
        match self {
            CapeTransaction::Burn {
                xfr, ..
            } => {
                xfr.inputs_nullifiers.clone()
            },

            CapeTransaction::AAP(TransactionNote::Transfer(xfr)) => {
                xfr.inputs_nullifiers.clone()
            },

            CapeTransaction::AAP(TransactionNote::Mint(mint)) => {
                vec![mint.input_nullifier.clone()]
            },

            CapeTransaction::AAP(TransactionNote::Freeze(frz)) => {
                freeze.input_nullifiers.clone()
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Erc20Code([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumAddr([u8; 20]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapeOperation {
    SubmitBlock(Vec<CapeTransaction>),
    RegisterErc20 {
        asset_def: AssetDefinition,
        erc20Code: Erc20Code,
        sponsor_addr: EthereumAddr,
    },
    WrapERC20 {
        erc20Code: Erc20Code,
        src_addr: EthereumAddr,
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
    InvalidErc20Def {
        asset_def: AssetDefinition,
        erc20Code: Erc20Code,
        sponsor: EthereumAddr,
    },
    InvalidAAPDef {
        asset_def: AssetDefinition,
    },
    UnregisteredErc20 {
        asset_def: AssetDefinition,
    },
    IncorrectErc20 {
        asset_def: AssetDefinition,
        erc20Code: Erc20Code,
        expected_erc20Code: Erc20Code,
    },
    Erc20AlreadyRegistered {
        asset_def: AssetDefinition,
    },

    NullifierAlreadyExists {
        nullifier: Nullifier,
    },

    IncorrectBurnOpening {
        expected_comm: RecordCommitment,
        ro: RecordOpening,
    },

    IncorrectBurnField {
        xfr: TransferNote,
    },

    UnsupportedBurnSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    UnsupportedTransferSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    UnsupportedFreezeSize {
        num_inputs: usize,
    },

    BadMerkleRoot {},

    CryptoError {
        // TxnApiError cannot be serialized, and, since it depends on many foreign error types which
        // are not Serialize, it is infeasible to make it serializable. Instead, if we have to
        // serialize this variant, we will serialize Ok(err) to Err(format(err)), and when we
        // deserialize we will at least preserve the variant CryptoError and a String representation
        // of the underlying error.
        #[serde(with = "ser_display")]
        err: Result<TxnApiError, String>,
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
    pub erc20_registrar: HashMap<AssetDefinition, (Erc20Code,EthereumAddr)>,
    pub erc20_deposited: HashMap<Erc20Code,u128>,
    pub erc20_deposits: Vec<RecordCommitment>,
}

fn is_erc20_asset_def_valid(def: &AssetDefinition, erc20Code: &Erc20Code, sponsor: &EthereumAddr) -> bool {
    // TODO
    true
}

fn is_aap_asset_def_valid(def: &AssetDefinition) -> bool {
    // TODO
    true
}

/// None => invalid field, should always be rejected
/// Some(None) => Valid field, not a burn
/// Some(Some(addr)) => Valid field, a burn sending to `addr`
fn extract_burn_dst(xfr: &TransferNote) -> Option<EthereumAddr> {
    let magic_bytes = CAPE_BURN_MAGIC_BYTES.as_bytes().to_vec();
    assert_eq!(magic_bytes.len(), 12);
    assert_eq!(EthereumAddr::default().0.len(), 20);

    let field_data = &xfr.aux_info.extra_proof_bound_data;

    match field_data.len() {
        0 => Some(None),
        32 => {
            if field_data[..12] != magic_bytes[..] {
                None
            } else {
                Some(field_data[12..32].as_vec())
            }
        },
        _ => None,
    }
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
        let mut new_state = self.clone();
        let mut effects = vec![];

        new_state.ledger.state_number += 1;

        for o in ops {
            match o {
                CapeOperation::RegisterErc20 {
                    asset_def, erc20Code, sponsor_addr
                } => {
                    if !is_erc20_asset_def_valid(asset_def,erc20Code,sponsor) {
                        return Err(InvalidErc20Def { 
                            asset_def
                        });
                    }

                    if new_state.erc20_registrar.contains_key(asset_def) {
                        return Err(Erc20AlreadyRegistered {
                            asset_def
                        });
                    }
                    new_state.erc20_registrar.insert(asset_def,(erc20Code,sponsor));
                    effects.push(CheckErc20Exists { erc20Code });
                }
                CapeOperation::WrapErc20 {
                    erc20Code, src_addr, ro
                } => {
                    let asset_def = ro.asset_def;
                    let (expected_erc20Code,_sponsor) = new_state.erc20_registrar.get(asset_def)
                        .ok_or_else(|| UnregisteredErc20 { asset_def })?;
                    if expected_erc20Code != erc20Code {
                        return Err(
                            IncorrectErc20 {
                                asset_def,
                                erc20Code,
                                expected_erc20Code,
                            });
                    }

                    new_state.erc20_deposits.push(RecordCommitment::from(ro));
                    effects.push(ReceiveErc20 {
                        erc20Code,
                        amount: ro.amount,
                        src_addr,
                    });
                }
                CapeOperation::SubmitBlock(txns) => {
                    // Step 1: filter txns for those with nullifiers that
                    // aren't already published
                    let filtered_txns = txns.iter().filter(|t| t.nullifiers().into_iter().all(|x| !new_state.nullifiers.contains(x))).cloned().collect();

                    let mut records_to_insert = vec![];
                    // TODO: the workflow code puts these after the things
                    // in the transactions -- which thing is correct?
                    records_to_insert.extend(new_state.erc20_deposits.drain(..));

                    // past this point, if any validation error occurs the
                    // entire evm transaction rolls back, so we can mutate
                    // new_state in place.

                    // check everything except the plonk proofs, build up
                    // verif_keys

                    let mut verif_keys = vec![];
                    let mut merkle_roots = vec![];
                    for t in filtered_txns.iter() {
                        // insert nullifiers
                        for n in t.nullifiers() { if new_state.nullifiers.insert(n).is_some() {
                                return Err(NullifierAlreadyExists{nullifier: n})
                            }
                        }

                        // TODO: fee-collection records
                        let (vkey,merkle_root,new_records) = match txn {
                            CapeTransaction::AAP(TransactionNote::Mint(mint)) => {
                                if !is_aap_asset_def_valid(&mint.mint_asset_def) {
                                    return Err(InvalidAAPDef { asset_def: mint.mint_asset_def });
                                }

                                (&new_state.verif_crs.mint,mint.aux_info.merkle_root,mint.output_commitments())
                            },

                            CapeTransaction::Burn{ xfr, ro }) => {
                                let num_inputs = note.inputs_nullifiers.len();
                                let num_outputs = note.output_commitments.len();

                                // TODO: is this correct?
                                if (num_inputs,num_outputs) != (2,2) {
                                    return Err(UnsupportedBurnSize { num_inputs,num_outputs });
                                }

                                let expected_comm = xfr.outputs_commitments[1];
                                let actual_comm   = RecordCommitment::from(ro);
                                if expected_comm != actual_comm {
                                    return Err(IncorrectBurnOpening {
                                        expected_comm, ro
                                    });
                                }

                                let asset_def = ro.asset_def;

                                let (erc20Code,_sponsor) = new_state.erc20_registrar.get(asset_def)
                                    .ok_or_else(|| UnregisteredErc20 { asset_def })?;

                                let dst_addr = if let Some(Some(dst) = extract_burn_dst(&xfr) {
                                    Some(dst)
                                } else {
                                    None
                                }.unwrap_or_else(|| IncorrectBurnField { xfr })?;

                                effects.push(SendErc20 { erc20Code, ro.amount, dst_addr });

                                let verif_key = verif_crs
                                    .xfr
                                    .key_for_size(num_inputs, num_outputs)
                                    .ok_or(UnsupportedBurnSize {
                                        num_inputs,
                                        num_outputs,
                                    })?;

                                (verif_key,xfr.aux_info.merkle_root,vec![xfr.outputs_commitments[0]])
                            }

                            CapeTransaction::AAP(TransactionNote::Transfer(note)) => {

                                let num_inputs = note.inputs_nullifiers.len();
                                let num_outputs = note.output_commitments.len();

                                if Some(None) != extract_burn_dst(&note) {
                                    return Err(IncorrectBurnField { xfr: note });
                                }

                                let verif_key = verif_crs
                                    .xfr
                                    .key_for_size(num_inputs, num_outputs)
                                    .ok_or(UnsupportedBurnSize {
                                        num_inputs,
                                        num_outputs,
                                    })?;

                                (verify_key,note.aux_info.merkle_root,note.output_commitments())
                            }

                            CapeTransaction::AAP(TransactionNote::Freeze(note)) => {
                                let num_inputs = note.inputs_nullifiers.len();
                                let num_outputs = note.output_commitments.len();

                                let verif_key = verif_crs
                                    .freeze
                                    .key_for_size(num_inputs, num_outputs)
                                    .ok_or(UnsupportedBurnSize {
                                        num_inputs,
                                        num_outputs,
                                    })?;

                                (verify_key,note.aux_info.merkle_root,note.output_commitments())
                            }
                        }

                        verif_keys.push(vkey);
                        if !new_state.ledger.past_merkle_roots.0.contains(merkle_root) {
                            return Err(BadMerkleRoot {});
                        }
                        merkle_roots.push(merkle_root);
                        records_to_insert.extend(new_records.into_iter());
                    }

                    // Batch PLONK verify
                    if !filtered_txns.is_empty() {
                        assert_eq!(filtered_txns.len(),verif_keys.len());
                        assert_eq!(filtered_txns.len(),merkle_roots.len());

                        txn_batch_verify(
                            &filtered_txns,
                            &merkle_roots,
                            new_state.state_number,
                            &verif_keys).map_err(|err| CryptoError { err: Ok(err) })?;
                    }


                    // update the record tree
                    let (record_merkle_frontier,record_merkle_commitment) = {
                        let mut builder = FilledMTBuilder::from_frontier(
                            new_state.ledger.record_merkle_commitment,
                            &new_state.ledger.record_merkle_frontier,
                        )
                        .ok_or(ValidationError::BadMerklePath {})?;

                        for rc in records_to_insert {
                            builder.push(rc);
                        }

                        builder.into_frontier_and_commitment()
                    };

                    if new_state.ledger.past_record_merkle_roots.0.len() >= Self::RECORD_ROOT_HISTORY_SIZE {
                        new_state.ledger.past_record_merkle_roots.0.pop_back();
                    }
                    new_state.ledger.past_record_merkle_roots
                        .0
                        .push_front(new_state.ledger.record_merkle_commitment.root_value);
                    new_state.ledger.record_merkle_commitment = record_merkle_commitment;
                    new_state.ledger.record_merkle_frontier = record_merkle_frontier;
                }
            }
        }

        Ok((new_state,))
    }

}

