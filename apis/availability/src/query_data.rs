// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use ark_serialize::*;
use espresso_core::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedBlockCommitment,
    ElaboratedTransaction, TransactionCommitment, ValidatorState,
};
use jf_cap::structs::RecordCommitment;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

#[tagged_blob("NODEID")]
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize, Hash, PartialEq, Eq)]
pub struct EncodedPublicKey(pub Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockQueryData {
    pub raw_block: ElaboratedBlock,
    pub block_hash: ElaboratedBlockCommitment,
    pub block_id: u64,
    pub records_from: u64,
    pub record_count: u64,
    pub txn_hashes: Vec<TransactionCommitment>,
    pub timestamp: i128,
    pub proposer_id: EncodedPublicKey,
}

impl BlockQueryData {
    pub fn len(&self) -> usize {
        self.raw_block.block.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn transaction(&self, i: usize) -> Option<TransactionQueryData> {
        if i >= self.len() {
            return None;
        }
        Some(TransactionQueryData {
            raw_transaction: ElaboratedTransaction {
                txn: self.raw_block.block.0[i].clone(),
                proofs: self.raw_block.proofs[i].clone(),
                memos: self.raw_block.memos[i].clone(),
            },
            block_id: self.block_id,
            txn_id: i as u64,
            transaction_hash: self.txn_hashes[i],
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionQueryData {
    pub raw_transaction: ElaboratedTransaction,
    pub block_id: u64,
    pub txn_id: u64,
    pub transaction_hash: TransactionCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordQueryData {
    pub commitment: RecordCommitment,
    pub uid: u64,
    pub block_id: u64,
    pub txn_id: u64,
    pub output_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateQueryData {
    pub state: ValidatorState,
    pub commitment: LedgerStateCommitment,
    pub block_id: u64,
    /// Event index to subscribe to to follow chain events built on top of this state.
    pub continuation_event_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummaryQueryData {
    pub size: usize,
    pub txn_count: usize,
    /// The UID of the first output of this block.
    pub records_from: u64,
    /// The total number of outputs in this block.
    pub record_count: u64,
    pub view_number: u64,
    pub timestamp: i128,
    pub proposer_id: Vec<u8>,
    pub block_hash: ElaboratedBlockCommitment,
    pub block_id: u64,
}
