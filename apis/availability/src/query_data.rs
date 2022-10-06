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

use ark_serialize::*;
use espresso_core::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedBlockCommitment,
    ElaboratedTransaction, TransactionCommitment, ValidatorState,
};
use jf_cap::structs::RecordCommitment;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

#[tagged_blob("EncodedPubKey")]
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

// TODO !keyao Add proposer ID and timestamp to the block summary data.
// Issue: https://github.com/EspressoSystems/espresso/issues/624.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummaryQueryData {
    pub size: usize,
    pub txn_count: usize,
    /// The UID of the first output of this block.
    pub records_from: u64,
    /// The total number of outputs in this block.
    pub record_count: u64,
    pub view_number: u64,
}
