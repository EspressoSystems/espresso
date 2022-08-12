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

use crate::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedTransaction, EspressoTransaction,
    SetMerkleProof, SetMerkleTree, ValidationError, ValidatorState,
};
use crate::util::canonical;
use commit::{Commitment, Committable};
use itertools::izip;
use itertools::MultiUnzip;
use jf_cap::{
    keys::{ViewerKeyPair, ViewerPubKey},
    structs::{AssetCode, AssetDefinition, Nullifier, RecordCommitment},
    TransactionNote,
};
use reef::traits::Transaction;
use reef::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum EspressoTransactionKind {
    CAP(reef::cap::TransactionKind),
    // REWARD TODO (fernando)
}

impl traits::TransactionKind for EspressoTransactionKind {
    fn send() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Send)
    }

    fn receive() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Receive)
    }

    fn mint() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Mint)
    }

    fn freeze() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Freeze)
    }

    fn unfreeze() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Unfreeze)
    }

    fn unknown() -> Self {
        EspressoTransactionKind::CAP(reef::cap::TransactionKind::Unknown)
    }
}

impl traits::NullifierSet for SetMerkleTree {
    type Proof = SetMerkleProof;

    fn multi_insert(&mut self, nullifiers: &[(Nullifier, Self::Proof)]) -> Result<(), Self::Proof> {
        // Bring nullifier tree branches containing spent nullifiers into memory, using the proofs
        // contained in the block. All the proofs are relative to the original nullifiers set, so we
        // need to bring all the relevant branches into memory before adding any of the new
        // nullifiers to the set, as this will change the tree and invalidate the remaining proofs.
        for (nullifier, proof) in nullifiers {
            if self.remember(*nullifier, proof.clone()).is_err() {
                return Err(proof.clone());
            }
        }
        // Now we can add the new nullifiers to the tree.
        for (nullifier, _) in nullifiers {
            // This should not fail, since we remembered all the relevant nullifiers in the previous
            // loop, so we can unwrap().
            self.insert(*nullifier).unwrap();
        }
        // Now that the new nullifiers have all been inserted, we can prune our nullifiers set back
        // down to restore sparseness.
        for (nullifier, _) in nullifiers {
            //todo !jeb.bearer for now we unconditionally forget the new nullifier, knowing we can
            // get it back from the backend if necessary. However, this nullifier may be helping us
            // by representing a branch of the tree that we care about, that would allow us to
            // generate a proof that the nullifier for one of our owned records is _not_ in the
            // tree. We should be more careful about pruning to cut down on the amount we have to
            // ask the network.
            // https://github.com/EspressoSystems/espresso/issues/414
            self.forget(*nullifier);
        }

        Ok(())
    }
}

impl EspressoTransaction {
    pub(crate) fn open_viewing_memo(
        &self,
        viewable_assets: &HashMap<AssetCode, AssetDefinition>,
        viewing_keys: &HashMap<ViewerPubKey, ViewerKeyPair>,
    ) -> Result<ViewingMemoOpening, ViewingError> {
        match self {
            Self::CAP(txn) => {
                reef::traits::Transaction::open_viewing_memo(txn, viewable_assets, viewing_keys)
            }
        }
    }

    /// Retrieve transaction output record commitments.
    pub fn output_commitments(&self) -> Vec<RecordCommitment> {
        match self {
            Self::CAP(txn) => txn.output_commitments(),
        }
    }

    /// A committing hash of this transaction.
    pub fn hash(&self) -> Commitment<EspressoTransaction> {
        self.commit()
    }

    /// Retrieve kind of transaction.
    pub fn kind(&self) -> EspressoTransactionKind {
        match self {
            EspressoTransaction::CAP(txn) => EspressoTransactionKind::CAP(txn.kind()),
        }
    }

    /// Retrieve number of transaction outputs.
    pub fn output_len(&self) -> usize {
        match self {
            Self::CAP(txn) => txn.output_len(),
        }
    }

    /// Retrieve transaction input nullifiers.
    pub fn input_nullifiers(&self) -> Vec<Nullifier> {
        match self {
            Self::CAP(txn) => txn.input_nullifiers(),
        }
    }
}

impl commit::Committable for EspressoTransaction {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("Es Txn Comm")
            .var_size_bytes(&canonical::serialize(self).unwrap())
            .finalize()
    }
}

impl traits::Transaction for ElaboratedTransaction {
    type NullifierSet = SetMerkleTree;
    type Hash = Commitment<EspressoTransaction>;
    type Kind = EspressoTransactionKind;

    fn cap(note: TransactionNote, proofs: Vec<SetMerkleProof>) -> Self {
        Self {
            txn: EspressoTransaction::CAP(note),
            proofs,
            memos: Default::default(),
            signature: Default::default(),
        }
    }

    fn open_viewing_memo(
        &self,
        assets: &HashMap<AssetCode, AssetDefinition>,
        keys: &HashMap<ViewerPubKey, ViewerKeyPair>,
    ) -> Result<ViewingMemoOpening, ViewingError> {
        self.txn.open_viewing_memo(assets, keys)
    }

    fn proven_nullifiers(&self) -> Vec<(Nullifier, SetMerkleProof)> {
        // reward transaction wont have nullifiers, so self.txn.input_nullifiers will return
        // empty vector
        self.txn
            .input_nullifiers()
            .into_iter()
            .zip(self.proofs.clone())
            .collect()
    }

    fn input_nullifiers(&self) -> Vec<Nullifier> {
        self.txn.input_nullifiers()
    }

    fn output_commitments(&self) -> Vec<RecordCommitment> {
        self.txn.output_commitments()
    }

    fn output_len(&self) -> usize {
        self.txn.output_len()
    }

    fn hash(&self) -> Self::Hash {
        // We only commit to the transaction note, not to the nullifier proofs. The nullifier proofs
        // are auxiliary information meant to aid in validation. They do not contribute to the
        // fundamental identity of the transaction (i.e. its effect on the ledger state) and they
        // may even change without changing the identity of the transaction; for example, when the
        // EsQS updates nullifier proofs to the latest nullifier set root hash.

        self.txn.commit()
    }

    fn kind(&self) -> Self::Kind {
        self.txn.kind()
    }

    fn set_proofs(&mut self, proofs: Vec<SetMerkleProof>) {
        self.proofs = proofs;
    }
}

impl traits::ValidationError for ValidationError {
    fn new(_msg: impl Display) -> Self {
        Self::Failed {}
    }

    fn is_bad_nullifier_proof(&self) -> bool {
        matches!(self, ValidationError::BadNullifierProof { .. })
    }
}

impl traits::Block for ElaboratedBlock {
    type Transaction = ElaboratedTransaction;
    type Error = ValidationError;

    fn new(txns: Vec<Self::Transaction>) -> Self {
        let (txns, proofs, memos, signatures): (Vec<EspressoTransaction>, Vec<_>, Vec<_>, Vec<_>) =
            txns.into_iter()
                .map(|txn| (txn.txn, txn.proofs, txn.memos, txn.signature))
                .multiunzip();
        Self {
            block: crate::state::Block(txns),
            proofs,
            memos,
            signatures,
        }
    }

    fn txns(&self) -> Vec<Self::Transaction> {
        izip!(&self.block.0, &self.proofs, &self.memos, &self.signatures)
            .map(|(txn, proofs, memos, signature)| ElaboratedTransaction {
                txn: txn.clone(),
                proofs: proofs.clone(),
                memos: memos.clone(),
                signature: signature.clone(),
            })
            .collect()
    }

    fn add_transaction(&mut self, txn: Self::Transaction) -> Result<(), ValidationError> {
        use hotshot::traits::BlockContents;
        *self = self.add_transaction_raw(&txn)?;
        Ok(())
    }
}

impl traits::Validator for ValidatorState {
    type StateCommitment = LedgerStateCommitment;
    type Block = ElaboratedBlock;

    fn now(&self) -> u64 {
        self.prev_commit_time
    }

    fn commit(&self) -> Self::StateCommitment {
        self.commit()
    }

    fn validate_and_apply(&mut self, block: Self::Block) -> Result<Vec<u64>, ValidationError> {
        Ok(self
            .validate_and_apply(self.now() + 1, block.block, block.proofs)?
            .0)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EspressoLedger;

impl Ledger for EspressoLedger {
    type Validator = ValidatorState;

    fn name() -> String {
        String::from("Espresso")
    }

    fn record_root_history() -> usize {
        ValidatorState::HISTORY_SIZE
    }

    fn merkle_height() -> u8 {
        crate::state::MERKLE_HEIGHT
    }

    fn srs() -> &'static jf_cap::proof::UniversalParam {
        &crate::universal_params::UNIVERSAL_PARAM
    }
}
