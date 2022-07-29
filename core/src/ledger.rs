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
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedTransaction, SetMerkleProof,
    SetMerkleTree, ValidationError, ValidatorState,
};
use commit::{Commitment, Committable};
use itertools::izip;
use itertools::MultiUnzip;
use jf_cap::{
    keys::{ViewerKeyPair, ViewerPubKey},
    structs::{AssetCode, AssetDefinition, Nullifier, RecordCommitment},
    TransactionNote,
};
use reef::*;
use std::collections::HashMap;
use std::fmt::Display;

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

impl traits::Transaction for ElaboratedTransaction {
    type NullifierSet = SetMerkleTree;
    type Hash = Commitment<TransactionNote>;
    type Kind = cap::TransactionKind;

    fn cap(note: TransactionNote, proofs: Vec<SetMerkleProof>) -> Self {
        Self {
            txn: note,
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
        self.txn
            .nullifiers()
            .into_iter()
            .zip(self.proofs.clone())
            .collect()
    }

    fn input_nullifiers(&self) -> Vec<Nullifier> {
        self.txn.nullifiers()
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
        match &self.txn {
            TransactionNote::Mint(_) => cap::TransactionKind::Mint,
            TransactionNote::Transfer(_) => cap::TransactionKind::Send,
            TransactionNote::Freeze(_) => cap::TransactionKind::Freeze,
        }
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
        let (txns, proofs, memos, signatures): (Vec<TransactionNote>, Vec<_>, Vec<_>, Vec<_>) =
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
