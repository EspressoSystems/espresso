use crate::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedTransaction,
    ElaboratedTransactionHash, SetMerkleProof, SetMerkleTree, ValidationError, ValidatorState,
};
use jf_aap::{
    keys::{AuditorKeyPair, AuditorPubKey},
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
            self.forget(*nullifier);
        }

        Ok(())
    }
}

impl traits::Transaction for ElaboratedTransaction {
    type NullifierSet = SetMerkleTree;
    type Hash = ElaboratedTransactionHash;
    type Kind = aap::TransactionKind;

    fn aap(note: TransactionNote, proofs: Vec<SetMerkleProof>) -> Self {
        Self { txn: note, proofs }
    }

    fn open_audit_memo(
        &self,
        assets: &HashMap<AssetCode, AssetDefinition>,
        keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    ) -> Result<AuditMemoOpening, AuditError> {
        aap::open_audit_memo(assets, keys, &self.txn)
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
        self.etxn_hash()
    }

    fn kind(&self) -> Self::Kind {
        match &self.txn {
            TransactionNote::Mint(_) => aap::TransactionKind::Mint,
            TransactionNote::Transfer(_) => aap::TransactionKind::Send,
            TransactionNote::Freeze(_) => aap::TransactionKind::Freeze,
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
        let (txns, proofs): (Vec<TransactionNote>, Vec<_>) =
            txns.into_iter().map(|txn| (txn.txn, txn.proofs)).unzip();
        Self {
            block: crate::state::Block(txns),
            proofs,
        }
    }

    fn txns(&self) -> Vec<Self::Transaction> {
        self.block
            .0
            .iter()
            .zip(&self.proofs)
            .map(|(txn, proofs)| ElaboratedTransaction {
                txn: txn.clone(),
                proofs: proofs.clone(),
            })
            .collect()
    }

    fn add_transaction(&mut self, txn: Self::Transaction) -> Result<(), ValidationError> {
        use phaselock::BlockContents;
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
        self.validate_and_apply(self.now() + 1, block.block, block.proofs)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SpectrumLedger;

impl Ledger for SpectrumLedger {
    type Validator = ValidatorState;

    fn name() -> String {
        String::from("Spectrum")
    }
}
