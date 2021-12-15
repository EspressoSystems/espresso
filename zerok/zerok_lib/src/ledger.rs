use crate::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedTransaction,
    ElaboratedTransactionHash, SetMerkleProof, SetMerkleTree, ValidationError, ValidatorState,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_aap::{structs::Nullifier, TransactionNote};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::hash::Hash;

pub mod traits {
    use super::*;

    pub trait NullifierSet:
        Clone + Debug + PartialEq + Serialize + DeserializeOwned + Send + Sync
    {
        type Proof: Clone + Debug + Send + Sync;

        // Insert a collection of nullifiers into the set, given proofs that the nullifiers are not
        // already in the set. If this function fails, it returns one of the input proofs which was
        // invalid.
        fn multi_insert(
            &mut self,
            nullifiers: &[(Nullifier, Self::Proof)],
        ) -> Result<(), Self::Proof>;
    }

    pub trait TransactionKind:
        Clone + Debug + Display + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync
    {
        fn send() -> Self;
        fn receive() -> Self;
        fn mint() -> Self;
        fn freeze() -> Self;
        fn unfreeze() -> Self;
        fn unknown() -> Self;
    }

    pub trait Transaction: Clone + Debug + Serialize + DeserializeOwned + Send + Sync {
        type NullifierSet: NullifierSet;
        type Hash: Clone
            + Debug
            + Eq
            + Hash
            + Send
            + Sync
            + Serialize
            + DeserializeOwned
            + CanonicalSerialize
            + CanonicalDeserialize;
        type Kind: TransactionKind;
        fn new(
            note: TransactionNote,
            proofs: Vec<<Self::NullifierSet as NullifierSet>::Proof>,
        ) -> Self;
        fn note(&self) -> &TransactionNote;
        fn proofs(&self) -> Vec<<Self::NullifierSet as NullifierSet>::Proof>;
        fn hash(&self) -> Self::Hash;
        fn kind(&self) -> Self::Kind;

        fn set_proofs(&mut self, proofs: Vec<<Self::NullifierSet as NullifierSet>::Proof>) {
            *self = Self::new(self.note().clone(), proofs);
        }
    }

    pub trait Block: Clone + Debug + Serialize + DeserializeOwned + Send + Sync {
        type Transaction: Transaction;
        fn new(txns: Vec<Self::Transaction>) -> Self;
        fn txns(&self) -> Vec<Self::Transaction>;
    }

    pub trait Validator:
        Clone + Debug + PartialEq + Serialize + DeserializeOwned + Send + Sync
    {
        type StateCommitment: Copy + Debug + PartialEq + Serialize + DeserializeOwned + Send + Sync;
        type Block: Block;

        fn now(&self) -> u64;
        fn commit(&self) -> Self::StateCommitment;
        fn validate_and_apply(&mut self, block: Self::Block) -> Result<Vec<u64>, ValidationError>;
    }

    pub trait Ledger: Copy + Send + Sync {
        type Validator: traits::Validator;
    }
}

pub use traits::Ledger;

pub type Validator<L> = <L as Ledger>::Validator;
pub type StateCommitment<L> = <Validator<L> as traits::Validator>::StateCommitment;
pub type Block<L> = <Validator<L> as traits::Validator>::Block;
pub type Transaction<L> = <Block<L> as traits::Block>::Transaction;
pub type TransactionHash<L> = <Transaction<L> as traits::Transaction>::Hash;
pub type TransactionKind<L> = <Transaction<L> as traits::Transaction>::Kind;
pub type NullifierSet<L> = <Transaction<L> as traits::Transaction>::NullifierSet;
pub type NullifierProof<L> = <NullifierSet<L> as traits::NullifierSet>::Proof;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum AAPTransactionKind {
    Mint,
    Freeze,
    Unfreeze,
    Send,
    Receive,
    Unknown,
}

impl traits::TransactionKind for AAPTransactionKind {
    fn send() -> Self {
        Self::Send
    }

    fn receive() -> Self {
        Self::Receive
    }

    fn mint() -> Self {
        Self::Mint
    }

    fn freeze() -> Self {
        Self::Freeze
    }

    fn unfreeze() -> Self {
        Self::Unfreeze
    }

    fn unknown() -> Self {
        Self::Unknown
    }
}

impl traits::Transaction for ElaboratedTransaction {
    type NullifierSet = SetMerkleTree;
    type Hash = ElaboratedTransactionHash;
    type Kind = AAPTransactionKind;

    fn new(note: TransactionNote, proofs: Vec<SetMerkleProof>) -> Self {
        Self { txn: note, proofs }
    }

    fn note(&self) -> &TransactionNote {
        &self.txn
    }

    fn proofs(&self) -> Vec<SetMerkleProof> {
        self.proofs.clone()
    }

    fn hash(&self) -> Self::Hash {
        self.etxn_hash()
    }

    fn kind(&self) -> Self::Kind {
        match &self.txn {
            TransactionNote::Mint(_) => AAPTransactionKind::Mint,
            TransactionNote::Transfer(_) => AAPTransactionKind::Send,
            TransactionNote::Freeze(_) => AAPTransactionKind::Freeze,
        }
    }

    fn set_proofs(&mut self, proofs: Vec<SetMerkleProof>) {
        self.proofs = proofs;
    }
}

impl traits::Block for ElaboratedBlock {
    type Transaction = ElaboratedTransaction;

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
pub struct AAPLedger;

impl Ledger for AAPLedger {
    type Validator = ValidatorState;
}
