use crate::state::{
    state_comm::LedgerStateCommitment, ElaboratedBlock, ElaboratedTransaction,
    ElaboratedTransactionHash, SetMerkleProof, SetMerkleTree, ValidationError, ValidatorState,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_aap::{
    keys::{AuditorKeyPair, AuditorPubKey},
    mint::MintNote,
    structs::{AssetCode, AssetDefinition, AuditData, Nullifier, RecordCommitment},
    transfer::TransferNote,
    TransactionNote,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;

pub struct AuditMemoOpening {
    pub asset: AssetDefinition,
    pub inputs: Vec<AuditData>,
    pub outputs: Vec<AuditData>,
}

pub enum AuditError {
    UnauditableAsset,
    NoAuditMemos,
}

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

        fn aap(
            note: TransactionNote,
            proofs: Vec<<Self::NullifierSet as NullifierSet>::Proof>,
        ) -> Self;

        // Given a collection of asset types that the caller is able to audit, attempt to open the
        // audit memos attached to this transaction.
        //
        // `auditable_assets` should be the set of asset types which the caller can audit, indexed
        // by asset code. This determines which asset types can be audited by this method.
        // `auditor_keys` is the caller's collection of auditing key pairs, indexed by public key.
        // `auditor_keys` must contain every public key which is listed as an auditor in the policy
        // of one of the `auditable_assets`.
        fn open_audit_memo(
            &self,
            auditable_assets: &HashMap<AssetCode, AssetDefinition>,
            auditor_keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
        ) -> Result<AuditMemoOpening, AuditError>;
        fn proven_nullifiers(
            &self,
        ) -> Vec<(Nullifier, <Self::NullifierSet as NullifierSet>::Proof)>;
        fn output_commitments(&self) -> Vec<RecordCommitment>;
        fn hash(&self) -> Self::Hash;
        fn kind(&self) -> Self::Kind;

        fn set_proofs(&mut self, proofs: Vec<<Self::NullifierSet as NullifierSet>::Proof>);

        // Override with a more efficient implementation if the output length can be calculated
        // without building the vector of outputs.
        fn output_len(&self) -> usize {
            self.output_commitments().len()
        }

        fn input_nullifiers(&self) -> Vec<Nullifier> {
            self.proven_nullifiers()
                .into_iter()
                .map(|(n, _)| n)
                .collect()
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

pub fn open_aap_audit_memo(
    assets: &HashMap<AssetCode, AssetDefinition>,
    keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    txn: &TransactionNote,
) -> Result<AuditMemoOpening, AuditError> {
    match txn {
        TransactionNote::Transfer(xfr) => open_xfr_audit_memo(assets, keys, xfr),
        TransactionNote::Mint(mint) => open_mint_audit_memo(keys, mint),
        TransactionNote::Freeze(_) => Err(AuditError::NoAuditMemos),
    }
}

pub fn open_xfr_audit_memo(
    assets: &HashMap<AssetCode, AssetDefinition>,
    keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    xfr: &TransferNote,
) -> Result<AuditMemoOpening, AuditError> {
    for asset in assets.values() {
        let audit_key = &keys[asset.policy_ref().auditor_pub_key()];
        if let Ok((inputs, outputs)) = audit_key.open_transfer_audit_memo(asset, xfr) {
            return Ok(AuditMemoOpening {
                asset: asset.clone(),
                inputs,
                outputs,
            });
        }
    }
    Err(AuditError::UnauditableAsset)
}

pub fn open_mint_audit_memo(
    keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    mint: &MintNote,
) -> Result<AuditMemoOpening, AuditError> {
    keys.get(mint.mint_asset_def.policy_ref().auditor_pub_key())
        .ok_or(AuditError::UnauditableAsset)
        .map(|audit_key| {
            let output = audit_key.open_mint_audit_memo(mint).unwrap();
            AuditMemoOpening {
                asset: mint.mint_asset_def.clone(),
                inputs: vec![],
                outputs: vec![output],
            }
        })
}

impl traits::Transaction for ElaboratedTransaction {
    type NullifierSet = SetMerkleTree;
    type Hash = ElaboratedTransactionHash;
    type Kind = AAPTransactionKind;

    fn aap(note: TransactionNote, proofs: Vec<SetMerkleProof>) -> Self {
        Self { txn: note, proofs }
    }

    fn open_audit_memo(
        &self,
        assets: &HashMap<AssetCode, AssetDefinition>,
        keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    ) -> Result<AuditMemoOpening, AuditError> {
        open_aap_audit_memo(assets, keys, &self.txn)
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
