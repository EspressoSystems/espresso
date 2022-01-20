use crate::state::ValidationError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_aap::{
    keys::{AuditorKeyPair, AuditorPubKey},
    mint::MintNote,
    structs::{AssetCode, AssetDefinition, AuditData, Nullifier, RecordCommitment, RecordOpening},
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
        // Tries to get record openings corresponding to the outputs of this transaction. If
        // possible, the wallet should add any relevant openings right away when this transaction is
        // received. Otherwise, it will wait for corresponding receiver memos.
        fn output_openings(&self) -> Option<Vec<RecordOpening>> {
            // Most transactions do not have attached record openings. Override this default if the
            // implementing transaction type does.
            None
        }
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
        fn add_transaction(&mut self, txn: Self::Transaction) -> Result<(), ValidationError>;
        fn txns(&self) -> Vec<Self::Transaction>;
        fn len(&self) -> usize {
            self.txns().len()
        }
        fn is_empty(&self) -> bool {
            self.len() == 0
        }
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

    pub trait Ledger: Copy + Debug + Send + Sync {
        type Validator: traits::Validator;
        fn name() -> String;
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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Below are some implementations for generic AAP-style ledgers. These are meant to aid in the
// implementation of the ledger traits above for a particular AAP-like ledger type.
//

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
