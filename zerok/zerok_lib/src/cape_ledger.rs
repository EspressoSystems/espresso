use crate::cape_state::*;
use crate::ledger::{traits::*, AAPTransactionKind};
use crate::state::ValidationError;
use crate::util::commit::{Committable, Commitment, RawCommitmentBuilder};
use generic_array::GenericArray;
use jf_txn::{
    structs::{Nullifier, RecordCommitment, RecordOpening},
    TransactionNote,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::iter::repeat;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapeNullifierSet(HashSet<Nullifier>);

impl NullifierSet for CapeNullifierSet {
    type Proof = ();

    fn multi_insert(&mut self, nullifiers: &[(Nullifier, Self::Proof)]) -> Result<(), Self::Proof> {
        for (n, _) in nullifiers {
            self.0.insert(*n);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum CapeTransactionKind {
    AAP(AAPTransactionKind),
    Burn,
    Wrap,
}

impl TransactionKind for CapeTransactionKind {
    fn send() -> Self {
        Self::AAP(AAPTransactionKind::send())
    }

    fn receive() -> Self {
        Self::AAP(AAPTransactionKind::receive())
    }

    fn mint() -> Self {
        Self::AAP(AAPTransactionKind::mint())
    }

    fn freeze() -> Self {
        Self::AAP(AAPTransactionKind::freeze())
    }

    fn unfreeze() -> Self {
        Self::AAP(AAPTransactionKind::unfreeze())
    }

    fn unknown() -> Self {
        Self::AAP(AAPTransactionKind::unknown())
    }
}

// CapeTransition models all of the objects which can transition a CAPE ledger. This includes
// transactions, submitted from users to the validator via the relayer, as well as ERC20 wrap
// operations, which are submitted directly to the contract but whose outputs end up being included
// in the next committed block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CapeTransition {
    Transaction(CapeTransaction),
    Wrap(Box<RecordOpening>),
}

impl Committable for CapeTransition {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CapeTransition")
            .var_size_bytes(&bincode::serialize(self).unwrap())
            .finalize()
    }
}

impl Transaction for CapeTransition {
    type NullifierSet = CapeNullifierSet;
    type Hash = ();
    type Kind = CapeTransactionKind;

    fn aap(note: TransactionNote, _proofs: Vec<()>) -> Self {
        Self::Transaction(CapeTransaction::AAP(note))
    }

    fn as_aap(&self) -> Option<TransactionNote> {
        match self {
            Self::Transaction(CapeTransaction::AAP(note)) => Some(note.clone()),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) =>
                // What to do in this case? Currently, this function is only used for auditing, so
                // it probably makes sense to treat burns as transfers so we get thet most
                // information possible out of auditing. But in general it may not be great to
                // identify burns and transfers.
                Some(TransactionNote::Transfer(xfr.clone())),
            _ => None,
        }
    }

    fn proven_nullifiers(&self) -> Vec<(Nullifier, ())> {
        let nullifiers = match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => txn.nullifiers(),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) => xfr.inputs_nullifiers.clone(),
            Self::Wrap(..) => Vec::new(),
        };
        nullifiers.into_iter().zip(repeat(())).collect()
    }

    fn output_commitments(&self) -> Vec<RecordCommitment> {
        match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => txn.output_commitments(),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) => xfr.output_commitments.clone(),
            Self::Wrap(ro) => vec![RecordCommitment::from(&**ro)],
        }
    }

    fn hash(&self) {}

    fn kind(&self) -> CapeTransactionKind {
        match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => match txn {
                TransactionNote::Transfer(..) => CapeTransactionKind::send(),
                TransactionNote::Mint(..) => CapeTransactionKind::mint(),
                TransactionNote::Freeze(..) => CapeTransactionKind::freeze(),
            },
            Self::Transaction(CapeTransaction::Burn { .. }) => CapeTransactionKind::Burn,
            Self::Wrap(..) => CapeTransactionKind::Wrap,
        }
    }

    fn set_proofs(&mut self, _proofs: Vec<()>) {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapeBlock(Vec<CapeTransition>);

impl Committable for CapeBlock {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CapeBlock")
            .array_field("txns", &self.0.iter().map(|x| x.commit()).collect::<Vec<_>>())
            .finalize()
    }
}

impl Block for CapeBlock {
    type Transaction = CapeTransition;

    fn new(txns: Vec<CapeTransition>) -> Self {
        Self(txns)
    }

    fn txns(&self) -> Vec<CapeTransition> {
        self.0.clone()
    }
}

// In CAPE, we don't do local lightweight validation to check the results of queries. We trust the
// results of Ethereum query services, and our local validator stores just enough information to
// satisfy the Validator interface required by the wallet. Thus, the CAPE integration for the
// Validator interface is actually more Truster than Validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapeTruster {
    // The current timestamp. The only requirement is that this is a monotonically increasing value,
    // but in this implementation it tracks the number of blocks committed.
    now: u64,
    // Number of records, for generating new UIDs.
    num_records: u64,
    // Current state commitment. This is a commitment to every block which has been committed, as
    // well as to the initial (now, num_records) state for good measure.
    commitment: GenericArray<u8, <Keccak256 as Digest>::OutputSize>,
}

impl CapeTruster {
    #[allow(dead_code)]
    fn new(now: u64, num_records: u64) -> Self {
        Self {
            now,
            num_records,
            commitment: Keccak256::new()
                .chain("initial".as_bytes())
                .chain(now.to_le_bytes())
                .chain(num_records.to_le_bytes())
                .finalize(),
        }
    }
}

impl Validator for CapeTruster {
    type StateCommitment = GenericArray<u8, <Keccak256 as Digest>::OutputSize>;
    type Block = CapeBlock;

    fn now(&self) -> u64 {
        self.now
    }

    fn commit(&self) -> Self::StateCommitment {
        self.commitment
    }

    fn validate_and_apply(&mut self, block: Self::Block) -> Result<Vec<u64>, ValidationError> {
        // We don't actually do validation here, since in this implementation we trust the query
        // service to provide only valid blocks. Instead, just compute a new commitment (by chaining
        // the new block onto the current commitment hash, with a domain separator tag).
        self.commitment = Keccak256::new()
            .chain("block".as_bytes())
            .chain(&self.commitment)
            .chain(&block.commit())
            .finalize();
        self.now += 1;

        // Compute the unique IDs of the output records of this block. The IDs for each block are
        // a consecutive range of integers starting at the previous number of records.
        let mut uids = vec![];
        let mut uid = self.num_records;
        for txn in block.0 {
            for _ in 0..txn.output_len() {
                uids.push(uid);
                uid += 1;
            }
        }
        self.num_records = uid;

        Ok(uids)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CapeLedger;

impl Ledger for CapeLedger {
    type Validator = CapeTruster;
}
