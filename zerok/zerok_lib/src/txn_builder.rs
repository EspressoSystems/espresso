use crate::util::arbitrary_wrappers::*;
use crate::{
    // key_set::KeySet,
    ledger,
    ledger::traits::{Transaction as _, Validator as _},
    ser_test,
    state::ValidatorState,
};
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use jf_txn::{
    errors::TxnApiError,
    keys::{AuditorPubKey, FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey},
    // proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier,
        ReceiverMemo, RecordCommitment, RecordOpening,
    },
    // transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness,
    MerkleTree,
    Signature,
};
use jf_utils::tagged_blob;
use ledger::*;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Index, IndexMut};

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub")]
pub enum TransactionError {
    InsufficientBalance {
        asset: AssetCode,
        required: u64,
        actual: u64,
    },
    Fragmentation {
        asset: AssetCode,
        amount: u64,
        suggested_amount: u64,
        max_records: usize,
    },
    // TooManyOutputs {
    //     asset: AssetCode,
    //     max_records: usize,
    //     num_receivers: usize,
    //     num_change_records: usize,
    // },
    // UndefinedAsset {
    //     asset: AssetCode,
    // },
    // InvalidBlock {
    //     source: ValidationError,
    // },
    // NullifierAlreadyPublished {
    //     nullifier: Nullifier,
    // },
    // TimedOut {},
    // Cancelled {},
    CryptoError {
        source: TxnApiError,
    },
    // InvalidAddress {
    //     address: UserAddress,
    // },
    InvalidAuditorKey {
        my_key: AuditorPubKey,
        asset_key: AuditorPubKey,
    },
    // InvalidFreezerKey {
    //     my_key: FreezerPubKey,
    //     asset_key: FreezerPubKey,
    // },
    // NetworkError {
    //     source: phaselock::networking::NetworkError,
    // },
    // QueryServiceError {
    //     source: crate::node::QueryServiceError,
    // },
    // ClientConfigError {
    //     source: <surf::Client as TryFrom<surf::Config>>::Error,
    // },
    // ConsensusError {
    //     #[snafu(source(false))]
    //     source: Result<phaselock::error::PhaseLockError, String>,
    // },
    // PersistenceError {
    //     source: atomic_store::error::PersistenceError,
    // },
    // IoError {
    //     source: std::io::Error,
    // },
    // BincodeError {
    //     source: bincode::Error,
    // },
    // EncryptionError {
    //     source: encryption::Error,
    // },
    // KeyError {
    //     source: argon2::Error,
    // },
    // #[snafu(display("{}", msg))]
    // Failed {
    //     msg: String,
    // },
}

#[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RecordInfo {
    pub ro: RecordOpening,
    pub uid: u64,
    pub nullifier: Nullifier,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    pub hold_until: Option<u64>,
}

impl RecordInfo {
    pub fn on_hold(&self, now: u64) -> bool {
        matches!(self.hold_until, Some(t) if t > now)
    }

    pub fn hold_until(&mut self, until: u64) {
        self.hold_until = Some(until);
    }

    pub fn unhold(&mut self) {
        self.hold_until = None;
    }
}

impl<'a> Arbitrary<'a> for RecordInfo {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            ro: u.arbitrary::<ArbitraryRecordOpening>()?.into(),
            uid: u.arbitrary()?,
            nullifier: u.arbitrary::<ArbitraryNullifier>()?.into(),
            hold_until: u.arbitrary()?,
        })
    }
}

#[ser_test(ark(false))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(from = "Vec<RecordInfo>", into = "Vec<RecordInfo>")]
pub struct RecordDatabase {
    // all records in the database, by uid
    record_info: HashMap<u64, RecordInfo>,
    // record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    // transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    // makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    asset_records: HashMap<(AssetCode, UserPubKey, FreezeFlag), BTreeSet<(u64, u64)>>,
    // record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: HashMap<Nullifier, u64>,
}

impl RecordDatabase {
    pub fn assets(&'_ self) -> impl '_ + Iterator<Item = AssetDefinition> {
        self.record_info
            .values()
            .map(|rec| rec.ro.asset_def.clone())
    }

    /// Find records which can be the input to a transaction, matching the given parameters.
    pub fn input_records<'a>(
        &'a self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        now: u64,
    ) -> impl Iterator<Item = &'a RecordInfo> {
        self.asset_records
            .get(&(*asset, owner.clone(), frozen))
            .into_iter()
            .flatten()
            .rev()
            .filter_map(move |(_, uid)| {
                let record = &self.record_info[uid];
                if record.ro.amount == 0 || record.on_hold(now) {
                    // Skip useless dummy records and records that are on hold
                    None
                } else {
                    Some(record)
                }
            })
    }
    /// Find a record with exactly the requested amount, which can be the input to a transaction,
    /// matching the given parameters.
    pub fn input_record_with_amount(
        &self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        amount: u64,
        now: u64,
    ) -> Option<&RecordInfo> {
        let unspent_records = self.asset_records.get(&(*asset, owner.clone(), frozen))?;
        let exact_matches = unspent_records.range((amount, 0)..(amount + 1, 0));
        for (match_amount, uid) in exact_matches {
            assert_eq!(*match_amount, amount);
            let record = &self.record_info[uid];
            assert_eq!(record.ro.amount, amount);
            if record.on_hold(now) {
                continue;
            }
            return Some(record);
        }

        None
    }

    pub fn record_with_nullifier(&self, nullifier: &Nullifier) -> Option<&RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get(uid)
    }

    pub fn record_with_nullifier_mut(&mut self, nullifier: &Nullifier) -> Option<&mut RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get_mut(uid)
    }

    pub fn insert(&mut self, ro: RecordOpening, uid: u64, key_pair: &UserKeyPair) {
        let nullifier = key_pair.nullify(
            ro.asset_def.policy_ref().freezer_pub_key(),
            uid,
            &RecordCommitment::from(&ro),
        );
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    pub fn insert_freezable(&mut self, ro: RecordOpening, uid: u64, key_pair: &FreezerKeyPair) {
        let nullifier = key_pair.nullify(&ro.pub_key.address(), uid, &RecordCommitment::from(&ro));
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    pub fn insert_with_nullifier(&mut self, ro: RecordOpening, uid: u64, nullifier: Nullifier) {
        self.insert_record(RecordInfo {
            ro,
            uid,
            nullifier,
            hold_until: None,
        });
    }

    pub fn insert_record(&mut self, rec: RecordInfo) {
        self.asset_records
            .entry((
                rec.ro.asset_def.code,
                rec.ro.pub_key.clone(),
                rec.ro.freeze_flag,
            ))
            .or_insert_with(BTreeSet::new)
            .insert((rec.ro.amount, rec.uid));
        self.nullifier_records.insert(rec.nullifier, rec.uid);
        self.record_info.insert(rec.uid, rec);
    }

    pub fn remove_by_nullifier(&mut self, nullifier: Nullifier) -> Option<RecordInfo> {
        self.nullifier_records.remove(&nullifier).map(|uid| {
            let record = self.record_info.remove(&uid).unwrap();

            // Remove the record from `asset_records`, and if the sub-collection it was in becomes
            // empty, remove the whole collection.
            let asset_key = &(
                record.ro.asset_def.code,
                record.ro.pub_key.clone(),
                record.ro.freeze_flag,
            );
            let asset_records = self.asset_records.get_mut(asset_key).unwrap();
            asset_records.remove(&(record.ro.amount, uid));
            if asset_records.is_empty() {
                self.asset_records.remove(asset_key);
            }

            record
        })
    }
}

impl Index<Nullifier> for RecordDatabase {
    type Output = RecordInfo;
    fn index(&self, index: Nullifier) -> &RecordInfo {
        self.record_with_nullifier(&index).unwrap()
    }
}

impl IndexMut<Nullifier> for RecordDatabase {
    fn index_mut(&mut self, index: Nullifier) -> &mut RecordInfo {
        self.record_with_nullifier_mut(&index).unwrap()
    }
}

impl FromIterator<RecordInfo> for RecordDatabase {
    fn from_iter<T: IntoIterator<Item = RecordInfo>>(iter: T) -> Self {
        let mut db = Self::default();
        for info in iter {
            db.insert_record(info)
        }
        db
    }
}

impl From<Vec<RecordInfo>> for RecordDatabase {
    fn from(records: Vec<RecordInfo>) -> Self {
        records.into_iter().collect()
    }
}

impl From<RecordDatabase> for Vec<RecordInfo> {
    fn from(db: RecordDatabase) -> Self {
        db.record_info.into_values().collect()
    }
}

impl<'a> Arbitrary<'a> for RecordDatabase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<Vec<RecordInfo>>()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    AwaitingMemos,
    Retired,
    Rejected,
    Unknown,
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::AwaitingMemos => write!(f, "accepted, waiting for owner memos"),
            Self::Retired => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl TransactionStatus {
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Retired | Self::Rejected)
    }

    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[ser_test(arbitrary, types(AAPLedger))]
#[tagged_blob("TXN")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TransactionReceipt<L: Ledger = AAPLedger> {
    pub uid: TransactionUID<L>,
    pub fee_nullifier: Nullifier,
    pub submitter: UserAddress,
}

impl<L: Ledger> PartialEq<Self> for TransactionReceipt<L> {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid
            && self.fee_nullifier == other.fee_nullifier
            && self.submitter == other.submitter
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionReceipt<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            uid: u.arbitrary()?,
            fee_nullifier: u.arbitrary::<ArbitraryNullifier>()?.into(),
            submitter: u.arbitrary::<ArbitraryUserAddress>()?.into(),
        })
    }
}

#[ser_test(arbitrary, types(AAPLedger), ark(false))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct PendingTransaction<L: Ledger> {
    pub receiver_memos: Vec<ReceiverMemo>,
    pub signature: Signature,
    pub freeze_outputs: Vec<RecordOpening>,
    pub timeout: u64,
    pub uid: TransactionUID<L>,
    pub hash: TransactionHash<L>,
}

impl<L: Ledger> PartialEq<Self> for PendingTransaction<L> {
    fn eq(&self, other: &Self) -> bool {
        self.receiver_memos == other.receiver_memos
            && self.signature == other.signature
            && self.freeze_outputs == other.freeze_outputs
            && self.timeout == other.timeout
            && self.uid == other.uid
            && self.hash == other.hash
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for PendingTransaction<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let memos = std::iter::once(u.arbitrary())
            .chain(u.arbitrary_iter::<ArbitraryReceiverMemo>()?)
            .map(|a| Ok(a?.into()))
            .collect::<Result<Vec<_>, _>>()?;
        let key = u.arbitrary::<ArbitraryKeyPair>()?.into();
        let signature = sign_receiver_memos(&key, &memos).unwrap();
        Ok(Self {
            receiver_memos: memos,
            signature,
            freeze_outputs: u
                .arbitrary_iter::<ArbitraryRecordOpening>()?
                .map(|a| Ok(a?.into()))
                .collect::<Result<_, _>>()?,
            timeout: u.arbitrary()?,
            uid: u.arbitrary()?,
            hash: u.arbitrary()?,
        })
    }
}

#[ser_test(arbitrary, types(AAPLedger), ark(false))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct TransactionAwaitingMemos<L: Ledger> {
    // The uid of this transaction.
    uid: TransactionUID<L>,
    // The uids of the outputs of this transaction for which memos have not yet been posted.
    pending_uids: HashSet<u64>,
}

impl<L: Ledger> PartialEq<Self> for TransactionAwaitingMemos<L> {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid && self.pending_uids == other.pending_uids
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionAwaitingMemos<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            uid: u.arbitrary()?,
            pending_uids: u.arbitrary()?,
        })
    }
}

// Serialization intermediate for TransactionDatabase, which eliminates the redundancy of the
// in-memory indices in TransactionDatabase.
#[ser_test(arbitrary, types(AAPLedger), ark(false))]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(bound = "")]
struct TransactionStorage<L: Ledger> {
    pending_txns: Vec<PendingTransaction<L>>,
    txns_awaiting_memos: Vec<TransactionAwaitingMemos<L>>,
}

impl<L: Ledger> PartialEq<Self> for TransactionStorage<L> {
    fn eq(&self, other: &Self) -> bool {
        self.pending_txns == other.pending_txns
            && self.txns_awaiting_memos == other.txns_awaiting_memos
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionStorage<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            pending_txns: u.arbitrary()?,
            txns_awaiting_memos: u.arbitrary()?,
        })
    }
}

#[ser_test(arbitrary, types(AAPLedger))]
#[tagged_blob("TXUID")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TransactionUID<L: Ledger>(pub TransactionHash<L>);

impl<L: Ledger> PartialEq<TransactionUID<L>> for TransactionUID<L> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<L: Ledger> Eq for TransactionUID<L> {}

impl<L: Ledger> Hash for TransactionUID<L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0, state)
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionUID<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

#[ser_test(arbitrary, types(AAPLedger), ark(false))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "TransactionStorage<L>", into = "TransactionStorage<L>")]
#[serde(bound = "")]
pub struct TransactionDatabase<L: Ledger> {
    // The base storage. Every in-flight transaction is either pending or accepted and awaiting
    // memos. All the auxiliary data in this database is just an index into one of these two tables.
    pending_txns: HashMap<TransactionUID<L>, PendingTransaction<L>>,
    txns_awaiting_memos: HashMap<TransactionUID<L>, TransactionAwaitingMemos<L>>,

    txn_uids: HashMap<TransactionHash<L>, TransactionUID<L>>,
    expiring_txns: BTreeMap<u64, HashSet<TransactionUID<L>>>,
    uids_awaiting_memos: HashMap<u64, TransactionUID<L>>,
}

impl<L: Ledger> TransactionDatabase<L> {
    pub fn status(&self, uid: &TransactionUID<L>) -> TransactionStatus {
        if self.pending_txns.contains_key(uid) {
            TransactionStatus::Pending
        } else if self.txns_awaiting_memos.contains_key(uid) {
            TransactionStatus::AwaitingMemos
        } else {
            TransactionStatus::Unknown
        }
    }

    // Inform the database that we have received memos for the given record UIDs. Return a list of
    // the transactions that are completed as a result.
    pub fn received_memos(&mut self, uids: impl Iterator<Item = u64>) -> Vec<TransactionUID<L>> {
        let mut completed = Vec::new();
        for uid in uids {
            if let Some(txn_uid) = self.uids_awaiting_memos.remove(&uid) {
                let txn = self.txns_awaiting_memos.get_mut(&txn_uid).unwrap();
                txn.pending_uids.remove(&uid);
                if txn.pending_uids.is_empty() {
                    self.txns_awaiting_memos.remove(&txn_uid);
                    completed.push(txn_uid);
                }
            }
        }
        completed
    }

    pub fn await_memos(
        &mut self,
        uid: TransactionUID<L>,
        pending_uids: impl IntoIterator<Item = u64>,
    ) {
        self.insert_awaiting_memos(TransactionAwaitingMemos {
            uid,
            pending_uids: pending_uids.into_iter().collect(),
        })
    }

    pub fn remove_pending(&mut self, hash: &TransactionHash<L>) -> Option<PendingTransaction<L>> {
        self.txn_uids.remove(hash).and_then(|uid| {
            let pending = self.pending_txns.remove(&uid);
            if let Some(pending) = &pending {
                if let Some(expiring) = self.expiring_txns.get_mut(&pending.timeout) {
                    expiring.remove(&uid);
                    if expiring.is_empty() {
                        self.expiring_txns.remove(&pending.timeout);
                    }
                }
            }
            pending
        })
    }

    pub fn remove_expired(&mut self, now: u64) -> Vec<PendingTransaction<L>> {
        #[cfg(any(test, debug_assertions))]
        {
            if let Some(earliest_timeout) = self.expiring_txns.keys().next() {
                // Transactions expiring before now should already have been removed from the
                // expiring_txns set, because we clear expired transactions every time we step the
                // validator state.
                assert!(*earliest_timeout >= now);
            }
        }

        self.expiring_txns
            .remove(&now)
            .into_iter()
            .flatten()
            .map(|uid| {
                let pending = self.pending_txns.remove(&uid).unwrap();
                self.txn_uids.remove(&pending.hash);
                pending
            })
            .collect()
    }

    pub fn insert_pending(&mut self, txn: PendingTransaction<L>) {
        self.txn_uids.insert(txn.hash.clone(), txn.uid.clone());
        self.expiring_txns
            .entry(txn.timeout)
            .or_insert_with(HashSet::default)
            .insert(txn.uid.clone());
        self.pending_txns.insert(txn.uid.clone(), txn);
    }

    pub fn insert_awaiting_memos(&mut self, txn: TransactionAwaitingMemos<L>) {
        for uid in &txn.pending_uids {
            self.uids_awaiting_memos.insert(*uid, txn.uid.clone());
        }
        self.txns_awaiting_memos.insert(txn.uid.clone(), txn);
    }
}

impl<L: Ledger> Default for TransactionDatabase<L> {
    fn default() -> Self {
        Self {
            pending_txns: Default::default(),
            txns_awaiting_memos: Default::default(),
            txn_uids: Default::default(),
            expiring_txns: Default::default(),
            uids_awaiting_memos: Default::default(),
        }
    }
}

impl<L: Ledger> PartialEq<TransactionDatabase<L>> for TransactionDatabase<L> {
    fn eq(&self, other: &TransactionDatabase<L>) -> bool {
        self.pending_txns == other.pending_txns
            && self.txns_awaiting_memos == other.txns_awaiting_memos
            && self.txn_uids == other.txn_uids
            && self.expiring_txns == other.expiring_txns
            && self.uids_awaiting_memos == other.uids_awaiting_memos
    }
}

impl<L: Ledger> From<TransactionStorage<L>> for TransactionDatabase<L> {
    fn from(txns: TransactionStorage<L>) -> Self {
        let mut db = Self::default();
        for txn in txns.pending_txns {
            db.insert_pending(txn);
        }
        for txn in txns.txns_awaiting_memos {
            db.insert_awaiting_memos(txn);
        }
        db
    }
}

impl<L: Ledger> From<TransactionDatabase<L>> for TransactionStorage<L> {
    fn from(db: TransactionDatabase<L>) -> Self {
        Self {
            pending_txns: db.pending_txns.into_values().collect(),
            txns_awaiting_memos: db.txns_awaiting_memos.into_values().collect(),
        }
    }
}

impl<'a, L: Ledger> Arbitrary<'a> for TransactionDatabase<L>
where
    TransactionHash<L>: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<TransactionStorage<L>>()?))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MintInfo {
    pub seed: AssetCodeSeed,
    pub desc: Vec<u8>,
}

impl MintInfo {
    pub fn new(seed: AssetCodeSeed, desc: Vec<u8>) -> Self {
        Self { seed, desc }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AssetInfo {
    pub asset: AssetDefinition,
    pub mint_info: Option<MintInfo>,
}

impl AssetInfo {
    pub fn new(asset: AssetDefinition, mint_info: MintInfo) -> Self {
        Self {
            asset,
            mint_info: Some(mint_info),
        }
    }
}

impl From<AssetDefinition> for AssetInfo {
    fn from(asset: AssetDefinition) -> Self {
        Self {
            asset,
            mint_info: None,
        }
    }
}

// how long (in number of validator states) a record used as an input to an unconfirmed transaction
// should be kept on hold before the transaction is considered timed out. This should be the number
// of validator states after which the transaction's proof can no longer be verified.
pub const RECORD_HOLD_TIME: u64 = ValidatorState::RECORD_ROOT_HISTORY_SIZE as u64;
// (block_id, txn_id, [(uid, remember)])
pub type CommittedTxn<'a> = (u64, u64, &'a mut [(u64, bool)]);

#[derive(Debug, Clone)]
pub struct TransactionState<L: Ledger = AAPLedger> {
    // sequence number of the last event processed
    pub now: u64,
    // validator
    pub validator: Validator<L>,
    // all records we care about, including records we own, records we have audited, and records we
    // can freeze or unfreeze
    pub records: RecordDatabase,
    // sparse nullifier set Merkle tree mirrored from validators
    pub nullifiers: NullifierSet<L>,
    // sparse record Merkle tree mirrored from validators
    pub record_mt: MerkleTree,
    // when forgetting the last leaf in the tree, the forget operation will be deferred until a new
    // leaf is appended, using this field, because MerkleTree doesn't allow forgetting the last leaf.
    pub merkle_leaf_to_forget: Option<u64>,
    // set of pending transactions
    pub transactions: TransactionDatabase<L>,
}

impl<L: Ledger> TransactionState<L> {
    pub fn balance(&self, asset: &AssetCode, pub_key: &UserPubKey, frozen: FreezeFlag) -> u64 {
        self.records
            .input_records(asset, pub_key, frozen, self.validator.now())
            .map(|record| record.ro.amount)
            .sum()
    }

    pub fn assets(
        &self,
        auditable_assets: &HashMap<AssetCode, AssetDefinition>,
        defined_assets: &HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
    ) -> HashMap<AssetCode, AssetInfo> {
        // Get the asset definitions of each record we own.
        let mut assets: HashMap<AssetCode, AssetInfo> = self
            .records
            .assets()
            .map(|def| (def.code, AssetInfo::from(def)))
            .collect();
        // Add any assets that we know about through auditing.
        for (code, def) in auditable_assets {
            assets.insert(*code, AssetInfo::from(def.clone()));
        }
        // Add the minting information (seed and description) for each asset we've defined.
        for (code, (def, seed, desc)) in defined_assets {
            assets.insert(
                *code,
                AssetInfo::new(def.clone(), MintInfo::new(*seed, desc.clone())),
            );
        }
        assets
    }

    pub fn clear_expired_transactions(&mut self) -> Vec<TransactionUID<L>> {
        self.transactions
            .remove_expired(self.validator.now())
            .into_iter()
            .map(|txn| txn.uid)
            .collect()
    }

    pub fn define_asset<'b>(
        &'b mut self,
        rng: &mut ChaChaRng,
        description: &'b [u8],
        policy: AssetPolicy,
    ) -> Result<(AssetCodeSeed, AssetCode, AssetDefinition), TransactionError> {
        let seed = AssetCodeSeed::generate(rng);
        let code = AssetCode::new(seed, description);
        let asset_definition = AssetDefinition::new(code, policy).context(CryptoError)?;
        Ok((seed, code, asset_definition))
    }

    pub fn add_pending_transaction(
        &mut self,
        txn: &Transaction<L>,
        receiver_memos: Vec<ReceiverMemo>,
        signature: Signature,
        freeze_outputs: Vec<RecordOpening>,
        uid: Option<TransactionUID<L>>,
        user_address: UserAddress,
    ) -> TransactionReceipt<L> {
        let now = self.validator.now();
        let timeout = now + RECORD_HOLD_TIME;
        let hash = txn.hash();
        let uid = uid.unwrap_or_else(|| TransactionUID(hash.clone()));

        for nullifier in txn.note().nullifiers() {
            // hold the record corresponding to this nullifier until the transaction is committed,
            // rejected, or expired.
            if let Some(record) = self.records.record_with_nullifier_mut(&nullifier) {
                assert!(!record.on_hold(now));
                record.hold_until(timeout);
            }
        }

        // Add the transaction to `transactions`.
        let pending = PendingTransaction {
            receiver_memos,
            signature,
            timeout,
            freeze_outputs,
            uid: uid.clone(),
            hash,
        };
        self.transactions.insert_pending(pending);

        TransactionReceipt {
            uid,
            fee_nullifier: txn.note().nullifiers()[0],
            submitter: user_address,
        }
    }

    pub fn clear_pending_transaction<'t>(
        &mut self,
        txn: &Transaction<L>,
        res: &Option<CommittedTxn<'t>>,
    ) -> Option<PendingTransaction<L>> {
        let now = self.validator.now();

        // Remove the transaction from pending transaction data structures.
        let txn_hash = txn.hash();
        let pending = self.transactions.remove_pending(&txn_hash);

        for nullifier in txn.note().nullifiers() {
            if let Some(record) = self.records.record_with_nullifier_mut(&nullifier) {
                if pending.is_some() {
                    // If we started this transaction, all of its inputs should have been on hold,
                    // to preserve the invariant that all input nullifiers of all pending
                    // transactions are on hold.
                    assert!(record.on_hold(now));

                    if res.is_none() {
                        // If the transaction was not accepted for any reason, its nullifiers have
                        // not been spent, so remove the hold we placed on them.
                        record.unhold();
                    }
                } else {
                    // This isn't even our transaction.
                    assert!(!record.on_hold(now));
                }
            }
        }

        pending
    }

    #[allow(clippy::type_complexity)]
    pub fn find_records(
        &self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        amount: u64,
        now: u64,
        max_records: Option<usize>,
    ) -> Result<(Vec<(RecordOpening, u64)>, u64), TransactionError> {
        // If we have a record with the exact size required, use it to avoid fragmenting big records
        // into smaller change records.
        if let Some(record) = self
            .records
            .input_record_with_amount(asset, owner, frozen, amount, now)
        {
            return Ok((vec![(record.ro.clone(), record.uid)], 0));
        }

        // Take the biggest records we have until they exceed the required amount, as a heuristic to
        // try and get the biggest possible change record. This is a simple algorithm that
        // guarantees we will always return the minimum number of blocks, and thus we always succeed
        // in making a transaction if it is possible to do so within the allowed number of inputs.
        //
        // This algorithm is not optimal, though. For instance, it's possible we might be able to
        // make exact change using combinations of larger and smaller blocks. We can replace this
        // with something more sophisticated later.
        let mut result = vec![];
        let mut current_amount = 0u64;
        for record in self.records.input_records(asset, owner, frozen, now) {
            if let Some(max_records) = max_records {
                if result.len() >= max_records {
                    // Too much fragmentation: we can't make the required amount using few enough
                    // records. This should be less likely once we implement a better allocation
                    // strategy (or, any allocation strategy).
                    //
                    // In this case, we could either simply return an error, or we could
                    // automatically generate a merge transaction to defragment our assets.
                    // Automatically merging assets would implicitly incur extra transaction fees,
                    // so for now we do the simple, uncontroversial thing and error out.
                    return Err(TransactionError::Fragmentation {
                        asset: *asset,
                        amount,
                        suggested_amount: current_amount,
                        max_records,
                    });
                }
            }
            current_amount += record.ro.amount;
            result.push((record.ro.clone(), record.uid));
            if current_amount >= amount {
                return Ok((result, current_amount - amount));
            }
        }

        Err(TransactionError::InsufficientBalance {
            asset: *asset,
            required: amount,
            actual: current_amount,
        })
    }

    pub fn get_merkle_proof(&self, leaf: u64) -> AccMemberWitness {
        // The wallet never needs a Merkle proof that isn't guaranteed to already be in the Merkle
        // tree, so this unwrap() should never fail.
        AccMemberWitness::lookup_from_tree(&self.record_mt, leaf)
            .expect_ok()
            .unwrap()
            .1
    }

    // // Find a proving key large enough to prove the given transaction, returning the number of dummy
    // // inputs needed to pad the transaction.
    // //
    // // `proving_keys` should always be `&self.proving_key`. This is a non-member function in order
    // // to prove to the compiler that the result only borrows from `&self.proving_key`, not all of
    // // `&self`.
    // #[allow(clippy::too_many_arguments)]
    // fn xfr_proving_key<'k>(
    //     rng: &mut ChaChaRng,
    //     me: UserPubKey,
    //     proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
    //     asset: &AssetDefinition,
    //     inputs: &mut Vec<TransferNoteInput<'k>>,
    //     outputs: &mut Vec<RecordOpening>,
    //     change_record: bool,
    // ) -> Result<(&'k TransferProvingKey<'a>, usize), TransactionError> {
    //     let total_output_amount = outputs.iter().map(|ro| ro.amount).sum();
    //     // non-native transfers have an extra fee input, which is not included in `inputs`.
    //     let fee_inputs = if *asset == AssetDefinition::native() {
    //         0
    //     } else {
    //         1
    //     };
    //     // both native and non-native transfers have an extra fee change output which is
    //     // automatically generated and not included in `outputs`.
    //     let fee_outputs = 1;

    //     let num_inputs = inputs.len() + fee_inputs;
    //     let num_outputs = outputs.len() + fee_outputs;
    //     let (key_inputs, key_outputs, proving_key) = proving_keys
    //         .best_fit_key(num_inputs, num_outputs)
    //         .map_err(|(max_inputs, max_outputs)| {
    //             if max_outputs >= num_outputs {
    //                 // If there is a key that can fit the correct number of outputs had we only
    //                 // managed to find fewer inputs, call this a fragmentation error.
    //                 TransactionError::Fragmentation {
    //                     asset: asset.code,
    //                     amount: total_output_amount,
    //                     suggested_amount: inputs
    //                         .iter()
    //                         .take(max_inputs - fee_inputs)
    //                         .map(|input| input.ro.amount)
    //                         .sum(),
    //                     max_records: max_inputs,
    //                 }
    //             } else {
    //                 // Otherwise, we just have too many outputs for any of our available keys. There
    //                 // is nothing we can do about that on the wallet side.
    //                 TransactionError::TooManyOutputs {
    //                     asset: asset.code,
    //                     max_records: max_outputs,
    //                     num_receivers: outputs.len() - change_record as usize,
    //                     num_change_records: 1 + change_record as usize,
    //                 }
    //             }
    //         })?;
    //     assert!(num_inputs <= key_inputs);
    //     assert!(num_outputs <= key_outputs);

    //     if num_outputs < key_outputs {
    //         // pad with dummy (0-amount) outputs,leaving room for the fee change output
    //         loop {
    //             outputs.push(RecordOpening::new(
    //                 rng,
    //                 0,
    //                 asset.clone(),
    //                 me.clone(),
    //                 FreezeFlag::Unfrozen,
    //             ));
    //             if outputs.len() >= key_outputs - fee_outputs {
    //                 break;
    //             }
    //         }
    //     }

    //     // Return the required number of dummy inputs. We can't easily create the dummy inputs here,
    //     // because it requires creating a new dummy key pair and then borrowing from the key pair to
    //     // form the transfer input, so the key pair must be owned by the caller.
    //     let dummy_inputs = key_inputs.saturating_sub(num_inputs);
    //     Ok((proving_key, dummy_inputs))
    // }

    // async fn transfer_native(
    //     &mut self,
    //     owner_keypair: UserKeyPair,
    //     receivers: &[(UserPubKey, u64)],
    //     fee: u64,
    //     now: u64,
    //     rng: &mut ChaChaRng,
    // ) -> Result<TransactionReceipt<L>, TransactionError> {
    //     let total_output_amount: u64 =
    //         receivers.iter().fold(0, |sum, (_, amount)| sum + *amount) + fee;

    //     // find input records which account for at least the total amount, and possibly some change.
    //     let (input_records, _change) = self.find_records(
    //         &AssetCode::native(),
    //         &owner_keypair.pub_key(),
    //         FreezeFlag::Unfrozen,
    //         total_output_amount,
    //         now,
    //         None,
    //     )?;

    //     // prepare inputs
    //     let mut inputs = vec![];
    //     for (ro, uid) in input_records {
    //         let acc_member_witness = self.get_merkle_proof(uid);
    //         inputs.push(TransferNoteInput {
    //             ro,
    //             acc_member_witness,
    //             owner_keypair,
    //             cred: None,
    //         });
    //     }

    //     // prepare outputs, excluding fee change (which will be automatically generated)
    //     let mut outputs = vec![];
    //     for (pub_key, amount) in receivers {
    //         outputs.push(RecordOpening::new(
    //             &mut rng,
    //             *amount,
    //             AssetDefinition::native(),
    //             pub_key.clone(),
    //             FreezeFlag::Unfrozen,
    //         ));
    //     }

    //     // find a proving key which can handle this transaction size
    //     let (proving_key, dummy_inputs) = Self::xfr_proving_key(
    //         &mut rng,
    //         self.immutable_keys.key_pair.pub_key(),
    //         &self.proving_keys.xfr,
    //         &AssetDefinition::native(),
    //         &mut inputs,
    //         &mut outputs,
    //         false,
    //     )?;
    //     // pad with dummy inputs if necessary
    //     let rng = &mut session.rng;
    //     let dummy_inputs = (0..dummy_inputs)
    //         .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
    //         .collect::<Vec<_>>();
    //     for (ro, owner_keypair) in &dummy_inputs {
    //         let dummy_input = TransferNoteInput {
    //             ro: ro.clone(),
    //             acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
    //             owner_keypair,
    //             cred: None,
    //         };
    //         inputs.push(dummy_input);
    //     }

    //     // generate transfer note and receiver memos
    //     let (note, kp, fee_change_ro) = TransferNote::generate_native(
    //         &mut session.rng,
    //         inputs,
    //         &outputs,
    //         fee,
    //         UNEXPIRED_VALID_UNTIL,
    //         proving_key,
    //     )
    //     .context(CryptoError)?;

    //     let outputs: Vec<_> = vec![fee_change_ro]
    //         .into_iter()
    //         .chain(outputs.into_iter())
    //         .collect();

    //     let recv_memos: Vec<_> = outputs
    //         .iter()
    //         .map(|ro| ReceiverMemo::from_ro(&mut session.rng, ro, &[]))
    //         .collect::<Result<Vec<_>, _>>()
    //         .unwrap();
    //     let sig = sign_receiver_memos(&kp, &recv_memos).context(CryptoError)?;
    //     (note, recv_memos, sig)
    // }

    // async fn transfer_non_native(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     asset: &AssetCode,
    //     receivers: &[(UserPubKey, u64)],
    //     fee: u64,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     assert_ne!(
    //         *asset,
    //         AssetCode::native(),
    //         "call `transfer_native()` instead"
    //     );
    //     let total_output_amount: u64 = receivers.iter().fold(0, |sum, (_, amount)| sum + *amount);

    //     // find input records of the asset type to spend (this does not include the fee input)
    //     let (input_records, change) = self.find_records(
    //         asset,
    //         &self.pub_key(),
    //         FreezeFlag::Unfrozen,
    //         total_output_amount,
    //         None,
    //     )?;
    //     let asset = input_records[0].0.asset_def.clone();

    //     // prepare inputs
    //     let mut inputs = vec![];
    //     for (ro, uid) in input_records.into_iter() {
    //         let witness = self.get_merkle_proof(uid);
    //         inputs.push(TransferNoteInput {
    //             ro,
    //             acc_member_witness: witness,
    //             owner_keypair: &self.immutable_keys.key_pair,
    //             cred: None, // TODO support credentials
    //         })
    //     }

    //     // prepare outputs, excluding fee change (which will be automatically generated)
    //     let mut outputs = vec![];
    //     for (pub_key, amount) in receivers {
    //         outputs.push(RecordOpening::new(
    //             &mut session.rng,
    //             *amount,
    //             asset.clone(),
    //             pub_key.clone(),
    //             FreezeFlag::Unfrozen,
    //         ));
    //     }
    //     // change in the asset type being transfered (not fee change)
    //     if change > 0 {
    //         let me = self.pub_key();
    //         let change_ro = RecordOpening::new(
    //             &mut session.rng,
    //             change,
    //             asset.clone(),
    //             me,
    //             FreezeFlag::Unfrozen,
    //         );
    //         outputs.push(change_ro);
    //     }

    //     let (fee_ro, fee_uid) = self.find_native_record_for_fee(fee)?;
    //     let fee_input = FeeInput {
    //         ro: fee_ro,
    //         acc_member_witness: self.get_merkle_proof(fee_uid),
    //         owner_keypair: &self.immutable_keys.key_pair,
    //     };

    //     // find a proving key which can handle this transaction size
    //     let (proving_key, dummy_inputs) = Self::xfr_proving_key(
    //         &mut session.rng,
    //         self.immutable_keys.key_pair.pub_key(),
    //         &self.proving_keys.xfr,
    //         &asset,
    //         &mut inputs,
    //         &mut outputs,
    //         change > 0,
    //     )?;
    //     // pad with dummy inputs if necessary
    //     let rng = &mut session.rng;
    //     let dummy_inputs = (0..dummy_inputs)
    //         .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
    //         .collect::<Vec<_>>();
    //     for (ro, owner_keypair) in &dummy_inputs {
    //         let dummy_input = TransferNoteInput {
    //             ro: ro.clone(),
    //             acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
    //             owner_keypair,
    //             cred: None,
    //         };
    //         inputs.push(dummy_input);
    //     }

    //     // generate transfer note and receiver memos
    //     let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut session.rng, fee_input, fee).unwrap();
    //     let (note, sig_key) = TransferNote::generate_non_native(
    //         &mut session.rng,
    //         inputs,
    //         &outputs,
    //         fee_info,
    //         UNEXPIRED_VALID_UNTIL,
    //         proving_key,
    //         vec![],
    //     )
    //     .context(CryptoError)?;
    //     let recv_memos = vec![&fee_out_rec]
    //         .into_iter()
    //         .chain(outputs.iter())
    //         .map(|r| ReceiverMemo::from_ro(&mut session.rng, r, &[]))
    //         .collect::<Result<Vec<_>, _>>()
    //         .unwrap();
    //     let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
    //     self.submit_transaction(
    //         session,
    //         TransactionNote::Transfer(Box::new(note)),
    //         recv_memos,
    //         sig,
    //         vec![],
    //     )
    //     .await
    // }

    // pub async fn transfer(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     asset: &AssetCode,
    //     receivers: &[(UserAddress, u64)],
    //     fee: u64,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     let receivers = iter(receivers)
    //         .then(|(addr, amt)| {
    //             let session = &session;
    //             async move { Ok((session.backend.get_public_key(addr).await?, *amt)) }
    //         })
    //         .try_collect::<Vec<_>>()
    //         .await?;

    //     if *asset == AssetCode::native() {
    //         self.transfer_native(session, &receivers, fee).await
    //     } else {
    //         self.transfer_non_native(session, asset, &receivers, fee)
    //             .await
    //     }
    // }

    // pub async fn mint(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     fee: u64,
    //     asset_code: &AssetCode,
    //     amount: u64,
    //     owner: UserAddress,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     let (fee_ro, uid) = self.find_native_record_for_fee(fee)?;
    //     let acc_member_witness = self.get_merkle_proof(uid);
    //     let (asset_def, seed, asset_description) = self
    //         .defined_assets
    //         .get(asset_code)
    //         .ok_or(WalletError::UndefinedAsset { asset: *asset_code })?;
    //     let mint_record = RecordOpening {
    //         amount,
    //         asset_def: asset_def.clone(),
    //         pub_key: session.backend.get_public_key(&owner).await?,
    //         freeze_flag: FreezeFlag::Unfrozen,
    //         blind: BlindFactor::rand(&mut session.rng),
    //     };

    //     let fee_input = FeeInput {
    //         ro: fee_ro,
    //         acc_member_witness,
    //         owner_keypair: &self.immutable_keys.key_pair,
    //     };
    //     let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut session.rng, fee_input, fee).unwrap();
    //     let rng = &mut session.rng;
    //     let recv_memos = vec![&fee_out_rec, &mint_record]
    //         .into_iter()
    //         .map(|r| ReceiverMemo::from_ro(rng, r, &[]))
    //         .collect::<Result<Vec<_>, _>>()
    //         .unwrap();
    //     let (mint_note, sig_key) = jf_txn::mint::MintNote::generate(
    //         &mut session.rng,
    //         mint_record,
    //         *seed,
    //         asset_description.as_slice(),
    //         fee_info,
    //         &self.proving_keys.mint,
    //     )
    //     .context(CryptoError)?;
    //     let signature = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
    //     self.submit_transaction(
    //         session,
    //         TransactionNote::Mint(Box::new(mint_note)),
    //         recv_memos,
    //         signature,
    //         vec![],
    //     )
    //     .await
    // }

    // /// Freeze at least `amount` of a particular asset owned by a given user.
    // ///
    // /// In order to freeze an asset, this wallet must be an auditor of that asset type, and it must
    // /// have observed enough transactions to determine that the target user owns at least `amount`
    // /// of that asset.
    // ///
    // /// Freeze transactions do not currently support change, so the amount frozen will be at least
    // /// `amount` but might be more, depending on the distribution of the freezable records we have
    // /// for the target user.
    // ///
    // /// Some of these restrictions can be rolled back in the future:
    // /// * An API can be provided for freezing without being an auditor, if a freezable record
    // ///   opening is provided to us out of band by an auditor.
    // /// * `freeze` uses the same allocation scheme for input records as transfers, which tries to
    // ///   minimize fragmentation. But freeze transactions do not increase fragmentation because they
    // ///   have no change output, so we could use a different allocation scheme that tries to
    // ///   minimize change, which would limit the amount we can over-freeze, and would guarantee that
    // ///   we freeze the exact amount if it is possible to make exact change with the freezable
    // ///   records we have.
    // pub async fn freeze(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     fee: u64,
    //     asset: &AssetDefinition,
    //     amount: u64,
    //     owner: UserAddress,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Frozen)
    //         .await
    // }

    // /// Unfreeze at least `amount` of a particular asset owned by a given user.
    // ///
    // /// This wallet must have previously been used to freeze (without an intervening `unfreeze`) at
    // /// least `amount` of the given asset for the given user.
    // ///
    // /// Similar restrictions on change apply as for `freeze`.
    // pub async fn unfreeze(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     fee: u64,
    //     asset: &AssetDefinition,
    //     amount: u64,
    //     owner: UserAddress,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Unfrozen)
    //         .await
    // }

    // async fn freeze_or_unfreeze(
    //     &mut self,
    //     session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
    //     fee: u64,
    //     asset: &AssetDefinition,
    //     amount: u64,
    //     owner: UserAddress,
    //     outputs_frozen: FreezeFlag,
    // ) -> Result<TransactionReceipt<L>, WalletError> {
    //     let my_key = self.immutable_keys.freezer_key_pair.pub_key();
    //     let asset_key = asset.policy_ref().freezer_pub_key();
    //     if my_key != *asset_key {
    //         return Err(WalletError::InvalidFreezerKey {
    //             my_key,
    //             asset_key: asset_key.clone(),
    //         });
    //     }

    //     let owner = session.backend.get_public_key(&owner).await?;

    //     // find input records of the asset type to freeze (this does not include the fee input)
    //     let inputs_frozen = match outputs_frozen {
    //         FreezeFlag::Frozen => FreezeFlag::Unfrozen,
    //         FreezeFlag::Unfrozen => FreezeFlag::Frozen,
    //     };
    //     let (input_records, _) =
    //         self.find_records(&asset.code, &owner, inputs_frozen, amount, None)?;

    //     // prepare inputs
    //     let mut inputs = vec![];
    //     for (ro, uid) in input_records.into_iter() {
    //         let witness = self.get_merkle_proof(uid);
    //         inputs.push(FreezeNoteInput {
    //             ro,
    //             acc_member_witness: witness,
    //             keypair: &self.immutable_keys.freezer_key_pair,
    //         })
    //     }

    //     let (fee_ro, fee_uid) = self.find_native_record_for_fee(fee)?;
    //     let fee_input = FeeInput {
    //         ro: fee_ro,
    //         acc_member_witness: self.get_merkle_proof(fee_uid),
    //         owner_keypair: &self.immutable_keys.key_pair,
    //     };

    //     // find a proving key which can handle this transaction size
    //     let proving_key = Self::freeze_proving_key(
    //         &mut session.rng,
    //         &self.proving_keys.freeze,
    //         asset,
    //         &mut inputs,
    //         &self.immutable_keys.freezer_key_pair,
    //     )?;

    //     // generate transfer note and receiver memos
    //     let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut session.rng, fee_input, fee).unwrap();
    //     let (note, sig_key, outputs) =
    //         FreezeNote::generate(&mut session.rng, inputs, fee_info, proving_key)
    //             .context(CryptoError)?;
    //     let recv_memos = vec![&fee_out_rec]
    //         .into_iter()
    //         .chain(outputs.iter())
    //         .map(|r| ReceiverMemo::from_ro(&mut session.rng, r, &[]))
    //         .collect::<Result<Vec<_>, _>>()
    //         .unwrap();
    //     let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
    //     self.submit_transaction(
    //         session,
    //         TransactionNote::Freeze(Box::new(note)),
    //         recv_memos,
    //         sig,
    //         outputs,
    //     )
    //     .await
    // }

    // /// find a record and corresponding uid on the native asset type with enough
    // /// funds to pay transaction fee
    // fn find_native_record_for_fee(&self, fee: u64) -> Result<(RecordOpening, u64), WalletError> {
    //     self.find_records(
    //         &AssetCode::native(),
    //         &self.pub_key(),
    //         FreezeFlag::Unfrozen,
    //         fee,
    //         Some(1),
    //     )
    //     .map(|(ros, _change)| ros.into_iter().next().unwrap())
    // }

    // fn freeze_proving_key<'k>(
    //     rng: &mut ChaChaRng,
    //     proving_keys: &'k KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
    //     asset: &AssetDefinition,
    //     inputs: &mut Vec<FreezeNoteInput<'k>>,
    //     keypair: &'k FreezerKeyPair,
    // ) -> Result<&'k FreezeProvingKey<'a>, WalletError> {
    //     let total_output_amount = inputs.iter().map(|input| input.ro.amount).sum();

    //     let num_inputs = inputs.len() + 1; // make sure to include fee input
    //     let num_outputs = num_inputs; // freeze transactions always have equal outputs and inputs
    //     let (key_inputs, key_outputs, proving_key) = proving_keys
    //         .best_fit_key(num_inputs, num_outputs)
    //         .map_err(|(max_inputs, _)| {
    //             WalletError::Fragmentation {
    //                 asset: asset.code,
    //                 amount: total_output_amount,
    //                 suggested_amount: inputs
    //                     .iter()
    //                     .take(max_inputs - 1) // leave room for fee input
    //                     .map(|input| input.ro.amount)
    //                     .sum(),
    //                 max_records: max_inputs,
    //             }
    //         })?;
    //     assert!(num_inputs <= key_inputs);
    //     assert!(num_outputs <= key_outputs);

    //     if num_inputs < key_inputs {
    //         // pad with dummy inputs, leaving room for the fee input

    //         loop {
    //             let (ro, _) = RecordOpening::dummy(rng, FreezeFlag::Unfrozen);
    //             inputs.push(FreezeNoteInput {
    //                 ro,
    //                 acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
    //                 keypair,
    //             });
    //             if inputs.len() >= key_inputs - 1 {
    //                 break;
    //             }
    //         }
    //     }

    //     Ok(proving_key)
    // }

    // fn forget_merkle_leaf(&mut self, leaf: u64) {
    //     if leaf < self.record_mt.num_leaves() - 1 {
    //         self.record_mt.forget(leaf);
    //     } else {
    //         assert_eq!(leaf, self.record_mt.num_leaves() - 1);
    //         // We can't forget the last leaf in a Merkle tree. Instead, we just note that we want to
    //         // forget this leaf, and we'll forget it when we append a new last leaf.
    //         //
    //         // There can only be one `merkle_leaf_to_forget` at a time, because we will forget the
    //         // leaf and clear this field as soon as we append a new leaf.
    //         assert!(self.merkle_leaf_to_forget.is_none());
    //         self.merkle_leaf_to_forget = Some(leaf);
    //     }
    // }

    // #[must_use]
    // fn remember_merkle_leaf(&mut self, leaf: u64, proof: &MerkleLeafProof) -> bool {
    //     // If we were planning to forget this leaf once a new leaf is appended, stop planning that.
    //     if self.merkle_leaf_to_forget == Some(leaf) {
    //         self.merkle_leaf_to_forget = None;
    //         // `merkle_leaf_to_forget` is always represented in the tree, so we don't have to call
    //         // `remember` in this case.
    //         assert!(self.record_mt.get_leaf(leaf).expect_ok().is_ok());
    //         true
    //     } else {
    //         self.record_mt.remember(leaf, proof).is_ok()
    //     }
    // }

    // fn append_merkle_leaf(&mut self, comm: RecordCommitment) {
    //     self.record_mt.push(comm.to_field_element());

    //     // Now that we have appended a new leaf to the Merkle tree, we can forget the old last leaf,
    //     // if needed.
    //     if let Some(uid) = self.merkle_leaf_to_forget.take() {
    //         assert!(uid < self.record_mt.num_leaves() - 1);
    //         self.record_mt.forget(uid);
    //     }
    // }

    // fn get_merkle_proof(&self, leaf: u64) -> AccMemberWitness {
    //     // The wallet never needs a Merkle proof that isn't guaranteed to already be in the Merkle
    //     // tree, so this unwrap() should never fail.
    //     AccMemberWitness::lookup_from_tree(&self.record_mt, leaf)
    //         .expect_ok()
    //         .unwrap()
    //         .1
    // }
}
