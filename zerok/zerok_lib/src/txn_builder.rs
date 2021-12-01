use crate::util::arbitrary_wrappers::*;
use crate::{ledger, ser_test};
use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::*;
use jf_txn::{
    keys::{FreezerKeyPair, UserKeyPair, UserPubKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetDefinition, FreezeFlag, Nullifier, ReceiverMemo, RecordCommitment,
        RecordOpening,
    },
    MerkleTree, Signature,
};
use jf_utils::tagged_blob;
use ledger::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Index, IndexMut};

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
