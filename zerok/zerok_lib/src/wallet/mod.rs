pub mod network;

use crate::api;
use crate::key_set;
use crate::node::LedgerEvent;
use crate::set_merkle_tree::*;
use crate::{
    ElaboratedTransaction, ElaboratedTransactionHash, ProverKeySet, ValidationError,
    ValidatorState, MERKLE_HEIGHT,
};
use ark_serialize::*;
use async_scoped::AsyncScope;
use async_std::sync::Mutex;
use async_std::task::block_on;
use async_trait::async_trait;
use core::fmt::Debug;
use futures::{
    channel::oneshot,
    prelude::*,
    stream::{iter, Stream},
};
use jf_txn::{
    errors::TxnApiError,
    freeze::{FreezeNote, FreezeNoteInput},
    keys::{
        AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair,
        UserPubKey,
    },
    proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, BlindFactor, FeeInput, FreezeFlag,
        Nullifier, ReceiverMemo, RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness, MerkleTree, MerkleLeafProof, Signature, TransactionNote,
};
use jf_utils::tagged_blob;
use key_set::KeySet;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use snafu::{ResultExt, Snafu};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum WalletError {
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
    TooManyOutputs {
        asset: AssetCode,
        max_records: usize,
        num_receivers: usize,
        num_change_records: usize,
    },
    UndefinedAsset {
        asset: AssetCode,
    },
    InvalidBlock {
        source: ValidationError,
    },
    NullifierAlreadyPublished {
        nullifier: Nullifier,
    },
    TimedOut {},
    Cancelled {},
    CryptoError {
        source: TxnApiError,
    },
    InvalidAddress {
        address: UserAddress,
    },
    InvalidAuditorKey {
        my_key: AuditorPubKey,
        asset_key: AuditorPubKey,
    },
    InvalidFreezerKey {
        my_key: FreezerPubKey,
        asset_key: FreezerPubKey,
    },
    NetworkError {
        source: phaselock::networking::NetworkError,
    },
    QueryServiceError {
        source: crate::node::QueryServiceError,
    },
    ClientConfigError {
        source: <surf::Client as TryFrom<surf::Config>>::Error,
    },
    ConsensusError {
        #[snafu(source(false))]
        source: Result<phaselock::error::PhaseLockError, String>,
    },
    #[snafu(display("{}", msg))]
    Failed {
        msg: String,
    },
}

impl api::FromError for WalletError {
    fn catch_all(msg: String) -> Self {
        Self::Failed { msg }
    }

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        Self::QueryServiceError { source }
    }

    fn from_validation_error(source: ValidationError) -> Self {
        Self::InvalidBlock { source }
    }

    fn from_consensus_error(source: Result<phaselock::error::PhaseLockError, String>) -> Self {
        Self::ConsensusError { source }
    }
}

pub struct WalletState<'a> {
    pub(crate) rng: ChaChaRng,
    // sequence number of the last event processed
    pub(crate) now: u64,
    // wallets run validation in tandem with the validators, so that they do not have to trust new
    // blocks received from the event stream
    pub(crate) validator: ValidatorState,
    // proving key set. The proving keys are ordered by number of outputs first and number of inputs
    // second, because the wallet is less flexible with respect to number of outputs. If we are
    // building a transaction and find we have too many inputs we can always generate a merge
    // transaction to defragment, but if the user requests a transaction with N independent outputs,
    // there is nothing we can do to decrease that number. So when searching for an appropriate
    // proving key, we will want to find a key with enough outputs first, and then worry about the
    // number of inputs.
    pub(crate) proving_keys: ProverKeySet<'a, key_set::OrderByOutputs>,
    // all records we care about, including records we own, records we have audited, and records we
    // can freeze or unfreeze
    pub(crate) records: RecordDatabase,
    // key pair for decrypting auditor memos
    pub(crate) auditor_key_pair: AuditorKeyPair,
    // asset definitions for which we are an auditor, indexed by code
    pub(crate) auditable_assets: HashMap<AssetCode, AssetDefinition>,
    // key pair for computing nullifiers of records owned by someone else but which we can freeze or
    // unfreeze
    pub(crate) freezer_key_pair: FreezerKeyPair,
    // sparse nullifier set Merkle tree mirrored from validators
    pub(crate) nullifiers: SetMerkleTree,
    // maps defined asset code to asset definition, seed and description of the asset
    pub(crate) defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
    // set of unconfirmed transactions, indexed by UID
    pub(crate) pending_txns: HashMap<TransactionUID, PendingTransaction>,
    // the UIDs of transactions expiring at each validator timestamp.
    pub(crate) expiring_txns: BTreeMap<u64, HashSet<TransactionUID>>,
    // all transactions which have been committed but for which memos have not yet been posted.
    pub(crate) transactions_awaiting_memos: HashMap<TransactionUID, TransactionAwaitingMemos>,
    // indices into `transactions_awaiting_memos`, indexed by each output UID of each transaction.
    pub(crate) uids_awaiting_memos: HashMap<u64, TransactionUID>,
    // the transaction owning a particular hash
    pub(crate) transactions: HashMap<ElaboratedTransactionHash, TransactionUID>,
}

pub type TransactionUID = ElaboratedTransactionHash;

#[tagged_blob("TXN")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TransactionReceipt {
    uid: TransactionUID,
    fee_nullifier: Nullifier,
    submitter: UserAddress,
}

pub(crate) struct PendingTransaction {
    receiver_memos: Vec<ReceiverMemo>,
    signature: Signature,
    freeze_outputs: Vec<RecordOpening>,
    timeout: u64,
}

pub(crate) struct TransactionAwaitingMemos {
    // The uids of the outputs of this transaction for which memos have not yet been posted.
    pending_uids: HashSet<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Pending,
    AwaitingMemos,
    Retired,
    Rejected,
    Unknown,
}

impl std::fmt::Display for TransactionState {
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

impl TransactionState {
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Retired | Self::Rejected)
    }

    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[async_trait]
pub trait WalletBackend<'a> {
    type EventStream: 'a + Stream<Item = LedgerEvent> + Unpin + Send;
    async fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError>;
    async fn store(
        &mut self,
        key_pair: &UserKeyPair,
        state: &WalletState,
    ) -> Result<(), WalletError>;
    async fn subscribe(&self, starting_at: u64) -> Self::EventStream;
    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError>;
    async fn get_nullifier_proof(
        &self,
        root: set_hash::Hash,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError>;

    // Submit a transaction to a validator.
    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError>;
    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError>;
}

pub struct WalletSession<'a, Backend: WalletBackend<'a>> {
    backend: Backend,
    key_pair: UserKeyPair,
    _marker: std::marker::PhantomData<&'a ()>,
}

struct RecordInfo {
    ro: RecordOpening,
    uid: u64,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    hold_until: Option<u64>,
}

impl RecordInfo {
    fn on_hold(&self, now: u64) -> bool {
        matches!(self.hold_until, Some(t) if t > now)
    }

    fn hold_until(&mut self, until: u64) {
        self.hold_until = Some(until);
    }

    fn unhold(&mut self) {
        self.hold_until = None;
    }
}

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
    fn assets(&'_ self) -> impl '_ + Iterator<Item = AssetDefinition> {
        self.record_info
            .values()
            .map(|rec| rec.ro.asset_def.clone())
    }

    /// Find records which can be the input to a transaction, matching the given parameters.
    fn input_records<'a>(
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
    fn input_record_with_amount(
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

    fn record_with_nullifier_mut(&mut self, nullifier: &Nullifier) -> Option<&mut RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get_mut(uid)
    }

    fn insert(&mut self, ro: RecordOpening, uid: u64, key_pair: &UserKeyPair) {
        let nullifier = key_pair.nullify(
            ro.asset_def.policy_ref().freezer_pub_key(),
            uid,
            &RecordCommitment::from(&ro),
        );
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    fn insert_freezable(&mut self, ro: RecordOpening, uid: u64, key_pair: &FreezerKeyPair) {
        let nullifier = key_pair.nullify(&ro.pub_key, uid, &RecordCommitment::from(&ro));
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    fn insert_with_nullifier(&mut self, ro: RecordOpening, uid: u64, nullifier: Nullifier) {
        self.asset_records
            .entry((ro.asset_def.code, ro.pub_key.clone(), ro.freeze_flag))
            .or_insert_with(BTreeSet::new)
            .insert((ro.amount, uid));
        self.nullifier_records.insert(nullifier, uid);
        self.record_info.insert(
            uid,
            RecordInfo {
                ro,
                uid,
                hold_until: None,
            },
        );
    }

    fn remove_by_nullifier(&mut self, nullifier: Nullifier) -> Option<RecordInfo> {
        self.nullifier_records.remove(&nullifier).map(|uid| {
            let record = self.record_info.remove(&uid).unwrap();
            self.asset_records
                .get_mut(&(
                    record.ro.asset_def.code,
                    record.ro.pub_key.clone(),
                    record.ro.freeze_flag,
                ))
                .unwrap()
                .remove(&(record.ro.amount, uid));
            record
        })
    }
}

impl Default for RecordDatabase {
    fn default() -> Self {
        Self {
            record_info: HashMap::new(),
            asset_records: HashMap::new(),
            nullifier_records: HashMap::new(),
        }
    }
}

// a never expired target
const UNEXPIRED_VALID_UNTIL: u64 = 2u64.pow(jf_txn::constants::MAX_TIMESTAMP_LEN as u32) - 1;
// how long (in number of validator states) a record used as an input to an unconfirmed transaction
// should be kept on hold before the transaction is considered timed out. This should be the number
// of validator states after which the transaction's proof can no longer be verified.
const RECORD_HOLD_TIME: u64 = ValidatorState::RECORD_ROOT_HISTORY_SIZE as u64;
// (block_id, txn_id, [(uid, remember)])
type CommittedTxn<'a> = (u64, u64, &'a mut [(u64, bool)]);

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

#[derive(Clone, Debug, Default)]
struct EventSummary {
    updated_txns: Vec<(TransactionUID, TransactionState)>,
    spent_nullifiers: Vec<(Nullifier, u64)>,
    rejected_nullifiers: Vec<Nullifier>,
    received_memos: Vec<(ReceiverMemo, u64)>,
}

impl<'a> WalletState<'a> {
    pub fn pub_key(&self, session: &WalletSession<'a, impl WalletBackend<'a>>) -> UserPubKey {
        session.key_pair.pub_key()
    }

    pub fn balance(
        &self,
        session: &WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> u64 {
        self.records
            .input_records(
                asset,
                &self.pub_key(session),
                frozen,
                self.validator.prev_commit_time,
            )
            .map(|record| record.ro.amount)
            .sum()
    }

    pub fn assets(&self) -> HashMap<AssetCode, AssetInfo> {
        // Get the asset definitions of each record we own.
        let mut assets: HashMap<AssetCode, AssetInfo> = self
            .records
            .assets()
            .map(|def| (def.code, AssetInfo::from(def)))
            .collect();
        // Add any assets that we know about through auditing.
        for (code, def) in &self.auditable_assets {
            assets.insert(*code, AssetInfo::from(def.clone()));
        }
        // Add the minting information (seed and description) for each asset we've defined.
        for (code, (def, seed, desc)) in &self.defined_assets {
            assets.insert(
                *code,
                AssetInfo::new(def.clone(), MintInfo::new(*seed, desc.clone())),
            );
        }
        assets
    }

    pub async fn transaction_status(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        receipt: &TransactionReceipt,
    ) -> Result<TransactionState, WalletError> {
        if self.pending_txns.contains_key(&receipt.uid) {
            Ok(TransactionState::Pending)
        } else if self.transactions_awaiting_memos.contains_key(&receipt.uid) {
            Ok(TransactionState::AwaitingMemos)
        } else {
            let (spent, _) = self
                .get_nullifier_proof(session, receipt.fee_nullifier)
                .await?;
            if spent {
                Ok(TransactionState::Retired)
            } else {
                // If the transaction isn't in our pending data structures, but its fee record has
                // not been spent, then either it was rejected, or it's someone else's transaction
                // that we haven't been tracking through the lifecycle.
                if receipt.submitter == session.key_pair.address() {
                    Ok(TransactionState::Rejected)
                } else {
                    Ok(TransactionState::Unknown)
                }
            }
        }
    }

    async fn handle_event(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        event: LedgerEvent,
    ) -> EventSummary {
        self.now += 1;
        let mut summary = EventSummary::default();
        match event {
            LedgerEvent::Commit {
                block,
                block_id,
                state_comm,
            } => {
                // Don't trust the network connection that provided us this event; validate it
                // against our local mirror of the ledger and bail out if it is invalid.
                let mut uids = match self.validator.validate_and_apply(
                    self.validator.prev_commit_time + 1,
                    block.block.clone(),
                    block.proofs.clone(),
                    true, // remember all commitments; we will forget the ones we don't need later
                ) {
                    Ok(uids) => {
                        if state_comm != self.validator.commit() {
                            // Received a block which validates, but our state commitment does not
                            // match that of the event source. Since the block validates, we will
                            // accept it, but this must indicate that the event source is lying or
                            // mistaken about the state commitment. This would be a good time to
                            // switch to a different query server or something, but for now we'll
                            // just log the problem.
                            println!("received valid block with invalid state commitment");
                        }

                        // Get a list of new uids and whether we want to remember them in our record
                        // Merkle tree. Initially, set `remember` to false for all uids, to maximize
                        // sparseness. If any of the consumers of this block (for example, the
                        // auditor component, or the owner of this wallet) care about a uid, they
                        // will set its `remember` flag to true.
                        uids.into_iter().map(|uid| (uid, false)).collect::<Vec<_>>()
                    }
                    Err(val_err) => {
                        //todo !jeb.bearer handle this case more robustly. If we get here, it means
                        // the event stream has lied to us, so recovery is quite tricky and may
                        // require us to fail over to a different query service.
                        panic!("received invalid block: {:?}, {:?}", block, val_err);
                    }
                };

                for ((txn_id, txn), proofs) in
                    block.block.0.into_iter().enumerate().zip(block.proofs)
                {
                    // Split the uids corresponding to this transaction off the front of `uids`.
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());

                    assert_eq!(this_txn_uids.len(), txn.output_len());
                    summary.spent_nullifiers.extend(
                        txn.nullifiers()
                            .into_iter()
                            .zip(this_txn_uids.iter().map(|(uid, _)| *uid)),
                    );
                    let txn = ElaboratedTransaction { txn, proofs };

                    // Different concerns within the wallet consume transactions in different ways.
                    // Now we give each concern a chance to consume this transaction, performing any
                    // processing they need to do and possibly setting the `remember` flag for
                    // output records they care about.
                    //
                    // This is a transaction we submitted and have been
                    // awaiting confirmation.
                    if let Some((txn_uid, _)) = self
                        .clear_pending_transaction(
                            session,
                            &txn,
                            Some((block_id, txn_id as u64, &mut this_txn_uids)),
                        )
                        .await
                    {
                        summary
                            .updated_txns
                            .push((txn_uid, TransactionState::AwaitingMemos));
                    }

                    // This is someone else's transaction but we can audit it.
                    self.audit_transaction(session, &txn, &mut this_txn_uids)
                        .await;

                    // Update spent nullifiers. First we have to remember the sub-trees of our
                    // current sparse tree which will receive the new nullifiers, because
                    // SetMerkleTree::insert has no effect (not even updating the root hashs) if the
                    // insert goes into a forgotten sub-tree.
                    for (nullifier, proof) in txn.txn.nullifiers().into_iter().zip(txn.proofs) {
                        if self.nullifiers.remember(nullifier, proof).is_err() {
                            //todo !jeb.bearer handle this case more robustly. If we get here, it
                            // means the event stream has lied to us, so recovery is quite tricky
                            // and may require us to fail over to a different query service.
                            panic!("received block with invalid nullifier proof");
                        }
                    }
                    // Now we can insert the new nullifiers, and none of the inserts should fail.
                    for nullifier in txn.txn.nullifiers() {
                        // This should not fail after the remember() above, so we can unwrap().
                        self.nullifiers.insert(nullifier).unwrap();
                        // If we have a record with this nullifier, remove it as it has been spent.
                        if let Some(record) = self.records.remove_by_nullifier(nullifier) {
                            self.record_merkle_tree_mut().forget(record.uid);
                        }
                    }
                    // Now that the new nullifiers have all been inserted, we can prune our
                    // nullifiers set back down to restore sparseness.
                    for nullifier in txn.txn.nullifiers() {
                        //todo !jeb.bearer for now we unconditionally forget the new nullifier,
                        // knowing we can get it back from the backend if necessary. However, this
                        // nullifier may be helping us by representing a branch of the tree that we
                        // care about, that would allow us to generate a proof that the nullifier
                        // for one of our owned records is _not_ in the tree. We should be more
                        // careful about pruning to cut down on the amount we have to ask the
                        // network.
                        self.nullifiers.forget(nullifier);
                    }

                    // Prune the record Merkle tree of records we don't care about.
                    for (uid, remember) in this_txn_uids {
                        if !remember {
                            self.record_merkle_tree_mut().forget(uid);
                        }
                    }
                }

                // Some transactions may have expired when we stepped the validator state. Remove
                // them from our pending transaction data structures.
                //
                // This maintains the invariant that everything in `pending_transactions` must
                // correspond to an on-hold record, because everything which corresponds to a record
                // whose hold just expired will be removed from the set now.
                for txn_uid in self.clear_expired_transactions() {
                    summary
                        .updated_txns
                        .push((txn_uid, TransactionState::Rejected));
                }
            }

            LedgerEvent::Memos { outputs } => {
                for (memo, comm, uid, proof) in outputs {
                    summary.received_memos.push((memo.clone(), uid));

                    if let Ok(record_opening) = memo.decrypt(&session.key_pair, &comm, &[]) {
                        if !record_opening.is_dummy() {
                            // If this record is for us (i.e. its corresponding memo decrypts under
                            // our key) and not a dummy, then add it to our owned records.
                            self.records.insert(record_opening, uid, &session.key_pair);
                            if self
                                .record_merkle_tree_mut()
                                .remember(uid, &MerkleLeafProof::new(comm.to_field_element(), proof))
                                .is_err()
                            {
                                println!(
                                    "error: got bad merkle proof from backend for commitment {:?}",
                                    comm
                                );
                            }
                        }
                    }

                    if let Some(txn_uid) = self.uids_awaiting_memos.remove(&uid) {
                        let txn = self.transactions_awaiting_memos.get_mut(&txn_uid).unwrap();
                        txn.pending_uids.remove(&uid);
                        if txn.pending_uids.is_empty() {
                            self.transactions_awaiting_memos.remove(&txn_uid);
                            summary
                                .updated_txns
                                .push((txn_uid, TransactionState::Retired));
                        }
                    }
                }
            }

            LedgerEvent::Reject { block, error } => {
                for (txn, proofs) in block.block.0.into_iter().zip(block.proofs) {
                    summary.rejected_nullifiers.append(&mut txn.nullifiers());
                    let mut txn = ElaboratedTransaction { txn, proofs };
                    if let Some((txn_uid, pending)) =
                        self.clear_pending_transaction(session, &txn, None).await
                    {
                        // Try to resubmit if the error is recoverable.
                        if let ValidationError::BadNullifierProof {} = &error {
                            if self
                                .update_nullifier_proofs(session, &mut txn)
                                .await
                                .is_ok()
                                && self
                                    .submit_elaborated_transaction(
                                        session,
                                        txn,
                                        pending.receiver_memos,
                                        pending.signature,
                                        pending.freeze_outputs,
                                        Some(txn_uid.clone()),
                                    )
                                    .await
                                    .is_ok()
                            {
                                // The transaction has been successfully resubmitted. It is still in
                                // the same state (pending) so we don't need to add it to
                                // `updated_txns`.
                            } else {
                                // If we failed to resubmit, then the rejection is final.
                                summary
                                    .updated_txns
                                    .push((txn_uid, TransactionState::Rejected));
                            }
                        } else {
                            summary
                                .updated_txns
                                .push((txn_uid, TransactionState::Rejected));
                        }
                    }
                }
            }
        };

        summary
    }

    async fn clear_pending_transaction<'t>(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &ElaboratedTransaction,
        res: Option<CommittedTxn<'t>>,
    ) -> Option<(TransactionUID, PendingTransaction)> {
        let now = self.validator.prev_commit_time;

        // Remove the transaction from pending transaction data structures.
        let txn_hash = txn.hash();
        let pending = self.pending_txns.remove(&txn_hash);
        if let Some(pending) = &pending {
            // Remove the transaction from the set of transactions set to expire.
            if let Some(expiring) = self.expiring_txns.get_mut(&pending.timeout) {
                expiring.remove(&txn_hash);
            }
        }
        let txn_uid = self.transactions.remove(&txn_hash);
        assert_eq!(txn_uid.is_some(), pending.is_some());

        for nullifier in txn.txn.nullifiers() {
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

        // If this was a successful transaction, post its receiver memos and add all of its
        // frozen/unfrozen outputs to our freezable database (for freeze/unfreeze transactions).
        if let Some((block_id, txn_id, uids)) = res {
            if let Some(pending) = &pending {
                if let Err(err) = session
                    .backend
                    .post_memos(
                        block_id,
                        txn_id,
                        pending.receiver_memos.clone(),
                        pending.signature.clone(),
                    )
                    .await
                {
                    println!(
                        "Error: failed to post receiver memos for transaction ({}:{}): {:?}",
                        block_id, txn_id, err
                    );
                } else {
                    let uids = uids
                        .iter()
                        .map(|(uid, _)| {
                            self.uids_awaiting_memos.insert(*uid, txn_hash.clone());
                            *uid
                        })
                        .collect();
                    self.transactions_awaiting_memos.insert(
                        txn_hash.clone(),
                        TransactionAwaitingMemos { pending_uids: uids },
                    );
                }

                // the first uid corresponds to the fee change output, which is not one of the
                // `freeze_outputs`, so we skip that one
                for ((uid, remember), ro) in uids.iter_mut().skip(1).zip(&pending.freeze_outputs) {
                    self.records
                        .insert_freezable(ro.clone(), *uid, &self.freezer_key_pair);
                    *remember = true;
                }
            }
        }

        pending.map(|txn| (txn_uid.unwrap(), txn))
    }

    fn clear_expired_transactions(&mut self) -> Vec<TransactionUID> {
        let now = self.validator.prev_commit_time;

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
            .map(|txn_hash| {
                let txn_uid = self.transactions.remove(&txn_hash).unwrap();
                self.pending_txns.remove(&txn_hash);
                txn_uid
            })
            .collect()
    }

    async fn audit_transaction(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &ElaboratedTransaction,
        uids: &mut [(u64, bool)],
    ) {
        // Try to decrypt auditor memos.
        let mut audit_data = None;
        match &txn.txn {
            TransactionNote::Transfer(xfr) => {
                for asset in self.auditable_assets.values() {
                    audit_data = self
                        .auditor_key_pair
                        .open_transfer_audit_memo(asset, xfr)
                        .ok();
                    if audit_data.is_some() {
                        break;
                    }
                }
            }
            TransactionNote::Mint(mint) => {
                audit_data = self
                    .auditor_key_pair
                    .open_mint_audit_memo(mint)
                    .ok()
                    .map(|audit_output| (vec![], vec![audit_output]));
            }
            TransactionNote::Freeze(_) => {}
        }
        if let Some((_, audit_outputs)) = audit_data {
            //todo !jeb.bearer eventually, we will probably want to save all the audit memos for
            // the whole transaction (inputs and outputs) regardless of whether any of the outputs
            // are freezeable, just for general auditing purposes.

            // the first uid corresponds to the fee change output, which has no audit memo, so skip
            // that one
            for ((uid, remember), output) in uids.iter_mut().skip(1).zip(audit_outputs) {
                let pub_key = match output.user_address {
                    Some(address) => session.backend.get_public_key(&address).await.ok(),
                    None => None,
                };
                if let (Some(asset_def), Some(pub_key), Some(amount), Some(blind)) = (
                    self.auditable_assets.get(&output.asset_code),
                    pub_key,
                    output.amount,
                    output.blinding_factor,
                ) {
                    // If the audit memo contains all the information we need to potentially freeze
                    // this record, save it in our database for later freezing.
                    if *asset_def.policy_ref().freezer_pub_key() == self.freezer_key_pair.pub_key()
                    {
                        let record_opening = RecordOpening {
                            amount,
                            asset_def: asset_def.clone(),
                            pub_key,
                            freeze_flag: FreezeFlag::Unfrozen,
                            blind,
                        };
                        self.records
                            .insert_freezable(record_opening, *uid, &self.freezer_key_pair);
                        *remember = true;
                    }
                }
            }
        }
    }

    async fn update_nullifier_proofs(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &mut ElaboratedTransaction,
    ) -> Result<(), WalletError> {
        txn.proofs = Vec::new();
        for n in txn.txn.nullifiers() {
            let proof = self.prove_nullifier_unspent(session, n).await?;
            txn.proofs.push(proof);
        }
        Ok(())
    }

    pub fn define_asset(
        &mut self,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let seed = AssetCodeSeed::generate(&mut self.rng);
        let code = AssetCode::new(seed, description);
        let asset_definition = AssetDefinition::new(code, policy).context(CryptoError)?;
        self.defined_assets
            .insert(code, (asset_definition.clone(), seed, description.to_vec()));
        // If the policy lists ourself as the auditor, automatically start auditing transactions
        // involving this asset.
        if *asset_definition.policy_ref().auditor_pub_key() == self.auditor_key_pair.pub_key() {
            self.auditable_assets
                .insert(asset_definition.code, asset_definition.clone());
        }
        Ok(asset_definition)
    }

    /// Use `audit_asset` to start auditing transactions with a given asset type, when the asset
    /// type was defined by someone else and sent to us out of band.
    ///
    /// Auditing of assets created by this user with an appropriate asset policy begins
    /// automatically. Calling this function is unnecessary.
    pub fn audit_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError> {
        let my_key = self.auditor_key_pair.pub_key();
        let asset_key = asset.policy_ref().auditor_pub_key();
        if my_key != *asset_key {
            return Err(WalletError::InvalidAuditorKey {
                my_key,
                asset_key: asset_key.clone(),
            });
        }

        self.auditable_assets.insert(asset.code, asset.clone());
        Ok(())
    }

    pub async fn transfer(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetCode,
        receivers: &[(UserAddress, u64)],
        fee: u64,
    ) -> Result<TransactionReceipt, WalletError> {
        let receivers = iter(receivers)
            .then(|(addr, amt)| {
                let session = &session;
                async move { Ok((session.backend.get_public_key(addr).await?, *amt)) }
            })
            .try_collect::<Vec<_>>()
            .await?;

        if *asset == AssetCode::native() {
            self.transfer_native(session, &receivers, fee).await
        } else {
            self.transfer_non_native(session, asset, &receivers, fee)
                .await
        }
    }

    pub async fn mint(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        let (fee_ro, uid) = self.find_native_record_for_fee(session, fee)?;
        let acc_member_witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
            .expect_ok()
            .unwrap()
            .1;
        let (asset_def, seed, asset_description) = self
            .defined_assets
            .get(asset_code)
            .ok_or(WalletError::UndefinedAsset { asset: *asset_code })?;
        let mint_record = RecordOpening {
            amount,
            asset_def: asset_def.clone(),
            pub_key: session.backend.get_public_key(&owner).await?,
            freeze_flag: FreezeFlag::Unfrozen,
            blind: BlindFactor::rand(&mut self.rng),
        };

        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness,
            owner_keypair: &session.key_pair,
        };
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let rng = &mut self.rng;
        let recv_memos = vec![&fee_out_rec, &mint_record]
            .into_iter()
            .map(|r| ReceiverMemo::from_ro(rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (mint_note, sig_key) = jf_txn::mint::MintNote::generate(
            &mut self.rng,
            mint_record,
            *seed,
            asset_description.as_slice(),
            fee_info,
            &self.proving_keys.mint,
        )
        .context(CryptoError)?;
        let signature = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            session,
            TransactionNote::Mint(Box::new(mint_note)),
            recv_memos,
            signature,
            vec![],
        )
        .await
    }

    /// Freeze at least `amount` of a particular asset owned by a given user.
    ///
    /// In order to freeze an asset, this wallet must be an auditor of that asset type, and it must
    /// have observed enough transactions to determine that the target user owns at least `amount`
    /// of that asset.
    ///
    /// Freeze transactions do not currently support change, so the amount frozen will be at least
    /// `amount` but might be more, depending on the distribution of the freezable records we have
    /// for the target user.
    ///
    /// Some of these restrictions can be rolled back in the future:
    /// * An API can be provided for freezing without being an auditor, if a freezable record
    ///   opening is provided to us out of band by an auditor.
    /// * `freeze` uses the same allocation scheme for input records as transfers, which tries to
    ///   minimize fragmentation. But freeze transactions do not increase fragmentation because they
    ///   have no change output, so we could use a different allocation scheme that tries to
    ///   minimize change, which would limit the amount we can over-freeze, and would guarantee that
    ///   we freeze the exact amount if it is possible to make exact change with the freezable
    ///   records we have.
    pub async fn freeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Frozen)
            .await
    }

    /// Unfreeze at least `amount` of a particular asset owned by a given user.
    ///
    /// This wallet must have previously been used to freeze (without an intervening `unfreeze`) at
    /// least `amount` of the given asset for the given user.
    ///
    /// Similar restrictions on change apply as for `freeze`.
    pub async fn unfreeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Unfrozen)
            .await
    }

    async fn freeze_or_unfreeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
    ) -> Result<TransactionReceipt, WalletError> {
        let my_key = self.freezer_key_pair.pub_key();
        let asset_key = asset.policy_ref().freezer_pub_key();
        if my_key != *asset_key {
            return Err(WalletError::InvalidFreezerKey {
                my_key,
                asset_key: asset_key.clone(),
            });
        }

        let owner = session.backend.get_public_key(&owner).await?;

        // find input records of the asset type to freeze (this does not include the fee input)
        let inputs_frozen = match outputs_frozen {
            FreezeFlag::Frozen => FreezeFlag::Unfrozen,
            FreezeFlag::Unfrozen => FreezeFlag::Frozen,
        };
        let (input_records, _) =
            self.find_records(&asset.code, &owner, inputs_frozen, amount, None)?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records.into_iter() {
            let witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                .expect_ok()
                .unwrap()
                .1;
            inputs.push(FreezeNoteInput {
                ro,
                acc_member_witness: witness,
                keypair: &self.freezer_key_pair,
            })
        }

        let (fee_ro, fee_uid) = self.find_native_record_for_fee(session, fee)?;
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness: AccMemberWitness::lookup_from_tree(
                self.record_merkle_tree(),
                fee_uid,
            )
            .expect_ok()
            .unwrap()
            .1,
            owner_keypair: &session.key_pair,
        };

        // find a proving key which can handle this transaction size
        let proving_key = Self::freeze_proving_key(
            &mut self.rng,
            &self.proving_keys.freeze,
            asset,
            &mut inputs,
            &self.freezer_key_pair,
        )?;

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let (note, sig_key, outputs) =
            FreezeNote::generate(&mut self.rng, inputs, fee_info, proving_key)
                .context(CryptoError)?;
        let recv_memos = vec![&fee_out_rec]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            session,
            TransactionNote::Freeze(Box::new(note)),
            recv_memos,
            sig,
            outputs,
        )
        .await
    }

    async fn transfer_native(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        receivers: &[(UserPubKey, u64)],
        fee: u64,
    ) -> Result<TransactionReceipt, WalletError> {
        let total_output_amount: u64 =
            receivers.iter().fold(0, |sum, (_, amount)| sum + *amount) + fee;

        // find input records which account for at least the total amount, and possibly some change.
        let (input_records, _change) = self.find_records(
            &AssetCode::native(),
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records {
            let acc_member_witness =
                AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                    .expect_ok()
                    .unwrap()
                    .1;
            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness,
                owner_keypair: &session.key_pair,
                cred: None,
            });
        }

        // prepare outputs, excluding fee change (which will be automatically generated)
        let mut outputs = vec![];
        for (pub_key, amount) in receivers {
            outputs.push(RecordOpening::new(
                &mut self.rng,
                *amount,
                AssetDefinition::native(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }

        // find a proving key which can handle this transaction size
        let rng = &mut self.rng;
        let (proving_key, dummy_inputs) = Self::xfr_proving_key(
            rng,
            session.key_pair.pub_key(),
            &self.proving_keys.xfr,
            &AssetDefinition::native(),
            &mut inputs,
            &mut outputs,
            false,
        )?;
        // pad with dummy inputs if necessary
        let dummy_inputs = (0..dummy_inputs)
            .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
            .collect::<Vec<_>>();
        for (ro, owner_keypair) in &dummy_inputs {
            let dummy_input = TransferNoteInput {
                ro: ro.clone(),
                acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
                owner_keypair,
                cred: None,
            };
            inputs.push(dummy_input);
        }

        // generate transfer note and receiver memos
        let (note, kp, fee_change_ro) = TransferNote::generate_native(
            &mut self.rng,
            inputs,
            &outputs,
            fee,
            UNEXPIRED_VALID_UNTIL,
            proving_key,
        )
        .context(CryptoError)?;

        let outputs: Vec<_> = vec![fee_change_ro]
            .into_iter()
            .chain(outputs.into_iter())
            .collect();

        let recv_memos: Vec<_> = outputs
            .iter()
            .map(|ro| ReceiverMemo::from_ro(&mut self.rng, ro, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&kp, &recv_memos).context(CryptoError)?;
        self.submit_transaction(
            session,
            TransactionNote::Transfer(Box::new(note)),
            recv_memos,
            sig,
            vec![],
        )
        .await
    }

    async fn transfer_non_native(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetCode,
        receivers: &[(UserPubKey, u64)],
        fee: u64,
    ) -> Result<TransactionReceipt, WalletError> {
        assert_ne!(
            *asset,
            AssetCode::native(),
            "call `transfer_native()` instead"
        );
        let total_output_amount: u64 = receivers.iter().fold(0, |sum, (_, amount)| sum + *amount);

        // find input records of the asset type to spend (this does not include the fee input)
        let (input_records, change) = self.find_records(
            asset,
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;
        let asset = input_records[0].0.asset_def.clone();

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records.into_iter() {
            let witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                .expect_ok()
                .unwrap()
                .1;
            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness: witness,
                owner_keypair: &session.key_pair,
                cred: None, // TODO support credentials
            })
        }

        // prepare outputs, excluding fee change (which will be automatically generated)
        let mut outputs = vec![];
        for (pub_key, amount) in receivers {
            outputs.push(RecordOpening::new(
                &mut self.rng,
                *amount,
                asset.clone(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }
        // change in the asset type being transfered (not fee change)
        if change > 0 {
            let me = self.pub_key(session);
            let change_ro = RecordOpening::new(
                &mut self.rng,
                change,
                asset.clone(),
                me,
                FreezeFlag::Unfrozen,
            );
            outputs.push(change_ro);
        }

        let (fee_ro, fee_uid) = self.find_native_record_for_fee(session, fee)?;
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness: AccMemberWitness::lookup_from_tree(
                self.record_merkle_tree(),
                fee_uid,
            )
            .expect_ok()
            .unwrap()
            .1,
            owner_keypair: &session.key_pair,
        };

        // find a proving key which can handle this transaction size
        let rng = &mut self.rng;
        let (proving_key, dummy_inputs) = Self::xfr_proving_key(
            rng,
            session.key_pair.pub_key(),
            &self.proving_keys.xfr,
            &asset,
            &mut inputs,
            &mut outputs,
            change > 0,
        )?;
        // pad with dummy inputs if necessary
        let dummy_inputs = (0..dummy_inputs)
            .map(|_| RecordOpening::dummy(rng, FreezeFlag::Unfrozen))
            .collect::<Vec<_>>();
        for (ro, owner_keypair) in &dummy_inputs {
            let dummy_input = TransferNoteInput {
                ro: ro.clone(),
                acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
                owner_keypair,
                cred: None,
            };
            inputs.push(dummy_input);
        }

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let (note, sig_key) = TransferNote::generate_non_native(
            &mut self.rng,
            inputs,
            &outputs,
            fee_info,
            UNEXPIRED_VALID_UNTIL,
            proving_key,
        )
        .context(CryptoError)?;
        let recv_memos = vec![&fee_out_rec]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            session,
            TransactionNote::Transfer(Box::new(note)),
            recv_memos,
            sig,
            vec![],
        )
        .await
    }

    async fn submit_transaction(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        note: TransactionNote,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
    ) -> Result<TransactionReceipt, WalletError> {
        let mut nullifier_pfs = Vec::new();
        for n in note.nullifiers() {
            let proof = if let Some((contains, proof)) = self.nullifiers.contains(n) {
                if contains {
                    return Err(WalletError::NullifierAlreadyPublished { nullifier: n });
                } else {
                    proof
                }
            } else {
                let proof = self.prove_nullifier_unspent(session, n).await?;
                self.nullifiers.remember(n, proof.clone()).unwrap();
                proof
            };
            nullifier_pfs.push(proof);
        }

        let txn = ElaboratedTransaction {
            txn: note,
            proofs: nullifier_pfs,
        };
        self.submit_elaborated_transaction(session, txn, memos, sig, freeze_outputs, None)
            .await
    }

    async fn submit_elaborated_transaction(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: ElaboratedTransaction,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
        uid: Option<TransactionUID>,
    ) -> Result<TransactionReceipt, WalletError> {
        let receipt = self.add_pending_transaction(session, &txn, memos, sig, freeze_outputs, uid);
        if let Err(err) = session.backend.submit(txn.clone()).await {
            self.clear_pending_transaction(session, &txn, None).await;
            return Err(err);
        }
        Ok(receipt)
    }

    fn add_pending_transaction(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &ElaboratedTransaction,
        receiver_memos: Vec<ReceiverMemo>,
        signature: Signature,
        freeze_outputs: Vec<RecordOpening>,
        uid: Option<TransactionUID>,
    ) -> TransactionReceipt {
        let now = self.validator.prev_commit_time;
        let timeout = now + RECORD_HOLD_TIME;
        let hash = txn.hash();
        let uid = uid.unwrap_or_else(|| hash.clone());

        for nullifier in txn.txn.nullifiers() {
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
        };
        self.transactions.insert(hash.clone(), uid.clone());

        // Add the transaction to `pending_txns` and `expiring_txns` while it is in flight..
        self.pending_txns.insert(hash.clone(), pending);
        self.expiring_txns.entry(timeout).or_default().insert(hash);

        TransactionReceipt {
            uid,
            fee_nullifier: txn.txn.nullifiers()[0],
            submitter: session.key_pair.address(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn find_records(
        &self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        amount: u64,
        max_records: Option<usize>,
    ) -> Result<(Vec<(RecordOpening, u64)>, u64), WalletError> {
        let now = self.validator.prev_commit_time;

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
                    return Err(WalletError::Fragmentation {
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

        Err(WalletError::InsufficientBalance {
            asset: *asset,
            required: amount,
            actual: current_amount,
        })
    }

    /// find a record and corresponding uid on the native asset type with enough
    /// funds to pay transaction fee
    fn find_native_record_for_fee(
        &self,
        session: &WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
    ) -> Result<(RecordOpening, u64), WalletError> {
        self.find_records(
            &AssetCode::native(),
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            fee,
            Some(1),
        )
        .map(|(ros, _change)| ros.into_iter().next().unwrap())
    }

    // Find a proving key large enough to prove the given transaction, returning the number of dummy
    // inputs needed to pad the transaction.
    //
    // `proving_keys` should always be `&self.proving_key`. This is a non-member function in order
    // to prove to the compiler that the result only borrows from `&self.proving_key`, not all of
    // `&self`.
    #[allow(clippy::too_many_arguments)]
    fn xfr_proving_key<'k>(
        rng: &mut ChaChaRng,
        me: UserPubKey,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<TransferNoteInput<'k>>,
        outputs: &mut Vec<RecordOpening>,
        change_record: bool,
    ) -> Result<(&'k TransferProvingKey<'a>, usize), WalletError> {
        let total_output_amount = outputs.iter().map(|ro| ro.amount).sum();
        // non-native transfers have an extra fee input, which is not included in `inputs`.
        let fee_inputs = if *asset == AssetDefinition::native() {
            0
        } else {
            1
        };
        // both native and non-native transfers have an extra fee change output which is
        // automatically generated and not included in `outputs`.
        let fee_outputs = 1;

        let num_inputs = inputs.len() + fee_inputs;
        let num_outputs = outputs.len() + fee_outputs;
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, max_outputs)| {
                if max_outputs >= num_outputs {
                    // If there is a key that can fit the correct number of outputs had we only
                    // managed to find fewer inputs, call this a fragmentation error.
                    WalletError::Fragmentation {
                        asset: asset.code,
                        amount: total_output_amount,
                        suggested_amount: inputs
                            .iter()
                            .take(max_inputs - fee_inputs)
                            .map(|input| input.ro.amount)
                            .sum(),
                        max_records: max_inputs,
                    }
                } else {
                    // Otherwise, we just have too many outputs for any of our available keys. There
                    // is nothing we can do about that on the wallet side.
                    WalletError::TooManyOutputs {
                        asset: asset.code,
                        max_records: max_outputs,
                        num_receivers: outputs.len() - change_record as usize,
                        num_change_records: 1 + change_record as usize,
                    }
                }
            })?;
        assert!(num_inputs <= key_inputs);
        assert!(num_outputs <= key_outputs);

        if num_outputs < key_outputs {
            // pad with dummy (0-amount) outputs,leaving room for the fee change output
            while {
                outputs.push(RecordOpening::new(
                    rng,
                    0,
                    asset.clone(),
                    me.clone(),
                    FreezeFlag::Unfrozen,
                ));
                outputs.len() < key_outputs - fee_outputs
            } {}
        }

        // Return the required number of dummy inputs. We can't easily create the dummy inputs here,
        // because it requires creating a new dummy key pair and then borrowing from the key pair to
        // form the transfer input, so the key pair must be owned by the caller.
        let dummy_inputs = key_inputs.saturating_sub(num_inputs);
        Ok((proving_key, dummy_inputs))
    }

    fn freeze_proving_key<'k>(
        rng: &mut ChaChaRng,
        proving_keys: &'k KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<FreezeNoteInput<'k>>,
        keypair: &'k FreezerKeyPair,
    ) -> Result<&'k FreezeProvingKey<'a>, WalletError> {
        let total_output_amount = inputs.iter().map(|input| input.ro.amount).sum();

        let num_inputs = inputs.len() + 1; // make sure to include fee input
        let num_outputs = num_inputs; // freeze transactions always have equal outputs and inputs
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, _)| {
                WalletError::Fragmentation {
                    asset: asset.code,
                    amount: total_output_amount,
                    suggested_amount: inputs
                        .iter()
                        .take(max_inputs - 1) // leave room for fee input
                        .map(|input| input.ro.amount)
                        .sum(),
                    max_records: max_inputs,
                }
            })?;
        assert!(num_inputs <= key_inputs);
        assert!(num_outputs <= key_outputs);

        if num_inputs < key_inputs {
            // pad with dummy inputs, leaving room for the fee input
            while {
                let (ro, _) = RecordOpening::dummy(rng, FreezeFlag::Unfrozen);
                inputs.push(FreezeNoteInput {
                    ro,
                    acc_member_witness: AccMemberWitness::dummy(MERKLE_HEIGHT),
                    keypair,
                });
                inputs.len() < key_inputs - 1
            } {}
        }

        Ok(proving_key)
    }

    fn record_merkle_tree(&self) -> &MerkleTree {
        &self.validator.record_merkle_frontier
    }

    fn record_merkle_tree_mut(&mut self) -> &mut MerkleTree {
        &mut self.validator.record_merkle_frontier
    }

    async fn get_nullifier_proof(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError> {
        if let Some(ret) = self.nullifiers.contains(nullifier) {
            Ok(ret)
        } else {
            let (contains, proof) = session
                .backend
                .get_nullifier_proof(self.nullifiers.hash(), nullifier)
                .await?;
            self.nullifiers.remember(nullifier, proof.clone()).unwrap();
            Ok((contains, proof))
        }
    }

    async fn prove_nullifier_unspent(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        nullifier: Nullifier,
    ) -> Result<SetMerkleProof, WalletError> {
        let (spent, proof) = self.get_nullifier_proof(session, nullifier).await?;
        if spent {
            Err(WalletError::NullifierAlreadyPublished { nullifier })
        } else {
            Ok(proof)
        }
    }
}

/// Note: it is a soundness requirement that the destructor of a `Wallet` run when the `Wallet` is
/// dropped. Therefore, `std::mem::forget` must not be used to forget a `Wallet` without running its
/// destructor.
pub struct Wallet<'a, Backend: WalletBackend<'a>> {
    // Data shared between the main thread and the event handling thread:
    //  * the trusted, persistent wallet state
    //  * the trusted, ephemeral wallet session
    //  * promise completion handles for futures returned by sync(), indexed by the timestamp at
    //    which the corresponding future is supposed to complete. Handles are added in sync() (main
    //    thread) and removed and completed in the event thread
    mutex: Arc<Mutex<WalletSharedState<'a, Backend>>>,
    // Handle for the task running the event handling loop. When dropped, this handle will cancel
    // the task, so this field is never read, it exists solely to live as long as this struct and
    // then be dropped.
    _event_task: AsyncScope<'a, ()>,
}

struct WalletSharedState<'a, Backend: WalletBackend<'a>> {
    state: WalletState<'a>,
    session: WalletSession<'a, Backend>,
    sync_handles: HashMap<u64, Vec<oneshot::Sender<()>>>,
    txn_subscribers: HashMap<TransactionUID, Vec<oneshot::Sender<TransactionState>>>,
    pending_foreign_txns: HashMap<Nullifier, Vec<oneshot::Sender<TransactionState>>>,
}

impl<'a, Backend: 'a + WalletBackend<'a> + Send + Sync> Wallet<'a, Backend> {
    pub async fn new(
        key_pair: UserKeyPair,
        backend: Backend,
    ) -> Result<Wallet<'a, Backend>, WalletError> {
        let state = backend.load(&key_pair).await?;
        let mut events = backend.subscribe(state.now).await;
        let session = WalletSession {
            key_pair,
            backend,
            _marker: Default::default(),
        };
        let sync_handles = HashMap::new();
        let txn_subscribers = HashMap::new();
        let pending_foreign_txns = HashMap::new();
        let mutex = Arc::new(Mutex::new(WalletSharedState {
            state,
            session,
            sync_handles,
            txn_subscribers,
            pending_foreign_txns,
        }));

        // Start the event loop.
        let event_task = {
            let mutex = mutex.clone();
            let mut scope = unsafe {
                // Creating an AsyncScope is considered unsafe because `std::mem::forget` is allowed
                // in safe code, and forgetting an AsyncScope can allow its inner futures to
                // continue to be scheduled to run after the lifetime of the scope ends, since
                // normally the destructor of the scope ensures that its futures are driven to
                // completion before its lifetime ends.
                //
                // Since we are immediately going to store `scope` in the resulting `Wallet`, its
                // lifetime will be the same as the `Wallet`, and its destructor will run as long as
                // no one calls `forget` on the `Wallet` -- which no one should ever have any reason
                // to.
                AsyncScope::create()
            };
            scope.spawn_cancellable(
                async move {
                    let mut foreign_txns_awaiting_memos = HashMap::new();
                    while let Some(event) = events.next().await {
                        let WalletSharedState {
                            state,
                            session,
                            sync_handles,
                            txn_subscribers,
                            pending_foreign_txns,
                            ..
                        } = &mut *mutex.lock().await;
                        // handle an event
                        let summary = state.handle_event(session, event).await;
                        for (txn_uid, status) in summary.updated_txns {
                            // signal any await_transaction() futures which should complete due to a
                            // transaction having been completed.
                            if status.is_final() {
                                for sender in txn_subscribers.remove(&txn_uid).into_iter().flatten()
                                {
                                    // It is ok to ignore errors here; they just mean the receiver
                                    // has disconnected.
                                    sender.send(status).ok();
                                }
                            }
                        }
                        // For any await_transaction() futures waiting on foreign transactions which
                        // were just accepted, move them to the awaiting memos state.
                        for (n, uid) in summary.spent_nullifiers {
                            if let Some(subscribers) = pending_foreign_txns.remove(&n) {
                                foreign_txns_awaiting_memos
                                    .entry(uid)
                                    .or_insert_with(Vec::new)
                                    .extend(subscribers);
                            }
                        }
                        // Signal await_transaction() futures with a Rejected state for all rejected
                        // nullifiers.
                        for n in summary.rejected_nullifiers {
                            for sender in pending_foreign_txns.remove(&n).into_iter().flatten() {
                                sender.send(TransactionState::Rejected).ok();
                            }
                        }
                        // Signal any await_transaction() futures that are waiting on foreign
                        // transactions whose memos just arrived.
                        for (_, uid) in summary.received_memos {
                            for sender in foreign_txns_awaiting_memos
                                .remove(&uid)
                                .into_iter()
                                .flatten()
                            {
                                sender.send(TransactionState::Retired).ok();
                            }
                        }

                        // signal any sync() futures which should complete after the last event
                        for handle in sync_handles.remove(&state.now).into_iter().flatten() {
                            handle.send(()).ok();
                        }
                    }
                },
                || (),
            );
            scope
        };

        Ok(Self {
            mutex,
            _event_task: event_task,
        })
    }

    pub fn pub_key(&self) -> UserPubKey {
        let WalletSharedState { state, session, .. } = &*block_on(self.mutex.lock());
        state.pub_key(session)
    }

    pub fn auditor_pub_key(&self) -> AuditorPubKey {
        let WalletSharedState { state, .. } = &*block_on(self.mutex.lock());
        state.auditor_key_pair.pub_key()
    }

    pub fn freezer_pub_key(&self) -> FreezerPubKey {
        let WalletSharedState { state, .. } = &*block_on(self.mutex.lock());
        state.freezer_key_pair.pub_key()
    }

    pub fn address(&self) -> UserAddress {
        self.pub_key().address()
    }

    pub async fn balance(&self, asset: &AssetCode) -> u64 {
        let WalletSharedState { state, session, .. } = &*self.mutex.lock().await;
        state.balance(session, asset, FreezeFlag::Unfrozen)
    }

    pub async fn frozen_balance(&self, asset: &AssetCode) -> u64 {
        let WalletSharedState { state, session, .. } = &*self.mutex.lock().await;
        state.balance(session, asset, FreezeFlag::Frozen)
    }

    pub async fn assets(&self) -> HashMap<AssetCode, AssetInfo> {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.assets()
    }

    pub async fn transfer(
        &mut self,
        asset: &AssetCode,
        receivers: &[(UserAddress, u64)],
        fee: u64,
    ) -> Result<TransactionReceipt, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.transfer(session, asset, receivers, fee).await
    }

    /// define a new asset and store secret info for minting
    pub async fn define_asset(
        &mut self,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let WalletSharedState { state, .. } = &mut *self.mutex.lock().await;
        state.define_asset(description, policy)
    }

    /// create a mint note that assign asset to an owner
    pub async fn mint(
        &mut self,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.mint(session, fee, asset_code, amount, owner).await
    }

    pub async fn freeze(
        &mut self,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.freeze(session, fee, asset, amount, owner).await
    }

    pub async fn unfreeze(
        &mut self,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.unfreeze(session, fee, asset, amount, owner).await
    }

    pub async fn transaction_status(
        &self,
        receipt: &TransactionReceipt,
    ) -> Result<TransactionState, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.transaction_status(session, receipt).await
    }

    pub async fn await_transaction(
        &self,
        receipt: &TransactionReceipt,
    ) -> Result<TransactionState, WalletError> {
        let mut guard = self.mutex.lock().await;
        let WalletSharedState {
            state,
            session,
            txn_subscribers,
            pending_foreign_txns,
            ..
        } = &mut *guard;

        let status = state.transaction_status(session, receipt).await?;
        if status.is_final() {
            Ok(status)
        } else {
            let (sender, receiver) = oneshot::channel();

            if receipt.submitter == session.key_pair.address() {
                // If we submitted this transaction, we have all the information we need to track it
                // through the lifecycle based on its uid alone.
                txn_subscribers
                    .entry(receipt.uid.clone())
                    .or_insert_with(Vec::new)
                    .push(sender);
            } else {
                // Transaction uids are unique only to a given wallet, so if we're trying to track
                // somebody else's transaction, the best we can do is wait for one of its nullifiers
                // to be published on the ledger.
                pending_foreign_txns
                    .entry(receipt.fee_nullifier)
                    .or_insert_with(Vec::new)
                    .push(sender);
            }
            drop(guard);
            receiver.await.map_err(|_| WalletError::Cancelled {})
        }
    }

    pub async fn sync(&self, t: u64) -> Result<(), oneshot::Canceled> {
        let mut guard = self.mutex.lock().await;
        let WalletSharedState {
            state,
            sync_handles,
            ..
        } = &mut *guard;

        if state.now < t {
            let (sender, receiver) = oneshot::channel();
            sync_handles.entry(t).or_insert_with(Vec::new).push(sender);
            drop(guard);
            receiver.await
        } else {
            Ok(())
        }
    }
}

pub fn new_key_pair() -> UserKeyPair {
    UserKeyPair::generate(&mut ChaChaRng::from_entropy())
}

#[cfg(any(test, fuzzing))]
pub mod test_helpers {
    use super::*;
    use crate::{
        node, Block, ElaboratedBlock, TransactionVerifyingKey, VerifierKeySet, MERKLE_HEIGHT,
        UNIVERSAL_PARAM,
    };
    use futures::channel::mpsc as channel;
    use futures::future;
    use itertools::izip;
    use phaselock::traits::state::State;
    use phaselock::BlockContents;
    use rand_chacha::rand_core::RngCore;
    use std::iter::once;
    use std::sync::Mutex as SyncMutex;
    use std::time::Instant;

    pub struct MockLedger<'a> {
        pub validator: ValidatorState,
        nullifiers: SetMerkleTree,
        subscribers: Vec<channel::UnboundedSender<LedgerEvent>>,
        current_block: ElaboratedBlock,
        committed_blocks: Vec<(ElaboratedBlock, Vec<Vec<u64>>)>,
        block_size: usize,
        hold_next_transaction: bool,
        held_transaction: Option<ElaboratedTransaction>,
        proving_keys: ProverKeySet<'a, key_set::OrderByOutputs>,
        address_map: HashMap<UserAddress, UserPubKey>,
        events: Vec<LedgerEvent>,
    }

    impl<'a> MockLedger<'a> {
        pub fn now(&self) -> u64 {
            self.events.len() as u64
        }

        fn generate_event(&mut self, e: LedgerEvent) {
            self.events.push(e.clone());
            for s in self.subscribers.iter_mut() {
                s.start_send(e.clone()).unwrap();
            }
        }

        fn flush(&mut self) {
            let block = std::mem::replace(&mut self.current_block, self.validator.next_block());
            match self.validator.validate_and_apply(
                self.validator.prev_commit_time + 1,
                block.block.clone(),
                block.proofs.clone(),
                true,
            ) {
                Ok(mut uids) => {
                    // Add nullifiers
                    for txn in &block.block.0 {
                        for nullifier in txn.nullifiers() {
                            self.nullifiers.insert(nullifier);
                        }
                    }

                    // Broadcast the new block
                    self.generate_event(LedgerEvent::Commit {
                        block: block.clone(),
                        block_id: self.committed_blocks.len() as u64,
                        state_comm: self.validator.commit(),
                    });

                    // Store the block in the history
                    let mut block_uids = vec![];
                    for txn in block.block.0.iter() {
                        let mut this_txn_uids = uids;
                        uids = this_txn_uids.split_off(txn.output_len());
                        assert_eq!(this_txn_uids.len(), txn.output_len());
                        block_uids.push(this_txn_uids);
                    }
                    self.committed_blocks.push((block, block_uids));
                }
                Err(error) => self.generate_event(LedgerEvent::Reject { block, error }),
            }
        }

        pub fn hold_next_transaction(&mut self) {
            self.hold_next_transaction = true;
        }

        pub fn release_held_transaction(&mut self) -> Option<ElaboratedTransaction> {
            if let Some(txn) = self.held_transaction.take() {
                self.submit(txn.clone());
                Some(txn)
            } else {
                None
            }
        }

        pub fn submit(&mut self, txn: ElaboratedTransaction) {
            if self.hold_next_transaction {
                self.held_transaction = Some(txn);
                self.hold_next_transaction = false;
                return;
            }

            match self.current_block.add_transaction_raw(&txn) {
                Ok(block) => {
                    self.current_block = block;
                    // self.current_memos.push(memos);
                    if self.current_block.block.0.len() >= self.block_size {
                        self.flush();
                    }
                }
                Err(error) => {
                    let rejected = ElaboratedBlock {
                        block: Block(vec![txn.txn]),
                        proofs: vec![txn.proofs],
                    };
                    self.generate_event(LedgerEvent::Reject {
                        block: rejected,
                        error,
                    });
                }
            }
        }

        pub fn post_memos(
            &mut self,
            block_id: u64,
            txn_id: u64,
            memos: Vec<ReceiverMemo>,
            sig: Signature,
        ) -> Result<(), WalletError> {
            let (block, block_uids) = &self.committed_blocks[block_id as usize];
            let txn = &block.block.0[txn_id as usize];
            let comms = txn.output_commitments();
            let uids = block_uids[txn_id as usize].clone();

            txn.verify_receiver_memos_signature(&memos, &sig)
                .context(CryptoError)?;

            let merkle_paths = uids
                .iter()
                .map(|uid| {
                    self.validator
                        .record_merkle_frontier
                        .get_leaf(*uid)
                        .expect_ok()
                        .unwrap()
                        .1
                })
                .collect::<Vec<_>>();
            self.generate_event(LedgerEvent::Memos {
                outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            });

            Ok(())
        }
    }

    pub async fn sync<'a>(
        ledger: &Arc<SyncMutex<MockLedger<'a>>>,
        wallets: &[Wallet<'a, impl 'a + WalletBackend<'a> + Send + Sync>],
    ) {
        let t = {
            let ledger = ledger.lock().unwrap();
            if let Some(LedgerEvent::Commit { .. }) = ledger.events.last() {
                // If the last event is a Commit, wait until the sender receives the Commit event
                // and posts the receiver memos, generating a new Memos event.
                ledger.now() + 1
            } else {
                ledger.now()
            }
        };
        sync_with(wallets, t).await;
    }

    pub async fn sync_with<'a>(
        wallets: &[Wallet<'a, impl 'a + WalletBackend<'a> + Send + Sync>],
        t: u64,
    ) {
        println!("waiting for sync point {}", t);
        future::join_all(wallets.iter().map(|wallet| wallet.sync(t))).await;
    }

    #[derive(Clone)]
    pub struct MockWalletBackend<'a> {
        ledger: Arc<SyncMutex<MockLedger<'a>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
        seed: [u8; 32],
    }

    #[async_trait]
    impl<'a> WalletBackend<'a> for MockWalletBackend<'a> {
        type EventStream = channel::UnboundedReceiver<LedgerEvent>;

        async fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
            let ledger = self.ledger.lock().unwrap();
            assert_eq!(
                ledger.now(),
                0,
                "MockWalletBackend does not support restartability"
            );
            let mut rng = ChaChaRng::from_seed(self.seed);
            Ok(WalletState {
                validator: ledger.validator.clone(),
                proving_keys: ledger.proving_keys.clone(),
                records: {
                    let mut db: RecordDatabase = Default::default();
                    for (ro, uid) in self.initial_grants.iter() {
                        db.insert(ro.clone(), *uid, key_pair);
                    }
                    db
                },
                nullifiers: ledger.nullifiers.clone(),
                defined_assets: HashMap::new(),
                now: 0,
                pending_txns: Default::default(),
                expiring_txns: Default::default(),
                transactions_awaiting_memos: Default::default(),
                uids_awaiting_memos: Default::default(),
                transactions: Default::default(),
                auditable_assets: Default::default(),
                auditor_key_pair: AuditorKeyPair::generate(&mut rng),
                freezer_key_pair: FreezerKeyPair::generate(&mut rng),
                rng,
            })
        }

        async fn store(
            &mut self,
            _key_pair: &UserKeyPair,
            _state: &WalletState,
        ) -> Result<(), WalletError> {
            unimplemented!("MockWalletBackend does not support persistence");
        }

        async fn subscribe(&self, starting_at: u64) -> Self::EventStream {
            let mut ledger = self.ledger.lock().unwrap();
            assert_eq!(
                starting_at,
                ledger.now(),
                "subscribing from a historical state is not supported in the MockWalletBackend"
            );
            let (sender, receiver) = channel::unbounded();
            ledger.subscribers.push(sender);
            receiver
        }

        async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
            let ledger = self.ledger.lock().unwrap();
            match ledger.address_map.get(address) {
                Some(key) => Ok(key.clone()),
                None => Err(WalletError::InvalidAddress {
                    address: address.clone(),
                }),
            }
        }

        async fn get_nullifier_proof(
            &self,
            root: set_hash::Hash,
            nullifier: Nullifier,
        ) -> Result<(bool, SetMerkleProof), WalletError> {
            let ledger = self.ledger.lock().unwrap();
            if root == ledger.nullifiers.hash() {
                Ok(ledger.nullifiers.contains(nullifier).unwrap())
            } else {
                Err(WalletError::QueryServiceError {
                    source: node::QueryServiceError::InvalidNullifierRoot {},
                })
            }
        }

        async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
            self.ledger.lock().unwrap().submit(txn);
            Ok(())
        }

        async fn post_memos(
            &mut self,
            block_id: u64,
            txn_id: u64,
            memos: Vec<ReceiverMemo>,
            sig: Signature,
        ) -> Result<(), WalletError> {
            self.ledger
                .lock()
                .unwrap()
                .post_memos(block_id, txn_id, memos, sig)
        }
    }

    pub async fn create_test_network<'a>(
        xfr_sizes: &[(usize, usize)],
        initial_grants: Vec<u64>,
        now: &mut Instant,
    ) -> (
        Arc<SyncMutex<MockLedger<'a>>>,
        Vec<Wallet<'a, MockWalletBackend<'a>>>,
    ) {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);

        // Populate the unpruned record merkle tree with an initial record commitment for each
        // non-zero initial grant. Collect user-specific info (keys and record openings
        // corresponding to grants) in `users`, which will be used to create the wallets later.
        let mut record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        let mut users = vec![];
        for amount in initial_grants {
            let key = UserKeyPair::generate(&mut rng);
            if amount > 0 {
                let ro = RecordOpening::new(
                    &mut rng,
                    amount,
                    AssetDefinition::native(),
                    key.pub_key(),
                    FreezeFlag::Unfrozen,
                );
                let comm = RecordCommitment::from(&ro);
                let uid = record_merkle_tree.num_leaves();
                record_merkle_tree.push(comm.to_field_element());
                users.push((key, vec![(ro, uid)]));
            } else {
                users.push((key, vec![]));
            }
        }

        // Create the validator using the ledger state containing the initial grants, computed above.
        println!(
            "Generating validator keys: {}s",
            now.elapsed().as_secs_f32()
        );
        *now = Instant::now();

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_txn::proof::transfer::preprocess(
                &*UNIVERSAL_PARAM,
                *num_inputs,
                *num_outputs,
                MERKLE_HEIGHT,
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, mint_verif_key, _) =
            jf_txn::proof::mint::preprocess(&*UNIVERSAL_PARAM, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_txn::proof::freeze::preprocess(&*UNIVERSAL_PARAM, 2, MERKLE_HEIGHT).unwrap();
        let nullifiers: SetMerkleTree = Default::default();
        let validator = ValidatorState::new(
            VerifierKeySet {
                xfr: KeySet::new(xfr_verif_keys.into_iter()).unwrap(),
                mint: TransactionVerifyingKey::Mint(mint_verif_key),
                freeze: KeySet::new(
                    vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
                )
                .unwrap(),
            },
            record_merkle_tree,
        );

        let comm = validator.commit();
        println!(
            "Validator set up with state {:x?}: {}s",
            comm,
            now.elapsed().as_secs_f32()
        );

        let current_block = validator.next_block();
        let ledger = Arc::new(SyncMutex::new(MockLedger {
            validator,
            nullifiers,
            subscribers: Vec::new(),
            current_block,
            committed_blocks: Vec::new(),
            block_size: 1,
            hold_next_transaction: false,
            held_transaction: None,
            proving_keys: ProverKeySet {
                xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                mint: mint_prove_key,
                freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
            },
            address_map: users
                .iter()
                .map(|(key, _)| (key.address(), key.pub_key()))
                .collect(),
            events: Vec::new(),
        }));

        // Create a wallet for each user based on the validator and the per-user information
        // computed above.
        let wallets = iter(users)
            .then(|(key, initial_grants)| {
                let mut rng = ChaChaRng::from_rng(&mut rng).unwrap();
                let ledger = ledger.clone();
                async move {
                    let mut seed = [0u8; 32];
                    rng.fill_bytes(&mut seed);
                    Wallet::new(
                        key,
                        MockWalletBackend {
                            ledger,
                            initial_grants,
                            seed,
                        },
                    )
                    .await
                    .unwrap()
                }
            })
            .collect()
            .await;

        println!("Wallets set up: {}s", now.elapsed().as_secs_f32());
        *now = Instant::now();
        (ledger, wallets)
    }

    /*
     * This test is very similar to test_two_wallets, but it is parameterized on the number of users,
     * number of asset types, initial ledger state, and transactions to do, so it can be used with
     * quickcheck or proptest to do randomized fuzzing.
     */
    #[allow(clippy::type_complexity)]
    pub async fn test_multixfr_wallet(
        // List of blocks containing (def,key1,key2,amount) transfer specs
        // An asset def of 0 in a transfer spec or record indicates the native asset type; other
        // asset types are indexed startin from 1.
        txs: Vec<Vec<(u8, u8, u8, u64)>>,
        nkeys: u8,
        ndefs: u8,
        // (def,key,amount)
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>,
    ) {
        println!(
            "multixfr_wallet test: {} users, {} assets, {} records, {} transfers",
            nkeys,
            ndefs,
            init_recs.len() + 1,
            txs.iter().flatten().count()
        );
        let mut now = Instant::now();

        let xfr_sizes = &[
            (1, 2), // basic native transfer
            (2, 2), // basic non-native transfer, or native merge
            (2, 3), // non-native transfer with change output
            (3, 2), // non-native merge
        ];
        let mut balances = vec![vec![0; ndefs as usize + 1]; nkeys as usize];
        let grants =
            // The issuer (wallet 0) gets 1 coin per initial record, to pay transaction fees while
            // it mints and distributes the records, and 1 coin per transaction, to pay transaction
            // fees while minting additional records if test wallets run out of balance during the
            // test.
            once((1 + init_recs.len() + txs.iter().flatten().count()) as u64).chain(
                (0..nkeys)
                    .map(|i| {
                        // The remaining wallets (the test wallets) get 1 coin for each transaction
                        // in which they are the sender, to pay transaction fees, plus...
                        let txn_fees = txs.iter()
                            .flatten()
                            .map(|(_, sender, _, _)| {
                                if sender % nkeys == i {1} else {0}
                            })
                            .sum::<u64>();
                        balances[i as usize][0] += txn_fees;
                        txn_fees +
                        // ...one record for each native asset type initial record that they own,
                        // plus...
                        once(&init_rec).chain(&init_recs)
                            .map(|(def, owner, amount)| {
                                let def = (def % (ndefs + 1)) as usize;
                                let owner = (owner % nkeys) as usize;
                                if def == 0 && owner == (i as usize) {
                                    balances[owner][def] += amount;
                                    *amount
                                } else {
                                    0
                                }
                            })
                            .sum::<u64>() +
                        // We want to prevent transfers of the native asset type from failing due to
                        // insufficient funds, or worse, from dipping into native coins which were
                        // intended to be used later as transaction fees. Unlike non-native
                        // transfers, we can't mint more native coins during the test if we find
                        // that one of the wallets is low on balance. So we give each wallet an
                        // extra grant of native coins large enough to cover all the native
                        // transactions it will need to make, when combined with its original grant
                        // of native coins.
                        {
                            let total_txn_amount: u64 = txs.iter()
                                .flatten()
                                .map(|(def, sender, _, amount)| {
                                    if (def % (ndefs + 1)) == 0 && (sender % nkeys) == i {
                                        *amount
                                    } else {
                                        0
                                    }
                                })
                                .sum();
                            if txn_fees + total_txn_amount > balances[i as usize][0] {
                                let extra = txn_fees + total_txn_amount - balances[i as usize][0];
                                balances[i as usize][0] += extra;
                                extra
                            } else {
                                0
                            }
                        }
                    })
            ).collect();

        let (ledger, mut wallets) = create_test_network(xfr_sizes, grants, &mut now).await;
        println!(
            "ceremony complete, minting initial records: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        // Define all of the test assets and mint initial records.
        let mut assets = vec![];
        for i in 0..ndefs {
            assets.push(
                wallets[0]
                    .define_asset(format!("Asset {}", i).as_bytes(), Default::default())
                    .await
                    .unwrap(),
            );
        }
        for (asset, owner, amount) in once(init_rec).chain(init_recs) {
            let asset = (asset % (ndefs + 1)) as usize;
            if asset == 0 {
                // can't mint native assets
                continue;
            }
            let address = wallets[(owner % nkeys) as usize + 1].address();
            balances[(owner % nkeys) as usize][asset] += amount;
            wallets[0]
                .mint(1, &assets[asset - 1].code, amount, address)
                .await
                .unwrap();
            sync(&ledger, &wallets).await;
        }

        println!("assets minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check initial balances. This cannot be a closure because rust infers the wrong lifetime
        // for the references (it tries to use 'a, which is longer than we want to borrow `wallets`
        // for).
        async fn check_balances<'a>(
            wallets: &[Wallet<'a, MockWalletBackend<'a>>],
            balances: &[Vec<u64>],
            assets: &[AssetDefinition],
        ) {
            for (i, balance) in balances.iter().enumerate() {
                let wallet = &wallets[i + 1];

                // Check native asset balance.
                assert_eq!(wallet.balance(&AssetCode::native()).await, balance[0]);
                for (j, asset) in assets.iter().enumerate() {
                    assert_eq!(wallet.balance(&asset.code).await, balance[j + 1]);
                }
            }
        }
        check_balances(&wallets, &balances, &assets).await;

        // Run the test transactions.
        for (i, block) in txs.iter().enumerate() {
            println!(
                "Starting block {}/{}: {}s",
                i + 1,
                txs.len(),
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();

            // TODO process block as a batch. For now, do txs one by one.
            for (j, (asset_ix, sender_ix, receiver_ix, amount)) in block.iter().enumerate() {
                println!(
                    "Starting txn {}.{}/{}:{:?}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    (asset_ix, sender_ix, receiver_ix, amount),
                    now.elapsed().as_secs_f32()
                );

                let asset_ix = (asset_ix % (ndefs + 1)) as usize;
                let sender_ix = (sender_ix % nkeys) as usize;
                let receiver_ix = (receiver_ix % nkeys) as usize;
                let native = AssetDefinition::native();
                let asset = if asset_ix == 0 {
                    &native
                } else {
                    &assets[asset_ix - 1]
                };
                let receiver = wallets[receiver_ix + 1].address();
                let sender_address = wallets[sender_ix + 1].address();
                let sender_balance = wallets[sender_ix + 1].balance(&asset.code).await;

                let mut amount = if *amount <= sender_balance {
                    *amount
                } else if sender_balance > 0 {
                    // If we don't have enough to make the whole transfer, but we have some,
                    // transfer half of what we have.
                    let new_amount = std::cmp::max(sender_balance / 2, 1);
                    println!(
                        "decreasing transfer amount due to insufficient balance: {} -> {}: {}s",
                        *amount,
                        new_amount,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    new_amount
                } else {
                    // If we don't have any of this asset type, mint more.
                    assert_ne!(asset, &AssetDefinition::native());
                    println!(
                        "minting {} more of asset {:?}: {}s",
                        *amount,
                        &asset.code,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    wallets[0]
                        .mint(1, &asset.code, 2 * amount, sender_address)
                        .await
                        .unwrap();
                    sync(&ledger, &wallets).await;
                    balances[sender_ix][asset_ix] += 2 * amount;

                    println!("asset minted: {}s", now.elapsed().as_secs_f32());
                    now = Instant::now();
                    *amount
                };

                ledger.lock().unwrap().hold_next_transaction();
                let sender = &mut wallets[sender_ix + 1];
                match sender
                    .transfer(&asset.code, &[(receiver.clone(), amount)], 1)
                    .await
                {
                    Ok(txn) => txn,
                    Err(WalletError::Fragmentation {
                        suggested_amount, ..
                    }) => {
                        // Allow fragmentation. Without merge transactions, there's not much we can
                        // do to prevent it, and merge transactions require multiple transaction
                        // arities, which requires either dummy records or multiple verifier keys in
                        // the validator.
                        if suggested_amount > 0 {
                            // If the wallet suggested a transaction amount that it _can_ process,
                            // try again with that amount.
                            println!(
                                "decreasing transfer amount due to fragmentation: {} -> {}: {}s",
                                amount,
                                suggested_amount,
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();

                            amount = suggested_amount;
                            sender
                                .transfer(&asset.code, &[(receiver, amount)], 1)
                                .await
                                .unwrap()
                        } else {
                            println!(
                                "skipping transfer due to fragmentation: {}s",
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();
                            continue;
                        }
                    }
                    Err(err) => {
                        panic!("transaction failed: {:?}", err)
                    }
                };
                println!("transaction generated: {}s", now.elapsed().as_secs_f32());
                now = Instant::now();

                balances[sender_ix][0] -= 1; // transaction fee
                balances[sender_ix][asset_ix] -= amount;
                balances[receiver_ix][asset_ix] += amount;

                // The sending wallet should report the new balance immediately, even before a
                // validator has confirmed the transaction, because the transferred records are
                // placed on hold until the transfer is confirmed or rejected.
                //
                // Note that the sender may report less than the final balance if it is waiting on a
                // change output to be confirmed.
                assert!(sender.balance(&native.code).await <= balances[sender_ix][0]);
                assert!(sender.balance(&asset.code).await <= balances[sender_ix][asset_ix]);

                ledger.lock().unwrap().release_held_transaction();
                sync(&ledger, &wallets).await;
                check_balances(&wallets, &balances, &assets).await;

                println!(
                    "Finished txn {}.{}/{}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    now.elapsed().as_secs_f32()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task::block_on;
    use jf_txn::NodeValue;
    use proptest::collection::vec;
    use proptest::strategy::Strategy;
    use std::time::Instant;
    use test_helpers::*;

    /*
     * Test idea: simulate two wallets transferring funds back and forth. After initial
     * setup, the wallets only receive publicly visible information (e.g. block commitment
     * events and receiver memos posted on bulletin boards). Check that both wallets are
     * able to maintain accurate balance statements and enough state to construct new transfers.
     *
     * - Alice magically starts with some coins, Bob starts empty.
     * - Alice transfers some coins to Bob using exact change.
     * - Alice and Bob check their balances, then Bob transfers some coins back to Alice, in an
     *   amount that requires a fee change record.
     *
     * Limitations:
     * - Parts of the system are mocked (e.g. consensus is replaced by one omniscient validator,
     *   info event streams, query services, and bulletin boards is provided directly to the
     *   wallets by the test)
     */
    #[allow(unused_assignments)]
    async fn test_two_wallets(native: bool) {
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice an initial grant of 5 native coins. If using non-native transfers, give Bob an
        // initial grant with which to pay his transaction fee, since he will not be receiving any
        // native coins from Alice.
        let alice_grant = 5;
        let bob_grant = if native { 0 } else { 1 };
        let (ledger, mut wallets) = create_test_network(
            &[(num_inputs, num_outputs)],
            vec![alice_grant, bob_grant],
            &mut now,
        )
        .await;
        let alice_address = wallets[0].address();
        let bob_address = wallets[1].address();

        // Verify initial wallet state.
        assert_ne!(alice_address, bob_address);
        assert_eq!(wallets[0].balance(&AssetCode::native()).await, alice_grant);
        assert_eq!(wallets[1].balance(&AssetCode::native()).await, bob_grant);

        let coin = if native {
            AssetDefinition::native()
        } else {
            let coin = wallets[0]
                .define_asset("Alice's asset".as_bytes(), Default::default())
                .await
                .unwrap();
            // Alice gives herself an initial grant of 5 coins.
            wallets[0]
                .mint(1, &coin.code, 5, alice_address.clone())
                .await
                .unwrap();
            sync(&ledger, &wallets).await;
            println!("Asset minted: {}s", now.elapsed().as_secs_f32());
            now = Instant::now();

            assert_eq!(wallets[0].balance(&coin.code).await, 5);
            assert_eq!(wallets[1].balance(&coin.code).await, 0);

            coin
        };

        let alice_initial_native_balance = wallets[0].balance(&AssetCode::native()).await;
        let bob_initial_native_balance = wallets[1].balance(&AssetCode::native()).await;

        // Construct a transaction to transfer some coins from Alice to Bob.
        wallets[0]
            .transfer(&coin.code, &[(bob_address, 3)], 1)
            .await
            .unwrap();
        sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both wallets reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `wallets` for).
        async fn check_balance<'a>(
            wallet: &Wallet<'a, MockWalletBackend<'a>>,
            expected_coin_balance: u64,
            starting_native_balance: u64,
            fees_paid: u64,
            coin: &AssetDefinition,
            native: bool,
        ) {
            if native {
                assert_eq!(
                    wallet.balance(&coin.code).await,
                    expected_coin_balance - fees_paid
                );
            } else {
                assert_eq!(wallet.balance(&coin.code).await, expected_coin_balance);
                assert_eq!(
                    wallet.balance(&AssetCode::native()).await,
                    starting_native_balance - fees_paid
                );
            }
        }
        check_balance(
            &wallets[0],
            2,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 3, bob_initial_native_balance, 0, &coin, native).await;

        // Check that Bob's wallet has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3 coins, but
        // the sum of the outputs and fee of this transaction is only 2.
        wallets[1]
            .transfer(&coin.code, &[(alice_address, 1)], 1)
            .await
            .unwrap();
        sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        check_balance(
            &wallets[0],
            3,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 2, bob_initial_native_balance, 1, &coin, native).await;
    }

    #[async_std::test]
    async fn test_two_wallets_native() -> std::io::Result<()> {
        test_two_wallets(true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_two_wallets_non_native() -> std::io::Result<()> {
        test_two_wallets(false).await;
        Ok(())
    }

    // Test transactions that fail to complete.
    //
    // If `native`, the transaction is a native asset transfer.
    // If `!native && !mint && !freeze`, the transaction is a non-native asset transfer.
    // If `!native && mint`, the transaction is a non-native asset mint.
    // If `!native && freeze`, the transaction is a non-native asset freeze.
    //
    // If `timeout`, the failed transaction times out with no explicit rejection event. Otherwise,
    // the failed transaction fails to verify and a Reject event is emitted.
    //
    // (native, mint), (native, freeze), and (mint, freeze) are pairs of mutually exclusive flags.
    async fn test_wallet_rejected(native: bool, mint: bool, freeze: bool, timeout: bool) {
        assert!(!(native && mint));
        assert!(!(native && freeze));
        assert!(!(mint && freeze));

        let mut now = Instant::now();

        // Native transfers have extra fee/change inputs/outputs.
        let num_inputs = if native { 1 } else { 2 };
        let num_outputs = if native { 2 } else { 3 };

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment (or, for non-native transfers, a transaction fee and a mint fee). wallets[1] will
        // act as the receiver, and wallets[2] will be a third party which generates
        // RECORD_HOLD_TIME transfers while a transfer from wallets[0] is pending, causing the
        // transfer to time out.
        let (ledger, mut wallets) = create_test_network(
            &[(num_inputs, num_outputs)],
            // If native, wallets[0] gets 1 coin to transfer and 1 for a transaction fee. Otherwise,
            // it gets
            //  * 1 transaction fee
            //  * 1 mint fee for its initial non-native record, if the test itself is not minting
            //    that record
            //  * 1 mint fee for wallets[2]'s initial non-native record in the timeout test.
            vec![
                if native {
                    2
                } else {
                    1 + !mint as u64 + timeout as u64
                },
                0,
                2 * RECORD_HOLD_TIME,
            ],
            &mut now,
        )
        .await;

        let asset = if native {
            AssetDefinition::native()
        } else {
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(wallets[0].auditor_pub_key())
                .set_freezer_pub_key(wallets[0].freezer_pub_key())
                .reveal_record_opening()
                .unwrap();
            let asset = wallets[0]
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            if !mint {
                // If we're freezing, the transaction is essentially taking balance away from
                // wallets[1], so wallets[1] gets 1 coin to start with. Otherwise, the transaction
                // is transferring balance from wallets[0] to wallets[1], so  wallets[0] gets 1
                // coin. We only need this if the test itself is not minting the asset later on.
                let dst = if freeze {
                    wallets[1].address()
                } else {
                    wallets[0].address()
                };
                wallets[0].mint(1, &asset.code, 1, dst).await.unwrap();
                sync(&ledger, &wallets).await;
            }

            if timeout {
                // If doing a timeout test, wallets[2] (the sender that will generate enough
                // transactions to cause wallets[0]'s transaction to timeout) gets RECORD_HOLD_TIME
                // coins.
                let dst = wallets[2].address();
                wallets[0]
                    .mint(1, &asset.code, RECORD_HOLD_TIME, dst)
                    .await
                    .unwrap();
                sync(&ledger, &wallets).await;
            }

            asset
        };

        // Start a transfer that will ultimately get rejected.
        println!(
            "generating a transfer which will fail: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        ledger.lock().unwrap().hold_next_transaction();
        let receiver = wallets[1].address();
        if mint {
            wallets[0]
                .mint(1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else if freeze {
            wallets[0]
                .freeze(1, &asset, 1, receiver.clone())
                .await
                .unwrap();
        } else {
            wallets[0]
                .transfer(&asset.code, &[(receiver.clone(), 1)], 1)
                .await
                .unwrap();
        }
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that the sender's balance is on hold (for the fee and the payment).
        assert_eq!(wallets[0].balance(&AssetCode::native()).await, 0);
        if !freeze {
            assert_eq!(wallets[0].balance(&asset.code).await, 0);
        }

        // Now do something that causes the sender's transaction to not go through
        if timeout {
            // Generate RECORD_HOLD_TIME transactions to cause `txn` to time out.
            println!(
                "generating {} transfers to time out the original transfer: {}s",
                RECORD_HOLD_TIME,
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();
            for _ in 0..RECORD_HOLD_TIME {
                // Check that the sender's balance is still on hold.
                assert_eq!(wallets[0].balance(&AssetCode::native()).await, 0);
                if !freeze {
                    assert_eq!(wallets[0].balance(&asset.code).await, 0);
                }

                wallets[2]
                    .transfer(&asset.code, &[(receiver.clone(), 1)], 1)
                    .await
                    .unwrap();
                sync(&ledger, &wallets).await;
            }
        } else {
            {
                let mut ledger = ledger.lock().unwrap();

                // Change the validator state, so that the wallet's transaction (built against the
                // old validator state) will fail to validate.
                let old_record_merkle_root = ledger.validator.record_merkle_root;
                ledger.validator.record_merkle_root = NodeValue::from(0);

                println!(
                    "validating invalid transaction: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
                ledger.release_held_transaction();

                // The sender gets back in sync with the validator after their transaction is
                // rejected.
                ledger.validator.record_merkle_root = old_record_merkle_root;
            }

            sync(&ledger, &wallets).await;
        }

        // Check that the sender got their balance back.
        if native {
            assert_eq!(wallets[0].balance(&AssetCode::native()).await, 2);
        } else {
            assert_eq!(wallets[0].balance(&AssetCode::native()).await, 1);
            if !(mint || freeze) {
                // in the mint and freeze cases, we never had a non-native balance to start with
                assert_eq!(wallets[0].balance(&asset.code).await, 1);
            }
        }
        assert_eq!(
            wallets[1].balance(&asset.code).await,
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 1 } else { 0 })
        );

        // Now check that they can use the un-held record if their state gets back in sync with the
        // validator.
        println!(
            "transferring un-held record: {}s",
            now.elapsed().as_secs_f32()
        );
        if mint {
            wallets[0].mint(1, &asset.code, 1, receiver).await.unwrap();
        } else if freeze {
            wallets[0].freeze(1, &asset, 1, receiver).await.unwrap();
        } else {
            wallets[0]
                .transfer(&asset.code, &[(receiver, 1)], 1)
                .await
                .unwrap();
        }
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&AssetCode::native()).await, 0);
        assert_eq!(wallets[0].balance(&asset.code).await, 0);
        assert_eq!(
            wallets[1].balance(&asset.code).await,
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 0 } else { 1 })
        );
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_invalid() -> std::io::Result<()> {
        test_wallet_rejected(true, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_timeout() -> std::io::Result<()> {
        test_wallet_rejected(true, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, true, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, true, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, false, true, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, false, true, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_resubmit() -> std::io::Result<()> {
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment. wallets[1] will act as the receiver, and wallets[2] will be a third party
        // which generates RECORD_ROOT_HISTORY_SIZE-1 transfers while a transfer from wallets[0] is
        // pending, after which we will check if the pending transaction can be updated and
        // resubmitted.
        let (ledger, mut wallets) = create_test_network(
            &[(1, 2)],
            vec![
                2,
                0,
                2 * (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64,
            ],
            &mut now,
        )
        .await;

        println!("generating transaction: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        ledger.lock().unwrap().hold_next_transaction();
        let receiver = wallets[1].address();
        wallets[0]
            .transfer(&AssetCode::native(), &[(receiver.clone(), 1)], 1)
            .await
            .unwrap();
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Generate a transaction, invalidating the pending transfer.
        println!(
            "generating {} transfers to invalidate the original transfer: {}s",
            ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1,
            now.elapsed().as_secs_f32(),
        );
        now = Instant::now();
        for _ in 0..ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1 {
            wallets[2]
                .transfer(&AssetCode::native(), &[(receiver.clone(), 1)], 1)
                .await
                .unwrap();
            sync(&ledger, &wallets).await;
        }

        // Check that the pending transaction eventually succeeds, after being automatically
        // resubmitted by the wallet.
        println!(
            "submitting invalid transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        let ledger_time = ledger.lock().unwrap().now();
        ledger.lock().unwrap().release_held_transaction().unwrap();
        // Wait for 3 events: the first Reject event, then a later Commit event after the wallet
        // resubmits, and finally a Memos event after the wallet receives the Commit event and posts
        // the receiver memos.
        sync_with(&wallets, ledger_time + 3).await;
        assert_eq!(wallets[0].balance(&AssetCode::native()).await, 0);
        assert_eq!(
            wallets[1].balance(&AssetCode::native()).await,
            1 + (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_freeze() -> std::io::Result<()> {
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 1 for a transfer fee. wallets[1]
        // will act as the receiver, and wallets[2] will be a third party which issues and freezes
        // some of wallets[0]'s assets. It gets a grant of 3, for a mint fee, a freeze fee and an
        // unfreeze fee.
        //
        // Note that the transfer proving key size (3, 4) used here is chosen to be 1 larger than
        // necessary in both inputs and outputs, to test dummy records.
        let (ledger, mut wallets) = create_test_network(&[(3, 4)], vec![1, 0, 3], &mut now).await;

        let asset = {
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(wallets[2].auditor_pub_key())
                .set_freezer_pub_key(wallets[2].freezer_pub_key())
                .reveal_record_opening()
                .unwrap();
            let asset = wallets[2]
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            // wallets[0] gets 1 coin to transfer to wallets[1].
            let dst = wallets[0].address();
            wallets[2].mint(1, &asset.code, 1, dst).await.unwrap();
            sync(&ledger, &wallets).await;

            asset
        };
        assert_eq!(wallets[0].balance(&asset.code).await, 1);
        assert_eq!(wallets[0].frozen_balance(&asset.code).await, 0);

        // Now freeze wallets[0]'s record.
        println!(
            "generating a freeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let dst = wallets[0].address();
        ledger.lock().unwrap().hold_next_transaction();
        wallets[2].freeze(1, &asset, 1, dst.clone()).await.unwrap();

        // Check that, like transfer inputs, freeze inputs are placed on hold and unusable while a
        // freeze that uses them is pending.
        match wallets[2].freeze(1, &asset, 1, dst).await {
            Err(WalletError::InsufficientBalance { .. }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now go ahead with the original freeze.
        ledger.lock().unwrap().release_held_transaction();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code).await, 0);
        assert_eq!(wallets[0].frozen_balance(&asset.code).await, 1);

        // Check that trying to transfer fails due to frozen balance.
        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        let dst = wallets[1].address();
        match wallets[0].transfer(&asset.code, &[(dst, 1)], 1).await {
            Err(WalletError::InsufficientBalance { .. }) => {
                println!(
                    "transfer correctly failed due to frozen balance: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
            }
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now unfreeze the asset and try again.
        println!(
            "generating an unfreeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let dst = wallets[0].address();
        wallets[2].unfreeze(1, &asset, 1, dst).await.unwrap();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code).await, 1);
        assert_eq!(wallets[0].frozen_balance(&asset.code).await, 0);

        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        let dst = wallets[1].address();
        wallets[0]
            .transfer(&asset.code, &[(dst, 1)], 1)
            .await
            .unwrap();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code).await, 0);
        assert_eq!(wallets[0].frozen_balance(&asset.code).await, 0);
        assert_eq!(wallets[1].balance(&asset.code).await, 1);

        Ok(())
    }

    #[async_std::test]
    async fn test_multixfr_wallet_simple() -> std::io::Result<()> {
        let alice_grant = (0, 0, 3); // Alice gets 3 of coin 0 to start
        let bob_grant = (1, 1, 3); // Bob gets 3 of coin 1 to start
        let txns = vec![vec![
            (1, 0, 1, 2), // Alice sends 2 of coin 1 to Bob
            (2, 1, 0, 2), // Bob sends 2 of coin 2 to Alice
            (1, 1, 0, 1), // Bob sends 1 of coin 1 to Alice
        ]];
        test_multixfr_wallet(txns, 2, 2, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_multixfr_wallet_various_kinds() -> std::io::Result<()> {
        let txns = vec![vec![
            (0, 0, 1, 1), // native asset transfer
            (1, 0, 1, 1), // non-native asset transfer with change output
            (1, 0, 2, 1), // non-native asset transfer with exact change
        ]];
        let native_grant = (0, 0, 1);
        let non_native_grant = (1, 0, 3);
        test_multixfr_wallet(txns, 2, 1, native_grant, vec![non_native_grant]).await;
        Ok(())
    }

    struct MultiXfrParams {
        max_txns: usize,
        max_blocks: usize,
        max_keys: u8,
        max_defs: u8,
        max_amt: u64,
        max_recs: usize,
    }

    impl MultiXfrParams {
        const fn new(txns: usize, max_amt: u64) -> Self {
            // divide txns into 5 blocks
            let max_txns = if txns > 5 { txns / 5 } else { 1 };
            let max_blocks = if txns > 5 { 5 } else { txns };
            // fewer users than txns so we get multiple txns with same key
            let max_keys = (txns / 2 + 2) as u8;
            // fewer defs than txns so we get multiple txns with same def
            let max_defs = (txns / 2 + 1) as u8;
            // enough records to give everyone 1 of each type, on average
            // Reasoning for /4:
            //      E[nkeys] = max_keys/2
            //      E[ndefs] = max_defs/2
            // So
            //      E[nkeys*ndefs] = max_keys*max_defs/4
            let max_recs = max_keys as usize * max_defs as usize / 4;

            MultiXfrParams {
                max_txns,
                max_blocks,
                max_keys,
                max_defs,
                max_amt,
                max_recs,
            }
        }

        fn def(&self) -> impl Strategy<Value = u8> {
            // range is inclusive because def 0 is the native asset, and other asset defs are
            // 1-indexed
            0..=self.max_defs
        }

        fn key(&self) -> impl Strategy<Value = u8> {
            0..self.max_keys
        }

        fn txn_amt(&self) -> impl Strategy<Value = u64> {
            // Transaction amounts are smaller than record amounts because we don't want to burn a
            // whole record in one transaction.
            1..=std::cmp::max(self.max_amt / 5, 2)
        }

        fn amt(&self) -> impl Strategy<Value = u64> {
            1..=self.max_amt
        }

        fn txs(&self) -> impl Strategy<Value = Vec<Vec<(u8, u8, u8, u64)>>> {
            vec(
                vec(
                    (self.def(), self.key(), self.key(), self.txn_amt()),
                    self.max_txns,
                ),
                self.max_blocks,
            )
        }

        fn nkeys(&self) -> impl Strategy<Value = u8> {
            2..=self.max_keys
        }

        fn ndefs(&self) -> impl Strategy<Value = u8> {
            1..=self.max_defs
        }

        fn rec(&self) -> impl Strategy<Value = (u8, u8, u64)> {
            (self.def(), self.key(), self.amt())
        }

        fn recs(&self) -> impl Strategy<Value = Vec<(u8, u8, u64)>> {
            vec(self.rec(), self.max_recs)
        }
    }

    const MULTI_XFR_SMALL: MultiXfrParams = MultiXfrParams::new(5, 1000);
    const MULTI_XFR_LARGE: MultiXfrParams = MultiXfrParams::new(50, 1000);

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        fn proptest_multixfr_wallet_small(
            txs in MULTI_XFR_SMALL.txs(),
            nkeys in MULTI_XFR_SMALL.nkeys(),
            ndefs in MULTI_XFR_SMALL.ndefs(),
            init_rec in MULTI_XFR_SMALL.rec(),
            init_recs in MULTI_XFR_SMALL.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 10,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        #[ignore]
        fn proptest_multixfr_wallet_many_small_tests(
            txs in MULTI_XFR_SMALL.txs(),
            nkeys in MULTI_XFR_SMALL.nkeys(),
            ndefs in MULTI_XFR_SMALL.ndefs(),
            init_rec in MULTI_XFR_SMALL.rec(),
            init_recs in MULTI_XFR_SMALL.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        #[ignore]
        fn proptest_multixfr_wallet_one_big_test(
            txs in MULTI_XFR_LARGE.txs(),
            nkeys in MULTI_XFR_LARGE.nkeys(),
            ndefs in MULTI_XFR_LARGE.ndefs(),
            init_rec in MULTI_XFR_LARGE.rec(),
            init_recs in MULTI_XFR_LARGE.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }
}
