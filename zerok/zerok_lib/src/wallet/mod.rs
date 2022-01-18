pub mod cape;
pub mod cli;
pub mod encryption;
pub mod hd;
pub mod loader;
pub mod network;
pub mod persistence;
pub mod reader;
mod secret;
#[cfg(any(test, feature = "mocks"))]
pub mod testing;

use crate::api;
use crate::state::key_set;
use crate::txn_builder::*;
use crate::util::arbitrary_wrappers::{ArbitraryNullifier, ArbitraryUserKeyPair};
use crate::{
    events::{EventIndex, EventSource, LedgerEvent},
    ledger, ser_test,
    state::{ProverKeySet, ValidationError},
};
use arbitrary::{Arbitrary, Unstructured};
use async_scoped::AsyncScope;
use async_std::sync::{Mutex, MutexGuard};
use async_std::task::block_on;
use async_trait::async_trait;
use chrono::Local;
use core::fmt::Debug;
use futures::{
    channel::oneshot,
    prelude::*,
    stream::{iter, Stream},
};
use jf_aap::{
    errors::TxnApiError,
    freeze::FreezeNote,
    keys::{
        AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair,
        UserPubKey,
    },
    mint::MintNote,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier,
        ReceiverMemo, RecordCommitment, RecordOpening,
    },
    KeyPair as SigKeyPair, MerkleLeafProof, MerklePath, Signature, TransactionNote,
};
use ledger::{
    traits::{
        Block as _, NullifierSet as _, Transaction as _, TransactionKind as _, Validator as _,
    },
    *,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::repeat;
use std::sync::Arc;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub")]
pub enum WalletError {
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
    AssetNotAuditable {
        asset: AssetDefinition,
    },
    AssetNotFreezable {
        asset: AssetDefinition,
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
    PersistenceError {
        source: atomic_store::error::PersistenceError,
    },
    IoError {
        source: std::io::Error,
    },
    BincodeError {
        source: bincode::Error,
    },
    EncryptionError {
        source: encryption::Error,
    },
    KeyError {
        source: argon2::Error,
    },
    NoSuchAccount {
        address: UserAddress,
    },
    CannotDecryptMemo {},
    TransactionError {
        source: crate::txn_builder::TransactionError,
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

impl From<crate::txn_builder::TransactionError> for WalletError {
    fn from(source: crate::txn_builder::TransactionError) -> Self {
        Self::TransactionError { source }
    }
}

impl From<crate::node::QueryServiceError> for WalletError {
    fn from(source: crate::node::QueryServiceError) -> Self {
        Self::QueryServiceError { source }
    }
}

#[ser_test(arbitrary, ark(false))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackgroundKeyScan {
    key: UserKeyPair,
    next_event: EventIndex,
    to_event: EventIndex,
    // Record openings we have discovered which belong to these key. These records are kept in a
    // separate pool until the scan is complete so that if the scan encounters an event which spends
    // some of these records, we can remove the spent records without ever reflecting them in the
    // wallet's balance.
    records: HashMap<Nullifier, (RecordOpening, u64, MerklePath)>,
    // Nullifiers which have been published since we started the scan. Since we don't add records to
    // the wallet until the scan is complete, records we add here will not be invalidated by the
    // normal event handling loop. Thus, we must take care not to add records which have been
    // invalidated since the scan started.
    //
    // This means that retroactive scans only need to scan up to the latest event as of the start of
    // the scan, not until the scan catches up with the current event, which guarantees the scan
    // will complete in a finite amount of time.
    new_nullifiers: HashSet<Nullifier>,
}

impl PartialEq<Self> for BackgroundKeyScan {
    fn eq(&self, other: &Self) -> bool {
        self.key.pub_key() == other.key.pub_key()
            && self.next_event == other.next_event
            && self.to_event == other.to_event
            && self.records == other.records
            && self.new_nullifiers == other.new_nullifiers
    }
}

impl<'a> Arbitrary<'a> for BackgroundKeyScan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary::<ArbitraryUserKeyPair>()?.into(),
            next_event: u.arbitrary()?,
            to_event: u.arbitrary()?,
            records: Default::default(),
            new_nullifiers: u
                .arbitrary_iter::<ArbitraryNullifier>()?
                .map(|n| Ok(n?.into()))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl BackgroundKeyScan {
    fn process_nullifiers(&mut self, nullifiers: &[Nullifier], new: bool) {
        for n in nullifiers {
            // Whether these nullifiers are newly published since the scan began, or were already
            // published and the scan has only now encountered them, we need to remove any records
            // we've collected which are nullified.
            if self.records.remove(n).is_none() && new {
                // Now, if this nullifier is newly published and we did not just remove a record
                // that we had already discovered, we need to save the nullifier in case we discover
                // the record that it nullifies later in our scan.
                //
                // Note that we do not need to save the nullifier if it is not newly published,
                // because if we are encountering this nullifier in the normal course of our scan,
                // then we have already scanned all blocks before it was published, and thus we must
                // have already discovered the corresponding record if the record is discoverable at
                // all.
                self.new_nullifiers.insert(*n);
            }
        }
    }

    fn add_records(&mut self, records: Vec<(RecordOpening, u64, MerklePath)>) {
        for (ro, uid, proof) in records {
            let nullifier = self.key.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                uid,
                &RecordCommitment::from(&ro),
            );
            if !self.new_nullifiers.remove(&nullifier) {
                // Add the record as long as its nullifier has not been invalidated since we started
                // the scan.
                self.records.insert(nullifier, (ro, uid, proof));
            }
        }
    }
}

#[ser_test(arbitrary, ark(false))]
#[derive(Arbitrary, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStreamState {
    pub auditor: u64,
    pub freezer: u64,
    pub user: u64,
}

#[derive(Debug, Clone)]
pub struct WalletState<'a, L: Ledger = AAPLedger> {
    // TODO: Move the mutable keys to the txn state.
    // https://github.com/spectrum-eco/spectrum/issues/6.
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Static data
    //
    // proving key set. The proving keys are ordered by number of outputs first and number of inputs
    // second, because the wallet is less flexible with respect to number of outputs. If we are
    // building a transaction and find we have too many inputs we can always generate a merge
    // transaction to defragment, but if the user requests a transaction with N independent outputs,
    // there is nothing we can do to decrease that number. So when searching for an appropriate
    // proving key, we will want to find a key with enough outputs first, and then worry about the
    // number of inputs.
    //
    // We keep the prover keys in an Arc because they are large, constant, and depend only on the
    // universal parameters of the system. This allows sharing them, which drastically decreases the
    // memory requirements of applications that create multiple wallets. This is not very realistic
    // for real applications, but it is very important for tests and costs little.
    pub(crate) proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Dynamic state
    pub(crate) txn_state: TransactionState<L>,
    // background scans triggered by the addition of new keys.
    pub(crate) key_scans: HashMap<UserAddress, BackgroundKeyScan>,
    // HD key generation state.
    pub(crate) key_state: KeyStreamState,

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Monotonic data
    //
    // asset definitions for which we are an auditor, indexed by code
    pub(crate) auditable_assets: HashMap<AssetCode, AssetDefinition>,
    // audit keys. This is guaranteed to contain the private key for every public key in an asset
    // policy contained in  auditable_assets`, but it may also contain additional keys that the user
    // has generated or imported but not yet attached to a particular asset type.
    pub(crate) audit_keys: HashMap<AuditorPubKey, AuditorKeyPair>,
    // freeze keys.
    pub(crate) freeze_keys: HashMap<FreezerPubKey, FreezerKeyPair>,
    // user keys, for spending owned records
    pub(crate) user_keys: HashMap<UserAddress, UserKeyPair>,
    // maps defined asset code to asset definition, seed and description of the asset
    pub(crate) defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
}

// Type erasure for key pairs so that backend components like storage that don't care about the
// detailed properties of different kinds of keys can just implement a single heterogeneous key
// store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoleKeyPair {
    Auditor(AuditorKeyPair),
    Freezer(FreezerKeyPair),
    User(UserKeyPair),
}

impl From<AuditorKeyPair> for RoleKeyPair {
    fn from(key: AuditorKeyPair) -> Self {
        Self::Auditor(key)
    }
}

impl From<FreezerKeyPair> for RoleKeyPair {
    fn from(key: FreezerKeyPair) -> Self {
        Self::Freezer(key)
    }
}

impl From<UserKeyPair> for RoleKeyPair {
    fn from(key: UserKeyPair) -> Self {
        Self::User(key)
    }
}

trait KeyPair: Clone + Into<RoleKeyPair> + TryFrom<RoleKeyPair> + Send + Sync {
    type PubKey: std::hash::Hash + Eq;
    fn pub_key(&self) -> Self::PubKey;
}

impl TryFrom<RoleKeyPair> for AuditorKeyPair {
    type Error = ();
    fn try_from(key: RoleKeyPair) -> Result<Self, ()> {
        match key {
            RoleKeyPair::Auditor(key) => Ok(key),
            _ => Err(()),
        }
    }
}

impl KeyPair for AuditorKeyPair {
    type PubKey = AuditorPubKey;
    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl TryFrom<RoleKeyPair> for FreezerKeyPair {
    type Error = ();
    fn try_from(key: RoleKeyPair) -> Result<Self, ()> {
        match key {
            RoleKeyPair::Freezer(key) => Ok(key),
            _ => Err(()),
        }
    }
}

impl KeyPair for FreezerKeyPair {
    type PubKey = FreezerPubKey;
    fn pub_key(&self) -> Self::PubKey {
        self.pub_key()
    }
}

impl TryFrom<RoleKeyPair> for UserKeyPair {
    type Error = ();
    fn try_from(key: RoleKeyPair) -> Result<Self, ()> {
        match key {
            RoleKeyPair::User(key) => Ok(key),
            _ => Err(()),
        }
    }
}

impl KeyPair for UserKeyPair {
    // The PubKey here is supposed to be a conceptual "primary key" for looking up UserKeyPairs. We
    // typically want to look up UserKeyPairs by Address, not PubKey, because if we have a PubKey we
    // can always get and Address to do the lookup.
    type PubKey = UserAddress;
    fn pub_key(&self) -> Self::PubKey {
        self.address()
    }
}

/// The interface required by the wallet from the persistence layer.
///
/// The persistent storage needed by the wallet is divided into 3 categories, based on usage
/// patterns and how often they change.
///
/// 1. Static data. This is data which is initialized when the wallet is created and never changes.
///
///    There is no interface in the WalletStorage trait for storing static data. When a new wallet
///    is created, the Wallet will call WalletBackend::create, which is responsible for working with
///    the storage layer to persist the wallet's static data.
///
///    See WalletState for information on which fields count as static data.
///
/// 2. Dynamic state. This is data which changes frequently, but grows boundedly or very slowly.
///
///    See WalletState for information on which fields count as dynamic state.
///
/// 3. Monotonic data. This is data which grows monotonically and never shrinks.
///
///    The monotonic data of a wallet is the set of auditable assets, and the set of defined assets
///    with their seeds.
///
/// The storage layer must provide a transactional interface. Updates to the individual storage
/// categories have no observable affects (that is, their results will not affect the next call to
/// load()) until commit() succeeds. If there are outstanding changes that have not been committed,
/// revert() can be used to roll back the state of each individual storage category to its state at
/// the most recent commit.
///
/// This interface is specified separately from the WalletBackend interface to allow the
/// implementation to separate the persistence layer from the network layer that implements the rest
/// of the backend with minimal boilerplate.
#[async_trait]
pub trait WalletStorage<'a, L: Ledger> {
    /// Check if there is already a stored wallet with this key.
    fn exists(&self) -> bool;

    /// Load the stored wallet identified by the given key.
    ///
    /// This function may assume `self.exists(key_pair)`.
    async fn load(&mut self) -> Result<WalletState<'a, L>, WalletError>;

    /// Store a snapshot of the wallet's dynamic state.
    async fn store_snapshot(&mut self, state: &WalletState<'a, L>) -> Result<(), WalletError>;

    /// Append a new auditable asset to the growing set.
    async fn store_auditable_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError>;

    /// Add a key to the wallet's key set.
    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError>;

    /// Append a new defined asset to the growing set.
    async fn store_defined_asset(
        &mut self,
        asset: &AssetDefinition,
        seed: AssetCodeSeed,
        desc: &[u8],
    ) -> Result<(), WalletError>;

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<L>,
    ) -> Result<(), WalletError>;
    async fn transaction_history(&mut self)
        -> Result<Vec<TransactionHistoryEntry<L>>, WalletError>;

    /// Commit to outstanding changes.
    async fn commit(&mut self);

    /// Roll back the persisted state to the previous commit.
    async fn revert(&mut self);
}

/// Interface for atomic storage transactions.
///
/// Any changes made to the persistent storage state through this struct will be part of a single
/// transaction. If any operation in the transaction fails, or if the transaction is dropped before
/// being committed, the entire transaction will be reverted and have no effect.
///
/// This struct should not be constructed directly, but instead a transaction should be obtained
/// through the WalletBackend::store() method, which will automatically commit the transaction after
/// it succeeds.
pub struct StorageTransaction<'a, 'l, L: Ledger, Storage: WalletStorage<'a, L>> {
    storage: MutexGuard<'l, Storage>,
    cancelled: bool,
    _phantom: std::marker::PhantomData<&'a ()>,
    _phantom2: std::marker::PhantomData<L>,
}

impl<'a, 'l, L: Ledger, Storage: WalletStorage<'a, L>> StorageTransaction<'a, 'l, L, Storage> {
    fn new(storage: MutexGuard<'l, Storage>) -> Self {
        Self {
            storage,
            cancelled: false,
            _phantom: Default::default(),
            _phantom2: Default::default(),
        }
    }

    async fn store_snapshot(&mut self, state: &WalletState<'a, L>) -> Result<(), WalletError> {
        if !self.cancelled {
            let res = self.storage.store_snapshot(state).await;
            if res.is_err() {
                self.cancel().await;
            }
            res
        } else {
            Ok(())
        }
    }

    async fn store_auditable_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError> {
        if !self.cancelled {
            let res = self.storage.store_auditable_asset(asset).await;
            if res.is_err() {
                self.cancel().await;
            }
            res
        } else {
            Ok(())
        }
    }

    async fn store_key<K: KeyPair>(&mut self, key: &K) -> Result<(), WalletError> {
        if !self.cancelled {
            let res = self.storage.store_key(&key.clone().into()).await;
            if res.is_err() {
                self.cancel().await;
            }
            res
        } else {
            Ok(())
        }
    }

    async fn store_defined_asset(
        &mut self,
        asset: &AssetDefinition,
        seed: AssetCodeSeed,
        desc: &[u8],
    ) -> Result<(), WalletError> {
        if !self.cancelled {
            let res = self.storage.store_defined_asset(asset, seed, desc).await;
            if res.is_err() {
                self.cancel().await;
            }
            res
        } else {
            Ok(())
        }
    }

    async fn store_transaction(
        &mut self,
        transaction: TransactionHistoryEntry<L>,
    ) -> Result<(), WalletError> {
        if !self.cancelled {
            let res = self.storage.store_transaction(transaction).await;
            if res.is_err() {
                self.cancel().await;
            }
            res
        } else {
            Ok(())
        }
    }

    async fn cancel(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            self.storage.revert().await;
        }
    }
}

impl<'a, 'l, L: Ledger, Storage: WalletStorage<'a, L>> Drop
    for StorageTransaction<'a, 'l, L, Storage>
{
    fn drop(&mut self) {
        block_on(self.cancel())
    }
}

#[async_trait]
pub trait WalletBackend<'a, L: Ledger>: Send {
    type EventStream: 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Unpin + Send;
    type Storage: WalletStorage<'a, L> + Send;

    /// Access the persistent storage layer.
    ///
    /// The interface is specified this way, with the main storage interface in a separate trait and
    /// an accessor function here, to allow implementations of WalletBackend to split the storage
    /// layer from the networking layer, since the two concerns are generally separate.
    ///
    /// Note that the return type of this function requires the implementation to guard the storage
    /// layer with a mutex, even if it is not internally shared between threads. This is meant to
    /// allow shared access to the storage layer internal, not require it. A better interface would
    /// be to have an associated type
    ///         `type<'l> StorageRef: 'l +  Deref<Target = Self::Storage> + DerefMut`
    /// This could be MutexGuard, RwLockWriteGuard, or just `&mut Self::Storage`, depending on the
    /// needs of the implementation. Maybe we can clean this up if and when GATs stabilize.
    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage>;

    async fn load(&mut self) -> Result<WalletState<'a, L>, WalletError> {
        let mut storage = self.storage().await;
        if storage.exists() {
            // If there is a stored wallet with this key pair, load it.
            storage.load().await
        } else {
            // Otherwise, ask the network layer to create and register a brand new wallet.
            drop(storage);
            self.create().await
        }
    }

    /// Make a change to the persisted state using a function describing a transaction.
    ///
    /// # Example
    ///
    /// ```ignore
    /// backend.store(key_pair, |mut t| async move {
    ///     t.store_snapshot(wallet_state).await?;
    ///     // If this store fails, the effects of the previous store will be reverted.
    ///     t.store_auditable_asset(wallet_state, asset).await?;
    ///     Ok(t)
    /// }).await?;
    /// ```
    async fn store<'l, F, Fut>(&'l mut self, update: F) -> Result<(), WalletError>
    where
        F: Send + FnOnce(StorageTransaction<'a, 'l, L, Self::Storage>) -> Fut,
        Fut: Send
            + Future<Output = Result<StorageTransaction<'a, 'l, L, Self::Storage>, WalletError>>,
        Self::Storage: 'l,
    {
        let storage = self.storage().await;
        let fut = update(StorageTransaction::new(storage)).and_then(|mut txn| async move {
            txn.storage.commit().await;
            Ok(())
        });
        fut.await
    }

    fn key_stream(&self) -> hd::KeyTree;

    // Querying the ledger
    async fn create(&mut self) -> Result<WalletState<'a, L>, WalletError>;
    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream;
    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError>;
    async fn get_nullifier_proof(
        &self,
        nullifiers: &mut NullifierSet<L>,
        nullifier: Nullifier,
    ) -> Result<(bool, NullifierProof<L>), WalletError>;
    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<Transaction<L>, WalletError>;
    async fn register_user_key(&mut self, pub_key: &UserPubKey) -> Result<(), WalletError>;

    // Submit a transaction to a validator.
    async fn submit(&mut self, txn: Transaction<L>) -> Result<(), WalletError>;
    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError>;
}

pub struct WalletSession<'a, L: Ledger, Backend: WalletBackend<'a, L>> {
    backend: Backend,
    rng: ChaChaRng,
    auditor_key_stream: hd::KeyTree,
    user_key_stream: hd::KeyTree,
    freezer_key_stream: hd::KeyTree,
    _marker: std::marker::PhantomData<&'a ()>,
    _marker2: std::marker::PhantomData<L>,
}

// Trait used to indicate that an abstract return type captures a reference with the lifetime 'a.
// See https://stackoverflow.com/questions/50547766/how-can-i-get-impl-trait-to-use-the-appropriate-lifetime-for-a-mutable-reference
pub trait Captures<'a> {}
impl<'a, T: ?Sized> Captures<'a> for T {}

#[derive(Clone, Debug)]
struct EventSummary<L: Ledger> {
    updated_txns: Vec<(TransactionUID<L>, TransactionStatus)>,
    spent_nullifiers: Vec<(Nullifier, u64)>,
    rejected_nullifiers: Vec<Nullifier>,
    // Fee nullifiers of transactions which were retired immediately upon being received.
    retired_nullifiers: Vec<Nullifier>,
    received_memos: Vec<(ReceiverMemo, u64)>,
}

impl<L: Ledger> Default for EventSummary<L> {
    fn default() -> Self {
        Self {
            updated_txns: Default::default(),
            spent_nullifiers: Default::default(),
            rejected_nullifiers: Default::default(),
            retired_nullifiers: Default::default(),
            received_memos: Default::default(),
        }
    }
}

impl<'a, L: Ledger> WalletState<'a, L> {
    pub fn pub_keys(&self) -> Vec<UserPubKey> {
        self.user_keys.values().map(|key| key.pub_key()).collect()
    }

    pub fn balance(&self, account: &UserAddress, asset: &AssetCode, frozen: FreezeFlag) -> u64 {
        match self.user_keys.get(account) {
            Some(key) => self.txn_state.balance(asset, &key.pub_key(), frozen),
            None => 0,
        }
    }

    pub fn assets(&self) -> HashMap<AssetCode, AssetInfo> {
        // Get the asset definitions of each record we own.
        let mut assets = self.txn_state.assets();
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
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        receipt: &TransactionReceipt<L>,
    ) -> Result<TransactionStatus, WalletError> {
        match self.txn_state.transactions.status(&receipt.uid) {
            TransactionStatus::Unknown => {
                // If the transactions database returns Unknown, it means the transaction is not in-
                // flight (the database only tracks in-flight transactions). So it must be retired,
                // rejected, or a foreign transaction that we were never tracking to begin with.
                // Check if it has been accepted by seeing if its fee nullifier is spent.
                let (spent, _) = session
                    .backend
                    .get_nullifier_proof(&mut self.txn_state.nullifiers, receipt.fee_nullifier)
                    .await?;
                if spent {
                    Ok(TransactionStatus::Retired)
                } else {
                    // If the transaction isn't in our pending data structures, but its fee record
                    // has not been spent, then either it was rejected, or it's someone else's
                    // transaction that we haven't been tracking through the lifecycle.
                    if self.user_keys.contains_key(&receipt.submitter) {
                        Ok(TransactionStatus::Rejected)
                    } else {
                        Ok(TransactionStatus::Unknown)
                    }
                }
            }

            state => Ok(state),
        }
    }

    async fn handle_event(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        event: LedgerEvent<L>,
        source: EventSource,
    ) -> EventSummary<L> {
        self.txn_state.now += EventIndex::from_source(source, 1);
        let mut summary = EventSummary::default();
        match event {
            LedgerEvent::Commit {
                block,
                block_id,
                state_comm,
            } => {
                // Don't trust the network connection that provided us this event; validate it
                // against our local mirror of the ledger and bail out if it is invalid.
                let mut uids = match self.txn_state.validator.validate_and_apply(block.clone()) {
                    Ok(uids) => {
                        if state_comm != self.txn_state.validator.commit() {
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

                // Update our full copies of sparse validator data structures to be consistent with
                // the validator state.
                for txn in block.txns() {
                    let nullifiers = txn.input_nullifiers();
                    // Remove spent records.
                    for n in &nullifiers {
                        if let Some(record) = self.txn_state.records.remove_by_nullifier(*n) {
                            self.txn_state.forget_merkle_leaf(record.uid);
                        }
                    }
                    // Insert new records.
                    for o in txn.output_commitments() {
                        self.txn_state.append_merkle_leaf(o);
                    }
                    // Update background scans with newly published nullifiers.
                    for scan in self.key_scans.values_mut() {
                        scan.process_nullifiers(&nullifiers, true);
                    }
                }
                // Update nullifier set
                let nullifier_proofs = block
                    .txns()
                    .into_iter()
                    .flat_map(|txn| txn.proven_nullifiers())
                    .collect::<Vec<_>>();
                if self
                    .txn_state
                    .nullifiers
                    .multi_insert(&nullifier_proofs)
                    .is_err()
                {
                    //todo !jeb.bearer handle this case more robustly. If we get here, it means the
                    // event stream has lied to us, so recovery is quite tricky and may require us
                    // to fail over to a different query service.
                    panic!("received block with invalid nullifier proof");
                }

                for (txn_id, txn) in block.txns().into_iter().enumerate() {
                    // Split the uids corresponding to this transaction off the front of `uids`.
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());
                    assert_eq!(this_txn_uids.len(), txn.output_len());

                    // If this transaction contains record openings for all of its outputs,
                    // consider it retired immediately, do not wait for memos.
                    let retired = txn.output_openings().is_some();

                    // Add the spent nullifiers to the summary. Map each nullifier to one of the
                    // output UIDs of the same transaction, so that we can tell when the memos
                    // arrive for the transaction which spent this nullifier (completing the
                    // transaction's life cycle) by looking at the UIDs attached to the memos.
                    // TODO !keyao Stop identifying transactions by input nullifier and instead use hashes.
                    // (https://github.com/SpectrumXYZ/cape/issues/275.)
                    if !txn.input_nullifiers().is_empty() {
                        summary.spent_nullifiers.extend(
                            txn.input_nullifiers()
                                .into_iter()
                                .zip(repeat(this_txn_uids[0].0)),
                        );
                        if retired {
                            summary.retired_nullifiers.push(txn.input_nullifiers()[0]);
                        }
                    }

                    // Different concerns within the wallet consume transactions in different ways.
                    // Now we give each concern a chance to consume this transaction, performing any
                    // processing they need to do and possibly setting the `remember` flag for
                    // output records they care about.
                    //
                    // This is a transaction we submitted and have been
                    // awaiting confirmation.
                    let mut self_published = false;
                    if let Some(pending) = self
                        .clear_pending_transaction(
                            session,
                            &txn,
                            Some((block_id, txn_id as u64, &mut this_txn_uids)),
                        )
                        .await
                    {
                        let status = if retired {
                            TransactionStatus::Retired
                        } else {
                            TransactionStatus::AwaitingMemos
                        };
                        summary.updated_txns.push((pending.uid(), status));
                        self_published = true;
                    }

                    // This is someone else's transaction but we can audit it.
                    self.audit_transaction(session, &txn, &mut this_txn_uids)
                        .await;

                    // If this transaction has record openings attached, check if they are for us
                    // and add them immediately, without waiting for memos.
                    self.receive_attached_records(
                        session,
                        block_id,
                        txn_id as u64,
                        &txn,
                        &mut this_txn_uids,
                        !self_published,
                        // Only add to history if we didn't send this same transaction
                    )
                    .await;

                    // Prune the record Merkle tree of records we don't care about.
                    for (uid, remember) in this_txn_uids {
                        if !remember {
                            self.txn_state.forget_merkle_leaf(uid);
                        }
                    }
                }

                // Some transactions may have expired when we stepped the validator state. Remove
                // them from our pending transaction data structures.
                //
                // This maintains the invariant that everything in `pending_transactions` must
                // correspond to an on-hold record, because everything which corresponds to a record
                // whose hold just expired will be removed from the set now.
                for txn_uid in self.txn_state.clear_expired_transactions() {
                    summary
                        .updated_txns
                        .push((txn_uid, TransactionStatus::Rejected));
                }
            }

            LedgerEvent::Memos {
                outputs,
                transaction,
            } => {
                let completed = self
                    .txn_state
                    .transactions
                    .received_memos(outputs.iter().map(|info| info.2));
                let self_published = !completed.is_empty();
                summary.updated_txns.extend(
                    completed
                        .into_iter()
                        .map(|txn_uid| (txn_uid, TransactionStatus::Retired))
                        .collect::<Vec<_>>(),
                );

                summary
                    .received_memos
                    .extend(outputs.iter().map(|(memo, _, uid, _)| (memo.clone(), *uid)));
                for key_pair in self.user_keys.values().cloned().collect::<Vec<_>>() {
                    let records = self
                        .try_open_memos(session, &key_pair, &outputs, transaction, !self_published)
                        .await;
                    self.add_records(&key_pair, records);
                }
            }

            LedgerEvent::Reject { block, error } => {
                for mut txn in block.txns() {
                    summary
                        .rejected_nullifiers
                        .append(&mut txn.input_nullifiers());
                    if let Some(pending) = self.clear_pending_transaction(session, &txn, None).await
                    {
                        // Try to resubmit if the error is recoverable.
                        let uid = pending.uid();
                        if let ValidationError::BadNullifierProof {} = &error {
                            if self
                                .update_nullifier_proofs(session, &mut txn)
                                .await
                                .is_ok()
                                && self
                                    .submit_elaborated_transaction(session, txn, pending.info)
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
                                    .push((uid, TransactionStatus::Rejected));
                            }
                        } else {
                            summary
                                .updated_txns
                                .push((uid, TransactionStatus::Rejected));
                        }
                    }
                }
            }
        };

        if let Err(err) = session
            .backend
            .store(|mut t| async {
                t.store_snapshot(self).await?;
                Ok(t)
            })
            .await
        {
            // We can ignore errors when saving the snapshot. If the save fails and then we crash,
            // we will replay this event when we load from the previously saved snapshot. Just print
            // a warning and move on.
            println!("warning: failed to save wallet state to disk: {}", err);
        }

        summary
    }

    async fn handle_retroactive_event(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        key: &UserKeyPair,
        event: LedgerEvent<L>,
        source: EventSource,
    ) {
        let scan = match event {
            LedgerEvent::Memos {
                outputs,
                transaction,
                ..
            } => {
                let records = self
                    .try_open_memos(session, key, &outputs, transaction, true)
                    .await;
                let scan = self.key_scans.get_mut(&key.address()).unwrap();
                scan.add_records(records);
                scan
            }

            LedgerEvent::Commit { block, .. } => {
                let nullifiers = block
                    .txns()
                    .into_iter()
                    .flat_map(|txn| txn.input_nullifiers())
                    .collect::<Vec<_>>();
                let scan = self.key_scans.get_mut(&key.address()).unwrap();
                scan.process_nullifiers(&nullifiers, false);
                scan
            }

            _ => self.key_scans.get_mut(&key.address()).unwrap(),
        };

        scan.next_event += EventIndex::from_source(source, 1);
        if let Err(err) = session
            .backend
            .store(|mut t| async {
                t.store_snapshot(self).await?;
                Ok(t)
            })
            .await
        {
            println!(
                "warning: failed to save background scan state to disk: {}",
                err
            );
        }
    }

    async fn try_open_memos(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        key_pair: &UserKeyPair,
        memos: &[(ReceiverMemo, RecordCommitment, u64, MerklePath)],
        transaction: Option<(u64, u64)>,
        add_to_history: bool,
    ) -> Vec<(RecordOpening, u64, MerklePath)> {
        let mut records = Vec::new();
        for (memo, comm, uid, proof) in memos {
            if let Ok(record_opening) = memo.decrypt(key_pair, comm, &[]) {
                if !record_opening.is_dummy() {
                    // If this record is for us (i.e. its corresponding memo decrypts under
                    // our key) and not a dummy, then add it to our owned records.
                    records.push((record_opening, *uid, proof.clone()));
                }
            }
        }

        if add_to_history && !records.is_empty() {
            if let Some((block_id, txn_id)) = transaction {
                // To add a transaction history entry, we need to fetch the actual transaction to
                // figure out what type it was.
                let kind = match session.backend.get_transaction(block_id, txn_id).await {
                    Ok(txn) => txn.kind(),
                    Err(err) => {
                        println!(
                            "Error fetching received transaction ({}, {}) from network: {}. \
                                Transaction will be recorded with unknown type.",
                            block_id, txn_id, err
                        );
                        TransactionKind::<L>::unknown()
                    }
                };

                self.add_receive_history(
                    session,
                    block_id,
                    txn_id,
                    kind,
                    &records
                        .iter()
                        .map(|(ro, _, _)| ro.clone())
                        .collect::<Vec<_>>(),
                )
                .await;
            }
        }

        records
    }

    async fn receive_attached_records(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        block_id: u64,
        txn_id: u64,
        txn: &Transaction<L>,
        uids: &mut [(u64, bool)],
        add_to_history: bool,
    ) {
        let my_records = txn
            .output_openings()
            .into_iter()
            .flatten()
            .zip(uids)
            .filter_map(|(ro, (uid, remember))| {
                if let Some(key_pair) = self.user_keys.get(&ro.pub_key.address()) {
                    // If this record is for us, add it to the wallet and include it in the
                    // list of received records for created a received transaction history
                    // entry.
                    *remember = true;
                    self.txn_state.records.insert(ro.clone(), *uid, key_pair);
                    Some(ro)
                } else if let Some(key_pair) = self
                    .freeze_keys
                    .get(ro.asset_def.policy_ref().freezer_pub_key())
                {
                    // If this record is not for us, but we can freeze it, then this
                    // becomes like an audit. Add the record to our collection of freezable
                    // records, but do not include it in the history entry.
                    *remember = true;
                    self.txn_state.records.insert_freezable(ro, *uid, key_pair);
                    None
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if add_to_history && !my_records.is_empty() {
            self.add_receive_history(session, block_id, txn_id, txn.kind(), &my_records)
                .await;
        }
    }

    async fn add_receive_history(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        block_id: u64,
        txn_id: u64,
        kind: TransactionKind<L>,
        records: &[RecordOpening],
    ) {
        // The last record is guaranteed not to be the fee change record. It contains useful
        // information about asset type and freeze state.
        let last_record = records.last().unwrap();
        let kind = if kind == TransactionKind::<L>::send() {
            TransactionKind::<L>::receive()
        } else if kind == TransactionKind::<L>::freeze()
            && last_record.freeze_flag == FreezeFlag::Unfrozen
        {
            TransactionKind::<L>::unfreeze()
        } else {
            kind
        };

        let txn_asset = last_record.asset_def.code;
        let history = TransactionHistoryEntry {
            time: Local::now(),
            asset: txn_asset,
            kind,
            sender: None,
            // When we receive transactions, we can't tell from the protocol
            // who sent it to us.
            receivers: records
                .iter()
                .filter_map(|ro| {
                    if ro.asset_def.code == txn_asset {
                        Some((ro.pub_key.address(), ro.amount))
                    } else {
                        println!(
                            "Received transaction ({}, {}) contains outputs with \
                            multiple asset types. Ignoring some of them.",
                            block_id, txn_id
                        );
                        None
                    }
                })
                .collect(),
            receipt: None,
        };

        if let Err(err) = session
            .backend
            .store(|mut t| async move {
                t.store_transaction(history).await?;
                Ok(t)
            })
            .await
        {
            println!(
                "Failed to store transaction ({}, {}) in history: {}.",
                block_id, txn_id, err
            );
        }
    }

    fn add_records(
        &mut self,
        key_pair: &UserKeyPair,
        records: Vec<(RecordOpening, u64, MerklePath)>,
    ) {
        for (record, uid, proof) in records {
            let comm = RecordCommitment::from(&record);
            if !self
                .txn_state
                .remember_merkle_leaf(uid, &MerkleLeafProof::new(comm.to_field_element(), proof))
            {
                println!(
                    "error: got bad merkle proof from backend for commitment {:?}",
                    comm
                );
            }

            self.txn_state.records.insert(record, uid, key_pair);
        }
    }

    async fn import_memo(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        memo: ReceiverMemo,
        comm: RecordCommitment,
        uid: u64,
        proof: MerklePath,
    ) -> Result<(), WalletError> {
        for key in self.user_keys.values().cloned().collect::<Vec<_>>() {
            let records = self
                .try_open_memos(
                    session,
                    &key,
                    &[(memo.clone(), comm, uid, proof.clone())],
                    None,
                    false,
                )
                .await;
            if !records.is_empty() {
                self.add_records(&key, records);
                return Ok(());
            }
        }

        Err(WalletError::CannotDecryptMemo {})
    }

    async fn clear_pending_transaction<'t>(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        txn: &Transaction<L>,
        res: Option<CommittedTxn<'t>>,
    ) -> Option<PendingTransaction<L>> {
        let pending = self.txn_state.clear_pending_transaction(txn, &res);

        // If this was a successful transaction, post its receiver memos and add all of its
        // frozen/unfrozen outputs to our freezable database (for freeze/unfreeze transactions).
        if let Some((block_id, txn_id, uids)) = res {
            if let Some(pending) = &pending {
                // Post receiver memos.
                if let Err(err) = session
                    .backend
                    .post_memos(
                        block_id,
                        txn_id,
                        pending.info.memos.clone(),
                        pending.info.sig.clone(),
                    )
                    .await
                {
                    println!(
                        "Error: failed to post receiver memos for transaction ({}:{}): {:?}",
                        block_id, txn_id, err
                    );
                } else {
                    self.txn_state
                        .transactions
                        .await_memos(pending.uid(), uids.iter().map(|(uid, _)| *uid));
                }

                // the first uid corresponds to the fee change output, which is not one of the
                // `freeze_outputs`, so we skip that one
                for ((uid, remember), ro) in
                    uids.iter_mut().skip(1).zip(&pending.info.freeze_outputs)
                {
                    self.txn_state.records.insert_freezable(
                        ro.clone(),
                        *uid,
                        &self.freeze_keys[ro.asset_def.policy_ref().freezer_pub_key()],
                    );
                    *remember = true;
                }
            }
        }

        pending
    }

    async fn audit_transaction(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        txn: &Transaction<L>,
        uids: &mut [(u64, bool)],
    ) {
        // Try to decrypt auditor memos.
        if let Ok(memo) = txn.open_audit_memo(&self.auditable_assets, &self.audit_keys) {
            //todo !jeb.bearer eventually, we will probably want to save all the audit memos for
            // the whole transaction (inputs and outputs) regardless of whether any of the outputs
            // are freezeable, just for general auditing purposes.

            // the first uid corresponds to the fee change output, which has no audit memo, so skip
            // that one
            for ((uid, remember), output) in uids.iter_mut().skip(1).zip(memo.outputs) {
                let pub_key = match output.user_address {
                    Some(address) => session.backend.get_public_key(&address).await.ok(),
                    None => None,
                };
                if let (Some(pub_key), Some(amount), Some(blind)) =
                    (pub_key, output.amount, output.blinding_factor)
                {
                    // If the audit memo contains all the information we need to potentially freeze
                    // this record, save it in our database for later freezing.
                    if let Some(freeze_key) = self
                        .freeze_keys
                        .get(memo.asset.policy_ref().freezer_pub_key())
                    {
                        let record_opening = RecordOpening {
                            amount,
                            asset_def: memo.asset.clone(),
                            pub_key,
                            freeze_flag: FreezeFlag::Unfrozen,
                            blind,
                        };
                        self.txn_state
                            .records
                            .insert_freezable(record_opening, *uid, freeze_key);
                        *remember = true;
                    }
                }
            }
        }
    }

    async fn update_nullifier_proofs(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        txn: &mut Transaction<L>,
    ) -> Result<(), WalletError> {
        let mut proofs = Vec::new();
        for n in txn.input_nullifiers() {
            let (spent, proof) = session
                .backend
                .get_nullifier_proof(&mut self.txn_state.nullifiers, n)
                .await?;
            if spent {
                return Err(WalletError::NullifierAlreadyPublished { nullifier: n });
            }
            proofs.push(proof);
        }
        txn.set_proofs(proofs);
        Ok(())
    }

    // This function ran into the same mystifying compiler behavior as
    // `submit_elaborated_transaction`, where the default async desugaring loses track of the `Send`
    // impl for the result type. As with the other function, this can be fixed by manually
    // desugaring the type signature.
    fn define_asset<'b>(
        &'b mut self,
        session: &'b mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        description: &'b [u8],
        policy: AssetPolicy,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<AssetDefinition, WalletError>> + Send
    where
        'a: 'b,
    {
        async move {
            let (seed, code, asset_definition) =
                self.txn_state
                    .define_asset(&mut session.rng, description, policy)?;
            let desc = description.to_vec();

            // If the policy lists ourself as the auditor, we will automatically start auditing
            // transactions involving this asset.
            let audit = self
                .audit_keys
                .contains_key(asset_definition.policy_ref().auditor_pub_key());

            // Persist the change that we're about to make before updating our in-memory state. We
            // can't report success until we know the new asset has been saved to disk (otherwise we
            // might lose the seed if we crash at the wrong time) and we don't want it in our
            // in-memory state if we're not going to report success.
            session
                .backend
                .store(|mut t| async {
                    t.store_defined_asset(&asset_definition, seed, &desc)
                        .await?;
                    if audit {
                        // If we are going to be an auditor of the new asset, we must also persist
                        // that information to disk before doing anything to the in-memory state.
                        t.store_auditable_asset(&asset_definition).await?;
                    }
                    Ok(t)
                })
                .await?;

            // Now we can add the asset definition to the in-memory state.
            self.defined_assets
                .insert(code, (asset_definition.clone(), seed, desc));
            if audit {
                self.auditable_assets
                    .insert(asset_definition.code, asset_definition.clone());
            }
            Ok(asset_definition)
        }
    }

    /// Use `audit_asset` to start auditing transactions with a given asset type, when the asset
    /// type was defined by someone else and sent to us out of band. The audit key for `asset` must
    /// already be in this wallet's key set.
    ///
    /// Auditing of assets created by this user with an appropriate asset policy begins
    /// automatically. Calling this function is unnecessary.
    pub async fn audit_asset(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        asset: &AssetDefinition,
    ) -> Result<(), WalletError> {
        if self.auditable_assets.contains_key(&asset.code) {
            // Don't add the same asset twice.
            return Ok(());
        }
        if !self
            .audit_keys
            .contains_key(asset.policy_ref().auditor_pub_key())
        {
            return Err(WalletError::AssetNotAuditable {
                asset: asset.clone(),
            });
        }

        // Store the new asset on disk before adding it to our in-memory data structure. We don't
        // want to update the in-memory structure if the persistent store fails.
        session
            .backend
            .store(|mut t| async {
                t.store_auditable_asset(asset).await?;
                Ok(t)
            })
            .await?;
        self.auditable_assets.insert(asset.code, asset.clone());
        Ok(())
    }

    pub async fn add_user_key(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        user_key: UserKeyPair,
        scan_from: Option<EventIndex>,
    ) -> Result<(), WalletError> {
        Self::add_key(session, &mut self.user_keys, user_key.clone()).await?;

        // Register the new public key with the public address->key mapping.
        session
            .backend
            .register_user_key(&user_key.pub_key())
            .await?;

        if let Some(scan_from) = scan_from {
            // Register a background scan of the ledger to import records belonging to this key.
            // Note that the caller is responsible for actually starting the task which processes
            // this scan, since the Wallet (not the WalletState) has the data structures needed to
            // manage tasks (the AsyncScope, mutexes, etc.).
            self.key_scans.insert(
                user_key.address(),
                BackgroundKeyScan {
                    key: user_key.clone(),
                    next_event: scan_from,
                    to_event: self.txn_state.now,
                    records: Default::default(),
                    new_nullifiers: Default::default(),
                },
            );
        }

        Ok(())
    }

    pub async fn add_audit_key(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        audit_key: AuditorKeyPair,
    ) -> Result<(), WalletError> {
        Self::add_key(session, &mut self.audit_keys, audit_key).await
    }

    pub async fn add_freeze_key(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        freeze_key: FreezerKeyPair,
    ) -> Result<(), WalletError> {
        Self::add_key(session, &mut self.freeze_keys, freeze_key).await
    }

    async fn add_key<K: KeyPair>(
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        keys: &mut HashMap<K::PubKey, K>,
        key: K,
    ) -> Result<(), WalletError> {
        if keys.contains_key(&key.pub_key()) {
            return Ok(());
        }

        session
            .backend
            .store(|mut t| async {
                t.store_key(&key).await?;
                Ok(t)
            })
            .await?;
        keys.insert(key.pub_key(), key);
        Ok(())
    }

    pub fn build_transfer<'k>(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        spec: TransferSpec<'k>,
    ) -> Result<TransferInfo<L>, WalletError> {
        self.txn_state
            .transfer(spec, &self.proving_keys.xfr, &mut session.rng)
            .context(TransactionError)
    }

    pub fn generate_memos(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        records: Vec<RecordOpening>,
        sig_keypair: &SigKeyPair,
    ) -> Result<(Vec<ReceiverMemo>, Signature), WalletError> {
        self.txn_state
            .generate_memos(records, &mut session.rng, sig_keypair)
            .context(TransactionError)
    }

    pub async fn build_mint(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        account: &UserAddress,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(MintNote, TransactionInfo<L>), WalletError> {
        let asset = self
            .defined_assets
            .get(asset_code)
            .ok_or(WalletError::UndefinedAsset { asset: *asset_code })?;
        self.txn_state
            .mint(
                &self.account_keypair(account)?.clone(),
                &self.proving_keys.mint,
                fee,
                asset,
                amount,
                session.backend.get_public_key(&owner).await?,
                &mut session.rng,
            )
            .context(TransactionError)
    }

    /// Freeze or unfreeze at least `amount` of a particular asset owned by a given user.
    ///
    /// In order to freeze an asset, this wallet must be an auditor of that asset type, and it must
    /// have observed enough transactions to determine that the target user owns at least `amount`
    /// of that asset. In order to unfreeze, this wallet must have previously been used to freeze at
    /// least `amount` of the target's assets.
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
    #[allow(clippy::too_many_arguments)]
    async fn build_freeze(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        account: &UserAddress,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
    ) -> Result<(FreezeNote, TransactionInfo<L>), WalletError> {
        let freeze_key = match self.freeze_keys.get(asset.policy_ref().freezer_pub_key()) {
            Some(key) => key,
            None => {
                return Err(WalletError::AssetNotFreezable {
                    asset: asset.clone(),
                });
            }
        };

        self.txn_state
            .freeze_or_unfreeze(
                &self.account_keypair(account)?.clone(),
                freeze_key,
                &self.proving_keys.freeze,
                fee,
                asset,
                amount,
                session.backend.get_public_key(&owner).await?,
                outputs_frozen,
                &mut session.rng,
            )
            .context(TransactionError)
    }

    async fn submit_transaction(
        &mut self,
        session: &mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        note: TransactionNote,
        info: TransactionInfo<L>,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let mut nullifier_pfs = Vec::new();
        for n in note.nullifiers() {
            let (spent, proof) = session
                .backend
                .get_nullifier_proof(&mut self.txn_state.nullifiers, n)
                .await?;
            if spent {
                return Err(WalletError::NullifierAlreadyPublished { nullifier: n });
            }
            nullifier_pfs.push(proof);
        }

        let txn = Transaction::<L>::aap(note, nullifier_pfs);
        self.submit_elaborated_transaction(session, txn, info).await
    }

    // For reasons that are not clearly understood, the default async desugaring for this function
    // loses track of the fact that the result type implements Send, which causes very confusing
    // error messages farther up the call stack (apparently at the point where this function is
    // monomorphized) which do not point back to this location. This is likely due to a bug in type
    // inference, or at least a deficiency around async sugar combined with a bug in diagnostics.
    //
    // As a work-around, we do the desugaring manually so that we can explicitly specify that the
    // return type implements Send. The return type also captures a reference with lifetime 'a,
    // which is different from (but related to) the lifetime 'b of the returned Future, and
    // `impl 'a + 'b + ...` does not work, so we use the work-around described at
    // https://stackoverflow.com/questions/50547766/how-can-i-get-impl-trait-to-use-the-appropriate-lifetime-for-a-mutable-reference
    // to indicate the captured lifetime using the Captures trait.
    fn submit_elaborated_transaction<'b>(
        &'b mut self,
        session: &'b mut WalletSession<'a, L, impl WalletBackend<'a, L>>,
        txn: Transaction<L>,
        info: TransactionInfo<L>,
    ) -> impl 'b + Captures<'a> + Future<Output = Result<TransactionReceipt<L>, WalletError>> + Send
    where
        'a: 'b,
    {
        async move {
            let receipt = self.txn_state.add_pending_transaction(&txn, info.clone());

            // Persist the pending transaction.
            if let Err(err) = session
                .backend
                .store(|mut t| async {
                    t.store_snapshot(self).await?;

                    // If we're submitting this transaction for the first time (as opposed to
                    // updating and resubmitting a failed transaction) add it to the history.
                    if let Some(mut history) = info.history {
                        history.receipt = Some(receipt.clone());
                        t.store_transaction(history).await?;
                    }

                    Ok(t)
                })
                .await
            {
                // If we failed to persist the pending transaction, we cannot submit it, because if
                // we then exit and reload the process from storage, there will be an in-flight
                // transaction which is not accounted for in our pending transaction data
                // structures. Instead, we remove the pending transaction from our in-memory data
                // structures and return the error.
                self.clear_pending_transaction(session, &txn, None).await;
                return Err(err);
            }

            // If we succeeded in creating and persisting the pending transaction, submit it to the
            // validators.
            if let Err(err) = session.backend.submit(txn.clone()).await {
                self.clear_pending_transaction(session, &txn, None).await;
                return Err(err);
            }

            Ok(receipt)
        }
    }

    fn account_keypair(&'_ self, account: &UserAddress) -> Result<&'_ UserKeyPair, WalletError> {
        match self.user_keys.get(account) {
            Some(key_pair) => Ok(key_pair),
            None => Err(WalletError::NoSuchAccount {
                address: account.clone(),
            }),
        }
    }
}

/// Note: it is a soundness requirement that the destructor of a `Wallet` run when the `Wallet` is
/// dropped. Therefore, `std::mem::forget` must not be used to forget a `Wallet` without running its
/// destructor.
pub struct Wallet<'a, Backend: WalletBackend<'a, L>, L: Ledger = AAPLedger> {
    // Data shared between the main thread and the event handling thread:
    //  * the trusted, persistent wallet state
    //  * the trusted, ephemeral wallet session
    //  * promise completion handles for futures returned by sync(), indexed by the timestamp at
    //    which the corresponding future is supposed to complete. Handles are added in sync() (main
    //    thread) and removed and completed in the event thread
    mutex: Arc<Mutex<WalletSharedState<'a, L, Backend>>>,
    // Handle for the background tasks running the event handling loop and retroactive ledger scans.
    // When dropped, this handle will cancel the tasks.
    task_scope: AsyncScope<'a, ()>,
}

pub struct WalletSharedState<'a, L: Ledger, Backend: WalletBackend<'a, L>> {
    state: WalletState<'a, L>,
    session: WalletSession<'a, L, Backend>,
    sync_handles: Vec<(EventIndex, oneshot::Sender<()>)>,
    txn_subscribers: HashMap<TransactionUID<L>, Vec<oneshot::Sender<TransactionStatus>>>,
    pending_foreign_txns: HashMap<Nullifier, Vec<oneshot::Sender<TransactionStatus>>>,
}

impl<'a, L: Ledger, Backend: WalletBackend<'a, L>> WalletSharedState<'a, L, Backend> {
    pub fn backend(&self) -> &Backend {
        &self.session.backend
    }

    pub fn backend_mut(&mut self) -> &mut Backend {
        &mut self.session.backend
    }

    pub fn rng(&mut self) -> &mut ChaChaRng {
        &mut self.session.rng
    }
}

// Fun fact: replacing `std::pin::Pin` with `Pin` and adding `use std::pin::Pin` causes the compiler
// to panic where this type alias is used in `Wallet::new`. As a result, the type alias `BoxFuture`
// from `futures::future` does not work, so we define our own.
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub trait SendFuture<'a, T>: Future<Output = T> + Captures<'a> + Send {}
impl<'a, T, F: Future<Output = T> + Captures<'a> + Send> SendFuture<'a, T> for F {}

impl<'a, L: 'static + Ledger, Backend: 'a + WalletBackend<'a, L> + Send + Sync>
    Wallet<'a, Backend, L>
{
    // This function suffers from github.com/rust-lang/rust/issues/89657, in which, if we define it
    // as an async function, the compiler loses track of the fact that the resulting opaque Future
    // implements Send, even though it does. Unfortunately, the workaround used for some other
    // functions in this module (c.f. `submit_elaborated_transaction`) where we manually desugar the
    // function signature to explicitly return `impl Future + Send` triggers a separate and possibly
    // unrelated compiler bug, which results in a panic during compilation.
    //
    // Fortunately, there is a different workaround which does work. The idea is the same: to
    // manually write out the opaque return type so that we can explicitly add the `Send` bound. The
    // difference is that we use dynamic type erasure (Pin<Box<dyn Future>>) instead of static type
    // erasure. I don't know why this doesn't crash the compiler, but it doesn't.
    pub fn new(backend: Backend) -> BoxFuture<'a, Result<Wallet<'a, Backend, L>, WalletError>> {
        Box::pin(async move { Self::new_impl(backend).await })
    }
    async fn new_impl(mut backend: Backend) -> Result<Wallet<'a, Backend, L>, WalletError> {
        let state = backend.load().await?;
        let mut events = backend.subscribe(state.txn_state.now, None).await;
        let mut key_scans = vec![];
        for scan in state.key_scans.values() {
            if let Some(ord) = scan.next_event.partial_cmp(&scan.to_event) {
                // `next_event` could be incomparable with `to_event`, if our position in some event
                // sources is greater than in `to_event`, but we have not finished scanning _all_
                // event sources. However, if comparable, `next_event` must be before `to_event`.
                assert_eq!(ord, std::cmp::Ordering::Less);
            }
            key_scans.push((
                scan.key.clone(),
                backend
                    .subscribe(scan.next_event, Some(scan.to_event))
                    .await,
            ));
        }
        let key_tree = backend.key_stream();
        let session = WalletSession {
            backend,
            rng: ChaChaRng::from_entropy(),
            auditor_key_stream: key_tree.derive_sub_tree("auditor".as_bytes()),
            freezer_key_stream: key_tree.derive_sub_tree("freezer".as_bytes()),
            user_key_stream: key_tree.derive_sub_tree("user".as_bytes()),
            _marker: Default::default(),
            _marker2: Default::default(),
        };
        let sync_handles = Vec::new();
        let txn_subscribers = HashMap::new();
        let pending_foreign_txns = HashMap::new();
        let mutex = Arc::new(Mutex::new(WalletSharedState {
            state,
            session,
            sync_handles,
            txn_subscribers,
            pending_foreign_txns,
        }));

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

        // Start the event loop.
        {
            let mutex = mutex.clone();
            scope.spawn_cancellable(
                async move {
                    let mut foreign_txns_awaiting_memos = HashMap::new();
                    while let Some((event, source)) = events.next().await {
                        let WalletSharedState {
                            state,
                            session,
                            sync_handles,
                            txn_subscribers,
                            pending_foreign_txns,
                            ..
                        } = &mut *mutex.lock().await;
                        // handle an event
                        let summary = state.handle_event(session, event, source).await;
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
                        // were just accepted, move them to the retired or awaiting memos state.
                        for n in summary.retired_nullifiers {
                            for sender in pending_foreign_txns.remove(&n).into_iter().flatten() {
                                sender.send(TransactionStatus::Retired).ok();
                            }
                        }
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
                                sender.send(TransactionStatus::Rejected).ok();
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
                                sender.send(TransactionStatus::Retired).ok();
                            }
                        }

                        // Keep all the sync() futures whose index is still in the future, and
                        // signal the rest.
                        let (sync_handles_to_keep, sync_handles_to_signal) =
                            std::mem::take(sync_handles)
                                .into_iter()
                                .partition(|(index, _)| *index > state.txn_state.now);
                        *sync_handles = sync_handles_to_keep;
                        for (_, handle) in sync_handles_to_signal {
                            handle.send(()).ok();
                        }
                    }
                },
                || (),
            );
        };

        let mut wallet = Self {
            mutex,
            task_scope: scope,
        };

        // Spawn background tasks for any scans which were in progress when the wallet was last shut
        // down.
        for (key, events) in key_scans {
            wallet.spawn_key_scan(key, events);
        }

        Ok(wallet)
    }

    pub async fn lock(&self) -> MutexGuard<'_, WalletSharedState<'a, L, Backend>> {
        self.mutex.lock().await
    }

    pub async fn pub_keys(&self) -> Vec<UserPubKey> {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.pub_keys()
    }

    pub async fn auditor_pub_keys(&self) -> Vec<AuditorPubKey> {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.audit_keys.keys().cloned().collect()
    }

    pub async fn freezer_pub_keys(&self) -> Vec<FreezerPubKey> {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.freeze_keys.keys().cloned().collect()
    }

    pub async fn balance(&self, account: &UserAddress, asset: &AssetCode) -> u64 {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.balance(account, asset, FreezeFlag::Unfrozen)
    }

    pub async fn frozen_balance(&self, account: &UserAddress, asset: &AssetCode) -> u64 {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.balance(account, asset, FreezeFlag::Frozen)
    }

    pub async fn assets(&self) -> HashMap<AssetCode, AssetInfo> {
        let WalletSharedState { state, .. } = &*self.mutex.lock().await;
        state.assets()
    }

    pub async fn transaction_history(
        &self,
    ) -> Result<Vec<TransactionHistoryEntry<L>>, WalletError> {
        let WalletSharedState { session, .. } = &mut *self.mutex.lock().await;
        let mut storage = session.backend.storage().await;
        storage.transaction_history().await
    }

    /// Basic transfer without customization.
    /// To add transfer size requirement, call `build_transfer` with a specified `xfr_size_requirement`.
    /// To skip an output when generating memos, call `genearte_memos` after removing the record from
    /// the list of outputs.
    pub async fn transfer(
        &mut self,
        account: &UserAddress,
        asset: &AssetCode,
        receivers: &[(UserAddress, u64)],
        fee: u64,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let xfr_info = self
            .build_transfer(account, asset, receivers, fee, vec![], None)
            .await?;
        let memos_rec = match xfr_info.fee_output {
            Some(ro) => {
                let mut rec = vec![ro];
                rec.append(&mut xfr_info.outputs.clone());
                rec
            }
            None => xfr_info.outputs.clone(),
        };
        let (memos, sig) = self
            .generate_memos(memos_rec, &xfr_info.sig_keypair)
            .await?;
        let txn_info = TransactionInfo {
            account: xfr_info.owner_address,
            memos,
            sig,
            freeze_outputs: vec![],
            history: Some(xfr_info.history),
            uid: None,
            inputs: xfr_info.inputs,
            outputs: xfr_info.outputs,
        };
        self.submit_aap(TransactionNote::Transfer(Box::new(xfr_info.note)), txn_info)
            .await
    }

    pub async fn build_transfer(
        &mut self,
        account: &UserAddress,
        asset: &AssetCode,
        receivers: &[(UserAddress, u64)],
        fee: u64,
        bound_data: Vec<u8>,
        xfr_size_requirement: Option<(usize, usize)>,
    ) -> Result<TransferInfo<L>, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        let receivers = iter(receivers)
            .then(|(addr, amt)| {
                let session = &session;
                async move {
                    Ok::<(UserPubKey, u64), WalletError>((
                        session.backend.get_public_key(addr).await?,
                        *amt,
                    ))
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        let spec = TransferSpec {
            owner_keypair: &state.account_keypair(account)?.clone(),
            asset,
            receivers: &receivers,
            fee,
            bound_data,
            xfr_size_requirement,
        };
        state.build_transfer(session, spec)
    }

    pub async fn generate_memos(
        &mut self,
        records: Vec<RecordOpening>,
        sig_keypair: &SigKeyPair,
    ) -> Result<(Vec<ReceiverMemo>, Signature), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.generate_memos(session, records, sig_keypair)
    }

    pub async fn submit(
        &mut self,
        txn: Transaction<L>,
        info: TransactionInfo<L>,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state
            .submit_elaborated_transaction(session, txn, info)
            .await
    }

    pub async fn submit_aap(
        &mut self,
        txn: TransactionNote,
        info: TransactionInfo<L>,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.submit_transaction(session, txn, info).await
    }

    /// define a new asset and store secret info for minting
    pub async fn define_asset(
        &mut self,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.define_asset(session, description, policy).await
    }

    /// start auditing transactions with a given asset type
    pub async fn audit_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.audit_asset(session, asset).await
    }

    /// add an auditor key to the wallet's key set
    pub async fn add_audit_key(&mut self, audit_key: AuditorKeyPair) -> Result<(), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.add_audit_key(session, audit_key).await
    }

    /// generate a new auditor key and add it to the wallet's key set
    pub fn generate_audit_key<'l>(
        &'l mut self,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<AuditorPubKey, WalletError>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
            let audit_key = session
                .auditor_key_stream
                .derive_auditor_keypair(&state.key_state.auditor.to_le_bytes());
            state.key_state.auditor += 1;
            state.add_audit_key(session, audit_key.clone()).await?;
            Ok(audit_key.pub_key())
        })
    }

    /// add a freezer key to the wallet's key set
    pub async fn add_freeze_key(&mut self, freeze_key: FreezerKeyPair) -> Result<(), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.add_freeze_key(session, freeze_key).await
    }

    /// generate a new freezer key and add it to the wallet's key set
    pub fn generate_freeze_key<'l>(
        &'l mut self,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<FreezerPubKey, WalletError>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
            let freeze_key = session
                .freezer_key_stream
                .derive_freezer_keypair(&state.key_state.freezer.to_le_bytes());
            state.key_state.freezer += 1;
            state.add_freeze_key(session, freeze_key.clone()).await?;
            Ok(freeze_key.pub_key())
        })
    }

    /// add a user/spender key to the wallet's key set
    pub async fn add_user_key(
        &mut self,
        user_key: UserKeyPair,
        scan_from: EventIndex,
    ) -> Result<(), WalletError> {
        let mut guard = self.mutex.lock().await;
        let WalletSharedState { state, session, .. } = &mut *guard;
        state
            .add_user_key(session, user_key.clone(), Some(scan_from))
            .await?;

        // Start a background task to scan for records belonging to the new key.
        let events = session
            .backend
            .subscribe(scan_from, Some(state.txn_state.now))
            .await;
        drop(guard);
        self.spawn_key_scan(user_key, events);
        Ok(())
    }

    /// generate a new user key and add it to the wallet's key set. Keys are generated
    /// deterministically based on the mnemonic phrase used to load the wallet. If this is a
    /// recovery of an HD wallet from a mnemonic phrase, `scan_from` can be used to initiate a
    /// background scan of the ledger from the given event index to find records already belonging
    /// to the new key.
    pub fn generate_user_key<'l>(
        &'l mut self,
        scan_from: Option<EventIndex>,
    ) -> std::pin::Pin<Box<dyn SendFuture<'a, Result<UserPubKey, WalletError>> + 'l>>
    where
        'a: 'l,
    {
        Box::pin(async move {
            let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
            let user_key = session
                .user_key_stream
                .derive_user_keypair(&state.key_state.user.to_le_bytes());
            state.key_state.user += 1;
            state
                .add_user_key(session, user_key.clone(), scan_from)
                .await?;
            Ok(user_key.pub_key())
        })
    }

    pub async fn import_memo(
        &mut self,
        memo: ReceiverMemo,
        comm: RecordCommitment,
        uid: u64,
        proof: MerklePath,
    ) -> Result<(), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.import_memo(session, memo, comm, uid, proof).await
    }

    /// create a mint note that assign asset to an owner
    pub async fn build_mint(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(MintNote, TransactionInfo<L>), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state
            .build_mint(session, account, fee, asset_code, amount, owner)
            .await
    }

    pub async fn mint(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let (note, info) = self
            .build_mint(account, fee, asset_code, amount, owner)
            .await?;
        self.submit_aap(TransactionNote::Mint(Box::new(note)), info)
            .await
    }

    pub async fn build_freeze(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(FreezeNote, TransactionInfo<L>), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state
            .build_freeze(
                session,
                account,
                fee,
                asset,
                amount,
                owner,
                FreezeFlag::Frozen,
            )
            .await
    }

    pub async fn freeze(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let (note, info) = self
            .build_freeze(account, fee, asset, amount, owner)
            .await?;
        self.submit_aap(TransactionNote::Freeze(Box::new(note)), info)
            .await
    }

    pub async fn build_unfreeze(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(FreezeNote, TransactionInfo<L>), WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state
            .build_freeze(
                session,
                account,
                fee,
                asset,
                amount,
                owner,
                FreezeFlag::Unfrozen,
            )
            .await
    }

    pub async fn unfreeze(
        &mut self,
        account: &UserAddress,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<TransactionReceipt<L>, WalletError> {
        let (note, info) = self
            .build_unfreeze(account, fee, asset, amount, owner)
            .await?;
        self.submit_aap(TransactionNote::Freeze(Box::new(note)), info)
            .await
    }

    pub async fn transaction_status(
        &self,
        receipt: &TransactionReceipt<L>,
    ) -> Result<TransactionStatus, WalletError> {
        let WalletSharedState { state, session, .. } = &mut *self.mutex.lock().await;
        state.transaction_status(session, receipt).await
    }

    pub async fn await_transaction(
        &self,
        receipt: &TransactionReceipt<L>,
    ) -> Result<TransactionStatus, WalletError> {
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

            if state.user_keys.contains_key(&receipt.submitter) {
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

    pub async fn sync(&self, t: EventIndex) -> Result<(), oneshot::Canceled> {
        let mut guard = self.mutex.lock().await;
        let WalletSharedState {
            state,
            sync_handles,
            ..
        } = &mut *guard;

        // It's important that we do the comparison this way (now >= t) rather than comparing
        // now < t and switching the branches of the `if`. This is because the partial order of
        // EventIndex tells us when _all_ event streams in `now` are at an index >= t, which is the
        // terminating condition for `sync()`: it should wait until _all_ event streams have been
        // processed at least to time `t`.
        if state.txn_state.now >= t {
            Ok(())
        } else {
            let (sender, receiver) = oneshot::channel();
            sync_handles.push((t, sender));
            drop(guard);
            receiver.await
        }
    }

    fn spawn_key_scan(
        &mut self,
        key: UserKeyPair,
        mut events: impl 'a + Stream<Item = (LedgerEvent<L>, EventSource)> + Unpin + Send,
    ) {
        let mutex = self.mutex.clone();
        self.task_scope.spawn_cancellable(
            async move {
                while let Some((event, source)) = events.next().await {
                    let WalletSharedState { state, session, .. } = &mut *mutex.lock().await;
                    state
                        .handle_retroactive_event(session, &key, event, source)
                        .await;
                }

                let WalletSharedState { state, session, .. } = &mut *mutex.lock().await;
                let scan = state.key_scans.remove(&key.address()).unwrap();
                state.add_records(&key, scan.records.into_values().collect());
                session
                    .backend
                    .store(|mut t| async {
                        t.store_snapshot(state).await?;
                        Ok(t)
                    })
                    .await
                    .ok();
            },
            || (),
        );
    }
}

pub fn new_key_pair() -> UserKeyPair {
    UserKeyPair::generate(&mut ChaChaRng::from_entropy())
}
