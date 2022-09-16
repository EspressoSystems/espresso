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

//! # The Espresso Faucet
//!

use async_channel as mpmc;
use async_std::{
    sync::{Arc, Mutex, RwLock},
    task::{sleep, spawn, JoinHandle},
};
use atomic_store::{
    load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader, PersistenceError,
};
use espresso_core::{ledger::EspressoLedger, universal_params::UNIVERSAL_PARAM};
use futures::{channel::mpsc, future::join_all, stream::StreamExt};
use jf_cap::{
    keys::{UserKeyPair, UserPubKey},
    structs::{AssetCode, FreezeFlag},
};
use net::server::response;
use rand::{
    distributions::{Alphanumeric, DistString},
    SeedableRng,
};
use rand_chacha::ChaChaRng;
use reef::traits::Validator;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use structopt::StructOpt;
use surf::Url;
use tide::{
    http::headers::HeaderValue,
    security::{CorsMiddleware, Origin},
    StatusCode,
};
use tracing::{error, info, warn};
use validator_node::keystore::{
    events::EventIndex,
    hd::Mnemonic,
    loader::{MnemonicPasswordLogin, RecoveryLoader},
    network::NetworkBackend,
    records::Record,
    txn_builder::{TransactionStatus, TransactionUID},
    EspressoKeystore, RecordAmount,
};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Espresso Faucet Server",
    about = "Grants a native asset seed to a provided UserPubKey"
)]
pub struct FaucetOptions {
    /// mnemonic for the faucet keystore
    #[structopt(long, env = "ESPRESSO_FAUCET_WALLET_MNEMONIC")]
    pub mnemonic: Mnemonic,

    /// path to the faucet keystore
    #[structopt(long = "keystore-path", env = "ESPRESSO_FAUCET_WALLET_STORE_PATH")]
    pub faucet_keystore_path: Option<PathBuf>,

    /// password on the faucet account keyfile
    #[structopt(
        long = "keystore-password",
        env = "ESPRESSO_FAUCET_WALLET_PASSWORD",
        default_value = ""
    )]
    pub faucet_password: String,

    /// binding port for the faucet service
    #[structopt(long, env = "ESPRESSO_FAUCET_PORT", default_value = "50079")]
    pub faucet_port: u16,

    /// size of transfer for faucet grant
    #[structopt(long, env = "ESPRESSO_FAUCET_GRANT_SIZE", default_value = "5000")]
    pub grant_size: u64,

    /// number of grants to give out per request
    #[structopt(long, env = "ESPRESSO_FAUCET_NUM_GRANTS", default_value = "5")]
    pub num_grants: usize,

    /// fee for faucet grant
    #[structopt(long, env = "ESPRESSO_FAUCET_FEE_SIZE", default_value = "100")]
    pub fee_size: u64,

    /// number of records to maintain simultaneously.
    ///
    /// This allows N transfers to take place simultaneously. A reasonable value is the number of
    /// simultaneous faucet requests you want to allow times ESPRESSO_FAUCET_NUM_GRANTS. There is a
    /// tradeoff in startup cost for having more simultaneous records: when the faucet initializes,
    /// it must execute transfers to itself to break up its records into more, smaller ones. This
    /// can take a long time, and it also forces the relayer to pay a lot of gas.
    #[structopt(
        long,
        name = "N",
        env = "ESPRESSO_FAUCET_NUM_RECORDS",
        default_value = "25"
    )]
    pub num_records: usize,

    /// URL for the Espresso Query Service.
    #[structopt(
        long,
        env = "ESPRESSO_ESQS_URL",
        default_value = "http://localhost:50087"
    )]
    pub esqs_url: Url,

    /// URL for the Espresso address book.
    #[structopt(
        long,
        env = "ESPRESSO_ADDRESS_BOOK_URL",
        default_value = "http://localhost:50078"
    )]
    pub address_book_url: Url,

    /// URL for a validator to submit transactions to.
    #[structopt(
        long,
        env = "ESPRESSO_SUBMIT_URL",
        default_value = "http://localhost:50087"
    )]
    pub submit_url: Url,

    /// Maximum number of outstanding requests to allow in the queue.
    ///
    /// If not provided, the queue can grow arbitrarily large.
    #[structopt(long, env = "ESPRESSO_FAUCET_MAX_QUEUE_LENGTH")]
    pub max_queue_len: Option<usize>,

    /// Number of worker threads.
    ///
    /// It is a good idea to configure the faucet so that this is the same as
    /// `num_records / num_grants`.
    #[structopt(long, env = "ESPRESSO_FAUCET_NUM_WORKERS", default_value = "5")]
    pub num_workers: usize,
}

impl FaucetOptions {
    fn keystore_path(&self) -> PathBuf {
        self.faucet_keystore_path.clone().unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("./")))
                .join(".espresso")
                .join("espresso")
                .join("faucet")
                .join("keystore")
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FaucetStatus {
    Initializing,
    Available,
}

#[derive(Clone)]
struct FaucetState {
    keystore: Arc<Mutex<EspressoKeystore<'static, NetworkBackend<'static>, MnemonicPasswordLogin>>>,
    status: Arc<RwLock<FaucetStatus>>,
    queue: FaucetQueue,
    grant_size: RecordAmount,
    num_grants: usize,
    fee_size: RecordAmount,
    num_records: usize,
    // Channel to signal when the distribution of records owned by the faucet changes. This will
    // wake the record breaker thread (which waits on the receiver) so it can create more records by
    // breaking up larger ones to maintain the target of `num_records`.
    //
    // We use a bounded channel so that a crashed or deadlocked record breaker thread that is not
    // pulling messages out of the queue does not result in an unbounded memory leak.
    signal_breaker_thread: mpsc::Sender<()>,
}

impl FaucetState {
    pub async fn new(
        keystore: EspressoKeystore<'static, NetworkBackend<'static>, MnemonicPasswordLogin>,
        signal_breaker_thread: mpsc::Sender<()>,
        opt: &FaucetOptions,
    ) -> Result<Self, FaucetError> {
        Ok(Self {
            keystore: Arc::new(Mutex::new(keystore)),
            status: Arc::new(RwLock::new(FaucetStatus::Initializing)),
            queue: FaucetQueue::load(&opt.keystore_path(), opt.max_queue_len).await?,
            grant_size: opt.grant_size.into(),
            num_grants: opt.num_grants,
            fee_size: opt.fee_size.into(),
            num_records: opt.num_records,
            signal_breaker_thread,
        })
    }
}

#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(module(error))]
pub enum FaucetError {
    #[snafu(display("error in faucet transfer: {}", msg))]
    Transfer { msg: String },

    #[snafu(display("internal server error: {}", msg))]
    Internal { msg: String },

    #[snafu(display("the queue is full with {} requests, try again later", max_len))]
    QueueFull { max_len: usize },

    #[snafu(display(
        "there is a pending request with key {}, you can only request once at a time",
        key
    ))]
    AlreadyInQueue { key: UserPubKey },

    #[snafu(display("error with persistent storage: {}", msg))]
    Persistence { msg: String },

    #[snafu(display("faucet service temporarily unavailable"))]
    Unavailable,
}

impl net::Error for FaucetError {
    fn catch_all(msg: String) -> Self {
        Self::Internal { msg }
    }
    fn status(&self) -> StatusCode {
        match self {
            Self::Transfer { .. } => StatusCode::BadRequest,
            Self::Internal { .. } => StatusCode::InternalServerError,
            Self::AlreadyInQueue { .. } => StatusCode::TooManyRequests,
            Self::QueueFull { .. } => StatusCode::InternalServerError,
            Self::Persistence { .. } => StatusCode::InternalServerError,
            Self::Unavailable => StatusCode::ServiceUnavailable,
        }
    }
}

impl From<PersistenceError> for FaucetError {
    fn from(source: PersistenceError) -> Self {
        Self::Persistence {
            msg: source.to_string(),
        }
    }
}

pub fn faucet_server_error<E: Into<FaucetError>>(err: E) -> tide::Error {
    net::server_error(err)
}

/// A shared, asynchronous queue of requests.
///
/// The queue is a model of an ordered map from public keys requesting assets to the number of
/// record grants they have received. It is represented as an explicit `HashMap`, which is the
/// authoritative data structure, as well as an auxiliary, implicit queue in the form of an
/// unbounded multi-producer, multi-consumer channel.
///
/// When a new request comes in, it can be added to the queue with [FaucetQueue::push]. This will
/// perform validity checks and then add a new entry mapping the public key to 0. It will also send
/// the public key as a message on the channel. A worker thread will then pick the message off the
/// channel using [FaucetQueue::pop], and start generating transfers to it. Each time the worker
/// completes a transfer to the public key, it will call [FaucetQueue::grant], which increments the
/// counter associated with that public key, persists the change, and instructs the worker to
/// either continue transferring to the same key or to move on to the next key.
///
/// The queue is persistent, so that if the faucet crashes or gets restarted, it doesn't lose the
/// queue of pending requests. The persistent queue is represented as a log of index entries, of the
/// form `UserPubKey -> Option<usize>`. An entry `key -> Some(n)` corresponds to updating the
/// counter associated with `key` to `n`. An entry `key -> None` corresponds to deleting the entry
/// for `key`. We can recover the in-memory index by simply replaying each log entry and inserting
/// or deleting into a `HashMap` as indicated.
///
/// Note that the persistent data format also encodes the order in which requests were added to the
/// queue. A new request being added to the queue corresponds to an entry `key -> Some(0)`, so the
/// queue simply consists of the most recent `key -> Some(0)` entry for each key, in order,
/// filtering out keys that have a more recent `key -> None` entry.
#[derive(Clone)]
struct FaucetQueue {
    sender: mpmc::Sender<(UserPubKey, usize)>,
    receiver: mpmc::Receiver<(UserPubKey, usize)>,
    index: Arc<Mutex<FaucetQueueIndex>>,
    max_len: Option<usize>,
}

// A persistent ordered set.
struct FaucetQueueIndex {
    index: HashMap<UserPubKey, usize>,
    store: AtomicStore,
    queue: AppendLog<BincodeLoadStore<(UserPubKey, Option<usize>)>>,
}

impl FaucetQueueIndex {
    fn len(&self) -> usize {
        self.index.len()
    }

    /// Add an element to the persistent index.
    ///
    /// Returns `true` if the element was inserted or `false` if it was already in the index.
    fn insert(&mut self, key: UserPubKey) -> Result<bool, FaucetError> {
        if self.index.contains_key(&key) {
            // If the key is already in the index, we don't have to persist anything.
            return Ok(false);
        }

        // Add the key to our persistent log.
        self.queue
            .store_resource(&(key.clone(), Some(0)))
            .map_err(|err| {
                error!("storage error adding {} to queue: {}", key, err);
                err
            })?;
        self.queue.commit_version().unwrap();
        self.store.commit_version().unwrap();
        // If successful, add it to our in-memory index.
        self.index.insert(key, 0);
        Ok(true)
    }

    /// Increment the number of grants received by an element in the index.
    ///
    /// If the new number of grants is at least `max_grants`, the entry is removed from the index.
    /// Otherwise, the counter is simply updated.
    ///
    /// Returns `true` if this key needs more grants.
    fn grant(
        &mut self,
        key: UserPubKey,
        granted: usize,
        max_grants: usize,
    ) -> Result<bool, FaucetError> {
        let grants_given = self.index[&key] + granted;
        if grants_given >= max_grants {
            // If this is the last grant to this key, remove it from the index.
            self.remove(&key)?;
            Ok(false)
        } else {
            // Update the entry in our persistent log.
            self.queue
                .store_resource(&(key.clone(), Some(grants_given)))
                .map_err(|err| {
                    error!("storage error updating {} in queue: {}", key, err);
                    err
                })?;
            self.queue.commit_version().unwrap();
            self.store.commit_version().unwrap();
            // If successful, update our in-memory index.
            self.index.insert(key, grants_given);
            Ok(true)
        }
    }

    /// Remove an element from the persistent set.
    fn remove(&mut self, key: &UserPubKey) -> Result<(), FaucetError> {
        // Make a persistent note to remove the key.
        self.queue
            .store_resource(&(key.clone(), None))
            .map_err(|err| {
                error!("storage error removing {} from queue: {}", key, err);
                err
            })?;
        self.queue.commit_version().unwrap();
        self.store.commit_version().unwrap();
        // Update our in-memory set.
        self.index.remove(key);
        Ok(())
    }

    /// Get the number of grants already given to this key.
    fn grants(&self, key: &UserPubKey) -> usize {
        self.index[key]
    }
}

impl FaucetQueue {
    async fn load(store: &Path, max_len: Option<usize>) -> Result<Self, FaucetError> {
        // Load from storage.
        let mut loader = AtomicStoreLoader::load(store, "queue")?;
        let persistent_queue = AppendLog::load(&mut loader, Default::default(), "requests", 1024)?;
        let store = AtomicStore::open(loader)?;

        // Traverse the persisted queue entries backwards. This ensures that we encounter the most
        // recent value for each key first. If the most recent value for a given key is `Some(n)`,
        // it gets added to the index. If it is `None`, we just store `None` in `index` so that if
        // we see this key again, we know we are not seeing the most recent value.
        let mut index = HashMap::new();
        // In addition, for the most recent `Some(0)` entry for each `key`, we also add that key to
        // the message channel, as long as there is not a more recent `None` entry. We use the set
        // `processed` to keep track of which elements have already been processed into the message
        // channel if necessary. An element is `processed` if we have added it to the message
        // channel, or if we have encountered a `None` entry for it and skipped it.
        let mut processed = HashSet::new();
        // We are encountering requests in reverse order, so if we need to add them to the queue, we
        // will add them to this [Vec] and then reverse it at the end before adding them to the
        // message channel.
        let mut queue = Vec::new();
        let entries: Vec<(UserPubKey, Option<usize>)> =
            persistent_queue.iter().collect::<Result<_, _>>()?;
        for (key, val) in entries.into_iter().rev() {
            if !index.contains_key(&key) {
                if let Some(val) = val {
                    // This is the most recent value for `key`, and it is an insert, which means
                    // `key` is in the queue. Go ahead and add it to the index and the message
                    // channel.
                    index.insert(key.clone(), Some(val));
                } else {
                    // This is the most recent value for `key`, and it is a delete, which means
                    // `key` is not in the queue. Remember this information in `index`.
                    index.insert(key.clone(), None);
                }
            }

            if !processed.contains(&key) {
                // We have seen neither a `Some(0)` or `None` entry for this element.
                if val == Some(0) {
                    // In the case of a `Some(0)` entry, the element should be in the queue.
                    queue.push(key.clone());
                    processed.insert(key);
                } else if val == None {
                    // In the case of a `None` entry, just add the element to `processed` so that it
                    // will not be added to the queue later.
                    processed.insert(key);
                }
            }
        }

        // Post-process `index` to remove [None] values.
        let index = index
            .into_iter()
            .filter_map(|(key, val)| val.map(|val| (key, val)))
            .collect::<HashMap<_, _>>();

        let (sender, receiver) = mpmc::unbounded();
        for key in queue.into_iter().rev() {
            let grants = index[&key];
            // `send` only fails if the receiving end of the channel has been dropped, but we have
            // the receiving end right now, so this `unwrap` will never fail.
            sender.send((key, grants)).await.unwrap();
        }

        Ok(Self {
            index: Arc::new(Mutex::new(FaucetQueueIndex {
                index,
                queue: persistent_queue,
                store,
            })),
            sender,
            receiver,
            max_len,
        })
    }

    async fn push(&self, key: UserPubKey) -> Result<(), FaucetError> {
        {
            // Try to insert this key into the index.
            let mut index = self.index.lock().await;
            if let Some(max_len) = self.max_len {
                if index.len() >= max_len {
                    warn!("rejecting {} because queue is full ({})", key, max_len);
                    return Err(FaucetError::QueueFull { max_len });
                }
            }
            if !index.insert(key.clone())? {
                warn!("rejecting {} because it is already in the queue", key);
                return Err(FaucetError::AlreadyInQueue { key });
            }
        }
        // If we successfully added the key to the index, we can send it to a receiver.
        if self.sender.send((key, 0)).await.is_err() {
            warn!("failed to add request to the queue: channel is closed");
        }
        Ok(())
    }

    async fn pop(&mut self) -> Option<(UserPubKey, usize)> {
        let req = self.receiver.next().await?;
        Some(req)
    }

    async fn grant(&mut self, request: UserPubKey, granted: usize, max_grants: usize) -> bool {
        self.index
            .lock()
            .await
            .grant(request, granted, max_grants)
            .unwrap_or(false)
    }

    async fn fail(&mut self, key: UserPubKey) {
        let grants = { self.index.lock().await.grants(&key) };
        if let Err(err) = self.sender.send((key, grants)).await {
            error!(
                "error re-adding failed request; request will be dropped. {}",
                err
            );
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub status: FaucetStatus,
}

/// Return a JSON expression with status 200 indicating the server
/// is up and running. The JSON expression is simply,
///    `{"status": Status}`
/// where `Status` is one of
/// * "initializing"
/// * "available"
/// When the server is running but unable to process requests
/// normally, a response with status 503 and payload {"status":
/// "unavailable"} should be added.
async fn healthcheck(req: tide::Request<FaucetState>) -> Result<tide::Response, tide::Error> {
    response(
        &req,
        &HealthCheck {
            status: *req.state().status.read().await,
        },
    )
}

async fn check_service_available(state: &FaucetState) -> Result<(), tide::Error> {
    if *state.status.read().await == FaucetStatus::Available {
        Ok(())
    } else {
        Err(faucet_server_error(FaucetError::Unavailable))
    }
}

async fn request_fee_assets(
    mut req: tide::Request<FaucetState>,
) -> Result<tide::Response, tide::Error> {
    check_service_available(req.state()).await?;
    let pub_key: UserPubKey = net::server::request_body(&mut req).await?;
    response(
        &req,
        &req.state()
            .queue
            .push(pub_key)
            .await
            .map_err(faucet_server_error)?,
    )
}

async fn worker(id: usize, mut state: FaucetState) {
    'wait_for_requests: while let Some((pub_key, mut grants)) = state.queue.pop().await {
        assert!(grants < state.num_grants);
        loop {
            // If we don't have a sufficient balance, to transfer, it is probably only because some
            // transactions are in flight. We are likely to get change back when the transactions
            // complete, so wait until we have a sufficient balance to do our job.
            let (mut keystore, balance) = loop {
                let keystore = state.keystore.lock().await;
                let balance = keystore.balance(&AssetCode::native()).await;
                if balance < state.grant_size.into() {
                    warn!(
                        "worker {}: insufficient balance for transfer, sleeping for 30s",
                        id
                    );
                    drop(keystore);
                    sleep(Duration::from_secs(30)).await;
                } else {
                    let records = spendable_records(&keystore, state.grant_size).await.count();
                    info!(
                        "worker {}: keystore balance before transfer: {} across {} records",
                        id, balance, records
                    );
                    break (keystore, balance);
                }
            };
            let (res, new_grants) =
                if state.num_grants - grants > 1 && balance >= (state.grant_size * 2).into() {
                    // If the receiver is still owed multiple grants and we have enough balance to
                    // make 2 simultaneous grants, take advantage of the 3-output proving key to
                    // create 2 grants at the same time.
                    info!(
                        "worker {}: transferring 2 records of {} tokens each to {}",
                        id,
                        state.grant_size,
                        net::UserAddress(pub_key.address())
                    );
                    (
                        keystore
                            .transfer(
                                None,
                                &AssetCode::native(),
                                &[
                                    (pub_key.clone(), state.grant_size),
                                    (pub_key.clone(), state.grant_size),
                                ],
                                state.fee_size,
                            )
                            .await,
                        2,
                    )
                } else {
                    info!(
                        "worker {}: transferring 1 record of {} tokens to {}",
                        id,
                        state.grant_size,
                        net::UserAddress(pub_key.address())
                    );
                    (
                        keystore
                            .transfer(
                                None,
                                &AssetCode::native(),
                                &[(pub_key.clone(), state.grant_size)],
                                state.fee_size,
                            )
                            .await,
                        1,
                    )
                };
            if let Err(err) = res {
                error!("worker {}: failed to transfer: {}", id, err);
                // If we failed, mark the request as failed in the queue so it can be retried later.
                state.queue.fail(pub_key).await;
                continue 'wait_for_requests;
            }

            // Update the queue with the results of this grant; find out if the key needs more
            // grants or not.
            if !state
                .queue
                .grant(pub_key.clone(), new_grants, state.num_grants)
                .await
            {
                break;
            }
            grants += new_grants;
        }

        // Signal the record breaking thread that we have spent some records, so that it can create
        // more by breaking up larger records.
        if state.signal_breaker_thread.clone().try_send(()).is_err() {
            error!(
                "worker {}: error signalling the breaker thread. Perhaps it has crashed?",
                id
            );
        }
    }

    warn!("worker {}: exiting, request queue closed", id);
}

async fn spendable_records(
    keystore: &EspressoKeystore<'static, NetworkBackend<'static>, MnemonicPasswordLogin>,
    grant_size: RecordAmount,
) -> impl Iterator<Item = Record> {
    let now = keystore.read().await.state().txn_state.validator.now();
    keystore.records().await.into_iter().filter(move |record| {
        record.asset_code() == AssetCode::native()
            && record.amount() >= grant_size
            && record.freeze_flag() == FreezeFlag::Unfrozen
            && !record.on_hold(now)
    })
}

/// Worker task to maintain at least `state.num_records` in the faucet keystore.
///
/// When signalled on `wakeup`, this thread will break large records into small records of size
/// `state.grant_size`, until there are at least `state.num_records` distinct records in the
/// keystore.
///
/// The record breakup is only triggered when the number of available records is less than half of
/// the desired number of records, and in that case we always replenish all the way to the desired
/// number of records if possible. This prevents us from generating a record transaction every time
/// we do a transfer, and ensures that whenever we do break up records, we break up many at a time,
/// so we can take advantage of the parallelism of having multiple record breakup transactions in
/// flight at the same time.
async fn maintain_enough_records(state: FaucetState, mut wakeup: mpsc::Receiver<()>) {
    loop {
        // Wait until we have few enough records that we need to break them up, and we have a big
        // enough record to break up.
        //
        // This is a simulation of a condvar loop, since async condvar is unstable, hence the manual
        // drop and reacquisition of the keystore mutex guard.
        loop {
            let keystore = state.keystore.lock().await;
            let records = spendable_records(&keystore, state.grant_size)
                .await
                .collect::<Vec<_>>();
            if records.len() >= state.num_records / 2 {
                // We have enough records for now, wait for a signal that the number of records has
                // changed.
                info!(
                    "got {}/{} records, waiting for a change",
                    records.len(),
                    state.num_records
                );
            } else if !records
                .into_iter()
                .any(|record| record.amount() > state.grant_size * 2u64)
            {
                // There are no big records to break up, so there's nothing for us to do. Exit
                // the inner loop and wait for a notification that the record distribution has
                // changed.
                warn!("not enough records, but no large records to break up");
            } else {
                // We don't have enough records and we do have a big record to break up. Break out
                // of the wait loop and enter the next loop to break up our records.
                break;
            }

            drop(keystore);
            wakeup.next().await;
        }

        if let Some(transactions) = break_up_records(&state).await {
            // If we succeeded, wait until we are signalled again. Even though we may not have
            // enough records just yet, we will when the transactions submitted by
            // `break_up_records` finalize. Returning to the previous loop and checking if we have
            // enough records might spuriously lead us to call `break_up_records` again, which would
            // be an unnecessary waste of time.
            info!(
                "will have sufficient records after {} transactions, waiting for a change",
                transactions.len()
            );
            wakeup.next().await;
        }
    }
}

/// Break records into smaller pieces to create at least `state.num_records` total.
///
/// If successful, returns a list of transaction receipts which will give at least
/// `state.num_records` when they are finalized. If there were not enough large records to break up
/// to obtain the desired number of records, returns [None].
async fn break_up_records(state: &FaucetState) -> Option<Vec<TransactionUID<EspressoLedger>>> {
    // Break up records until we have enough again.
    loop {
        // Generate as many transactions as we can simultaneously.
        let mut transactions = Vec::new();
        loop {
            // Acquire the keystore lock inside the loop, so we release it after each transfer.
            // Holding the lock for too long can unneccessarily slow down faucet requests.
            let mut keystore = state.keystore.lock().await;
            let pub_key = keystore.sending_keys().await[0].pub_key().clone();
            let records = spendable_records(&keystore, state.grant_size)
                .await
                .collect::<Vec<_>>();

            if records.len() + 2 * transactions.len() >= state.num_records {
                // We will have enough records again once the pending transactions finish. Return
                // _without_ waiting for pending transactions to finish: if we know we are going to
                // have enough records once they finish, there is no point in holding the keystore
                // lock and just waiting. Perhaps a faucet request can be filled using the records
                // we already have while the last few transactions are pending.
                //
                // Return the list of transaction receipts so the caller can wait on them if they
                // want.
                return Some(transactions);
            }

            let largest_record = match records
                .into_iter()
                .max_by(|x, y| x.amount().cmp(&y.amount()))
            {
                Some(record) if record.amount() >= state.grant_size * 2u64 => record,
                _ => {
                    // There are no records large enough to break up. Break out of the loop and wait
                    // for the transactions we have already initiated to finish. The change from
                    // those transactions will give us more records to break up.
                    break;
                }
            };

            let split_amount = largest_record.amount() / 2;
            let change_amount = largest_record.amount() - split_amount;

            info!(
                "breaking up a record of size {} into records of size {} and {}",
                largest_record.amount(),
                split_amount,
                change_amount,
            );

            // There is not yet an interface for transferring a specific record, so we just have to
            // specify the appropriate amounts and trust that Seahorse will use the largest record
            // available (it should). We specify two outputs so that if an existing record with
            // `change_amount` exists it won't be used "as is", which would prevent this loop
            // from making progress.
            let receipt = match keystore
                .transfer(
                    None,
                    &AssetCode::native(),
                    &[
                        (pub_key.clone(), change_amount),
                        (pub_key.clone(), split_amount),
                    ],
                    0u64,
                )
                .await
            {
                Ok(receipt) => receipt,
                Err(err) => {
                    // If our transfers start failing, we will assume there is something wrong and
                    // try not to put extra stress on the system. Break out of the inner loop and
                    // wait for the transactions we did initiate to finish.
                    error!("record breakup transfer failed: {}", err);
                    break;
                }
            };
            transactions.push(receipt);
        }

        if transactions.is_empty() {
            // We did not have sufficient records to generate any break-up transactions. Give up
            // early and return with fewer-than-desired records. When the allocation of records
            // changes, the record breaker thread will be notified and we will get to try again.
            warn!("No large records to break up");
            return None;
        }

        // If we get here, it means we generated some transactions, but it was not enough to give us
        // the desired number of records. Wait until those transactions finish, then repeat the
        // process, splitting up the outputs of those transactions.
        //
        // Note we have to reacquire the lock, since we released it at the end of the previous loop.
        // This is good: it potentially allows another thread to grab the lock and make a transfer
        // before we acquire it, during time where we would just be idly waiting. If this happens,
        // it only means we spend less time waiting for our transactions once we are able to
        // reacquire the lock.
        info!(
            "waiting for {} transactions before breaking more records",
            transactions.len()
        );
        let keystore = state.keystore.lock().await;
        for result in join_all(
            transactions
                .iter()
                .map(|receipt| keystore.await_transaction(receipt)),
        )
        .await
        {
            if !matches!(result, Ok(TransactionStatus::Retired)) {
                error!("record breakup transfer did not complete successfully");
            }
        }
    }
}

/// `faucet_key_pair` - If provided, will be added to the faucet keystore.
pub async fn init_web_server(
    rng: &mut ChaChaRng,
    opt: &FaucetOptions,
    faucet_key_pair: Option<UserKeyPair>,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    let mut password = opt.faucet_password.clone();
    if password.is_empty() {
        password = Alphanumeric.sample_string(rng, 16);
    }
    let mut loader = RecoveryLoader::new(rng, opt.keystore_path(), opt.mnemonic.clone(), password);
    let backend = NetworkBackend::new(
        &UNIVERSAL_PARAM,
        opt.esqs_url.clone(),
        opt.address_book_url.clone(),
        opt.submit_url.clone(),
    )
    .await
    .unwrap();
    let mut keystore = EspressoKeystore::new(backend, &mut loader).await.unwrap();

    // If a faucet key pair is provided, add it to the keystore. Otherwise, if we're initializing
    // for the first time, we need to generate a key. The faucet should be set up so that the
    // first HD sending key is the faucet key.
    let new_key = if let Some(key) = faucet_key_pair {
        keystore
            .add_sending_account(key.clone(), "faucet".into(), EventIndex::default())
            .await
            .unwrap();
        Some(key.pub_key())
    } else if keystore.sending_keys().await.is_empty() {
        // We pass `EventIndex::default()` to start a scan of the ledger from the beginning, in
        // order to discover the faucet record.
        Some(
            keystore
                .generate_sending_account("faucet".into(), Some(EventIndex::default()))
                .await
                .unwrap(),
        )
    } else {
        None
    };

    // Start the app before we wait for the key scan to complete. If we have to restart the faucet
    // service from scratch (for example, if the keystore storage format changes and we need to
    // recreate our files from a mnemonic) the key scan could take a very long time. We want the
    // healthcheck endpoint to be available and returning "initializing" during that time, so the
    // load balancer doesn't kill the service before it has a chance to start up. Other endpoints
    // will fail while the app is initializing. Once initialization is complete, the healthcheck
    // state will change to "available" and the other endpoints will start to work.
    //
    // The app state includes a bounded channel used to signal the record breaking thread when we
    // need it to break large records into smaller ones. We use the total number of records to
    // maintain as a conservative upper bound on how backed up the message channel can get.
    let signal_breaker_thread = mpsc::channel(opt.num_records);
    let state = FaucetState::new(keystore, signal_breaker_thread.0, opt)
        .await
        .unwrap();
    let mut app = tide::with_state(state.clone());
    app.at("/healthcheck").get(healthcheck);
    app.with(
        CorsMiddleware::new()
            .allow_methods("GET, POST".parse::<HeaderValue>().unwrap())
            .allow_headers("*".parse::<HeaderValue>().unwrap())
            .allow_origin(Origin::from("*")),
    );
    app.at("/request_fee_assets").post(request_fee_assets);
    let address = format!("0.0.0.0:{}", opt.faucet_port);
    let handle = spawn(app.listen(address));

    if let Some(key) = new_key {
        // Wait until we have scanned the ledger for records belonging to this key.
        state
            .keystore
            .lock()
            .await
            .await_key_scan(&key.address())
            .await
            .unwrap();
    }

    let bal = state
        .keystore
        .lock()
        .await
        .balance(&AssetCode::native())
        .await;
    tracing::info!("Keystore balance before init: {}", bal);

    // Create at least `opt.num_records` if possible, before starting to handle requests.
    if let Some(transactions) = break_up_records(&state).await {
        let keystore = state.keystore.lock().await;
        join_all(
            transactions
                .iter()
                .map(|receipt| keystore.await_transaction(receipt)),
        )
        .await;
    }

    // Spawn a thread to continuously break records into smaller records to maintain
    // `opt.num_records` at a time.
    spawn(maintain_enough_records(
        state.clone(),
        signal_breaker_thread.1,
    ));

    // Spawn the worker threads that will handle faucet requests.
    for id in 0..opt.num_workers {
        spawn(worker(id, state.clone()));
    }

    *state.status.write().await = FaucetStatus::Available;

    Ok(handle)
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Initialize the faucet web server.
    init_web_server(
        &mut ChaChaRng::from_entropy(),
        &FaucetOptions::from_args(),
        None,
    )
    .await?
    .await?;

    Ok(())
}

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use super::*;
    use async_std::task::{sleep, spawn_blocking};
    use escargot::CargoBuild;
    use espresso_validator::testing::minimal_test_network;
    use futures::{future::join_all, Future};
    use jf_cap::structs::AssetDefinition;
    use net::client::response_body;
    use portpicker::pick_unused_port;
    use primitive_types::U256;
    use rand::Rng;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use std::path::PathBuf;
    use std::process::Child;
    use std::time::Duration;
    use tempdir::TempDir;
    use tracing_test::traced_test;
    use validator_node::keystore::{hd::KeyTree, loader::CreateLoader};

    async fn retry<Fut: Future<Output = bool>>(f: impl Fn() -> Fut) {
        let mut backoff = Duration::from_millis(100);
        for _ in 0..13 {
            if f().await {
                return;
            }
            sleep(backoff).await;
            backoff *= 2;
        }
        panic!("retry loop did not complete in {:?}", backoff);
    }

    struct Faucet {
        esqs_url: Url,
        submit_url: Url,
        address_book_url: Url,
        mnemonic: Mnemonic,
        dir: PathBuf,
        port: u16,
        grant_size: RecordAmount,
        num_grants: usize,
        num_requests: usize,
        process: Option<Child>,
    }

    impl Faucet {
        async fn start(&mut self) {
            let esqs_url = self.esqs_url.to_string();
            let submit_url = self.submit_url.to_string();
            let address_book_url = self.address_book_url.to_string();
            let mnemonic = self.mnemonic.to_string();
            let dir = self.dir.display().to_string();
            let port = self.port.to_string();
            let grant_size = self.grant_size.to_string();
            let num_grants = self.num_grants.to_string();
            let num_requests = self.num_requests.to_string();
            let num_records = (self.num_grants * self.num_requests).to_string();

            self.process = Some(
                CargoBuild::new()
                    .current_release()
                    .current_target()
                    .bin("faucet")
                    .run()
                    .unwrap()
                    .command()
                    .args([
                        "--esqs-url",
                        &esqs_url,
                        "--submit-url",
                        &submit_url,
                        "--address-book-url",
                        &address_book_url,
                        "--mnemonic",
                        &mnemonic,
                        "--keystore-path",
                        &dir,
                        "--faucet-port",
                        &port,
                        "--grant-size",
                        &grant_size,
                        "--num-grants",
                        &num_grants,
                        "--num-records",
                        &num_records,
                        "--max-queue-len",
                        &num_requests,
                        "--num-workers",
                        &num_requests,
                    ])
                    .spawn()
                    .unwrap(),
            );

            // Wait for the service to become available.
            loop {
                if let Ok(mut res) = surf::get(format!("http://localhost:{}/healthcheck", port))
                    .send()
                    .await
                {
                    let health: HealthCheck = response_body(&mut res).await.unwrap();
                    if health.status == FaucetStatus::Available {
                        break;
                    }
                }

                sleep(Duration::from_secs(10)).await;
            }
        }

        async fn stop(&mut self) {
            if let Some(mut process) = self.process.take() {
                spawn_blocking(move || {
                    process.kill().unwrap();
                    process.wait().unwrap();
                })
                .await;
            }
        }

        async fn restart(&mut self) {
            self.stop().await;
            self.start().await;
        }
    }

    async fn parallel_request(num_requests: usize, restart: bool) {
        let mut rng = ChaChaRng::from_seed([1u8; 32]);

        // Create test network with a faucet key pair.
        let (key_stream, mnemonic) = KeyTree::random(&mut rng);
        let faucet_key_pair = key_stream
            .derive_sub_tree("keystore".as_bytes())
            .derive_sub_tree("user".as_bytes())
            .derive_user_key_pair(&0u64.to_le_bytes());
        let network = minimal_test_network(&mut rng, faucet_key_pair.pub_key()).await;

        // Initiate a faucet server with the mnemonic associated with the faucet key pair.
        let faucet_dir = TempDir::new("espresso_keystore_faucet").unwrap();
        let faucet_port = pick_unused_port().unwrap();
        let grant_size = RecordAmount::from(1000u64);
        let num_grants = 5;
        let mut faucet = Faucet {
            esqs_url: network.query_api.clone(),
            submit_url: network.submit_api.clone(),
            address_book_url: network.address_book_api.clone(),
            mnemonic,
            dir: faucet_dir.path().to_owned(),
            port: faucet_port,
            grant_size,
            num_grants,
            num_requests,
            process: None,
        };
        faucet.start().await;
        println!("Faucet server initiated.");

        // Check the status is "available".
        let mut res = surf::get(format!("http://localhost:{}/healthcheck", faucet_port))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(
            HealthCheck {
                status: FaucetStatus::Available
            },
            res.body_json().await.unwrap(),
        );

        // Create receiver keystores.
        let mut keystores = Vec::new();
        let mut keys = Vec::new();
        let mut temp_dirs = Vec::new();
        for i in 0..num_requests {
            let receiver_dir = TempDir::new("espresso_keystore_receiver").unwrap();
            let receiver_mnemonic = KeyTree::random(&mut rng).1;
            let mut receiver_loader = CreateLoader::exclusive(
                &mut rng,
                PathBuf::from(receiver_dir.path()),
                receiver_mnemonic,
                Alphanumeric.sample_string(&mut rand::thread_rng(), 16),
            );
            let mut receiver = network.create_keystore(&mut receiver_loader).await;
            let receiver_key = receiver
                .generate_sending_account("receiver".into(), None)
                .await
                .unwrap();
            println!("Receiver keystore {} created.", i);

            temp_dirs.push(receiver_dir);
            keystores.push(receiver);
            keys.push(receiver_key);
        }

        join_all(keys.iter().map(|key| {
            let url = format!("http://localhost:{}/request_fee_assets", faucet_port);
            async move {
                // Request native asset for the receiver.
                let response = surf::post(url)
                    .content_type(surf::http::mime::BYTE_STREAM)
                    .body_bytes(&bincode::serialize(key).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::Ok);
                println!("Asset transferred.");
            }
        }))
        .await;

        if restart {
            // After submitting all of the requests, wait a random amount of time, and then kill and
            // restart the faucet, so that it has to reload from storage.
            let delay = ChaChaRng::from_entropy().gen_range(0..30);
            tracing::info!("Waiting {} seconds, then killing faucet", delay);
            sleep(Duration::from_secs(delay)).await;
            faucet.restart().await;
        }

        // Check the balances for each keystore.
        join_all(
            keystores
                .into_iter()
                .zip(keys)
                .enumerate()
                .map(|(i, (keystore, key))| async move {
                    retry(|| async {
                        let balance = keystore.balance(&AssetCode::native()).await;
                        let desired = U256::from(grant_size) * num_grants;
                        println!("Keystore {}: balance is {}/{}", i, balance, desired);
                        if restart {
                            // It is possible to get an extra record, if we shut down the faucet at
                            // just the right time.
                            balance >= desired
                        } else {
                            balance == desired
                        }
                    })
                    .await;

                    // We should have received at least `num_grants` records of `grant_size` each.
                    let records = keystore.records().await;
                    if restart {
                        assert!(
                            records.len() >= num_grants,
                            "received {}/{}",
                            records.len(),
                            num_grants
                        );
                    } else {
                        assert_eq!(records.len(), num_grants);
                    }
                    for record in records {
                        assert_eq!(*record.asset_definition(), AssetDefinition::native());
                        assert_eq!(*record.pub_key(), key);
                        assert_eq!(record.amount(), grant_size);
                    }
                })
                .collect::<Vec<_>>(),
        )
        .await;

        faucet.stop().await;
    }

    #[async_std::test]
    #[traced_test]
    async fn test_faucet_transfer() {
        parallel_request(1, false).await;
    }

    #[async_std::test]
    #[traced_test]
    async fn test_faucet_transfer_restart() {
        parallel_request(1, true).await;
    }

    #[async_std::test]
    #[traced_test]
    async fn test_faucet_simultaneous_transfer_restart() {
        parallel_request(5, true).await;
    }
}
