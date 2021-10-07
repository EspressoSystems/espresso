pub mod network;
mod persistence;

use crate::ValidationError;
use async_std::sync::Mutex;
use async_trait::async_trait;
use core::fmt::Debug;
use futures::{
    prelude::*,
};
use jf_txn::{
    errors::TxnApiError,
    keys::{AuditorPubKey, FreezerPubKey, UserAddress, UserKeyPair},
    structs::{AssetCode, Nullifier},
};
use snafu::Snafu;
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
    PersistenceError {
        source: atomic_store::error::PersistenceError,
    },
    IoError {
        source: std::io::Error,
    },
    BincodeError {
        source: bincode::Error,
    },
    #[snafu(display("{}", msg))]
    Failed {
        msg: String,
    },
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
pub trait WalletStorage<'a> {
}

#[async_trait]
pub trait WalletBackend<'a>: Send {
    type Storage: WalletStorage<'a> + Send + Sync;

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
    #[deny(clippy::future_not_send)]
    async fn store<'l, F, Fut>(
        &'l mut self,
        _key_pair: &'l UserKeyPair,
        _update: F,
    ) -> Result<(), WalletError>
    where
        F: Fn(Self::Storage) -> Fut + Send,
        Fut: Future<Output = Result<(), WalletError>> + Send,
    {
        Ok(())
    }
}

pub struct WalletSession<'a, Backend: WalletBackend<'a>> {
    backend: Backend,
    key_pair: UserKeyPair,
    _marker: std::marker::PhantomData<&'a ()>,
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
    mutex: Arc<Mutex<WalletSession<'a, Backend>>>,
}

impl<'a, Backend: 'a + WalletBackend<'a> + Send + Sync> Wallet<'a, Backend> {
    
    #[deny(clippy::future_not_send)]
    pub async fn transfer(
        &mut self,
    ) -> Result<(), WalletError> {
        let fut = self.mutex.lock();
        let _: &dyn Sync = &fut;

        let session = &mut *fut.await;
        let _: &dyn Sync = &session;

        let _: &dyn Sync = &session.backend;
        let _: &dyn Sync = &session.key_pair;

        session
            .backend
            .store(&session.key_pair, |t| {
                // let state = &self;
                let _: &dyn Sync = &t;
                let fut = async move {
                    // t.store_snapshot(state).await?;
                    Ok(())
                };
                let _: &dyn Sync = &fut;
                fut
            })
            .await
    }
}
