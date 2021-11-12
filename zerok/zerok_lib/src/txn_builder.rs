// pub mod encryption;
// pub mod hd;
// pub mod network;
// pub mod persistence;
// mod secret;
// use crate::api;
// use crate::key_set;
// use crate::node::LedgerEvent;
use crate::set_merkle_tree::*;
// use crate::util::arbitrary_wrappers::*;
use crate::{
    // ser_test,
    // ElaboratedTransaction,
    ElaboratedTransactionHash,
    ProverKeySet,
    //  ValidationError,
    ValidatorState,
    // MERKLE_HEIGHT,
};
// use arbitrary::{Arbitrary, Unstructured};
// use ark_serialize::*;
// use async_scoped::AsyncScope;
// use async_std::sync::MutexGuard;
// use async_std::task::block_on;
// use async_trait::async_trait;
// use core::fmt::Debug;
// use futures::{
//     // channel::oneshot,
//     prelude::*,
//     stream::Stream,
// };
use jf_txn::{
    // errors::TxnApiError,
    // freeze::{FreezeNote, FreezeNoteInput},
    keys::{
        AuditorKeyPair,
        // AuditorPubKey,
        FreezerKeyPair,
        //  FreezerPubKey,
        UserAddress,
        UserKeyPair,
        UserPubKey,
    },
    // proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        AssetCode,
        AssetCodeSeed,
        AssetDefinition,
        // AssetPolicy,
        // BlindFactor,
        FeeInput,
        FreezeFlag,
        Nullifier,
        ReceiverMemo,
        // RecordCommitment,
        RecordOpening,
        TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness,
    // MerkleLeafProof,
    MerkleTree,
    // Signature,
    TransactionNote,
};
// use jf_utils::tagged_blob;
// use key_set::KeySet;
// use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
// use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::collections::HashMap;
// use std::convert::TryFrom;
// use std::iter::FromIterator;
// use std::ops::{Index, IndexMut};
// use std::sync::Arc;

// #[async_trait]
// pub trait WalletBackend<'a>: Send {
//     type EventStream: 'a + Stream<Item = LedgerEvent> + Unpin + Send;
//     type Storage: WalletStorage<'a> + Send;

//     /// Access the persistent storage layer.
//     ///
//     /// The interface is specified this way, with the main storage interface in a separate trait and
//     /// an accessor function here, to allow implementations of WalletBackend to split the storage
//     /// layer from the networking layer, since the two concerns are generally separate.
//     ///
//     /// Note that the return type of this function requires the implementation to guard the storage
//     /// layer with a mutex, even if it is not internally shared between threads. This is meant to
//     /// allow shared access to the storage layer internal, not require it. A better interface would
//     /// be to have an associated type
//     ///         `type<'l> StorageRef: 'l +  Deref<Target = Self::Storage> + DerefMut`
//     /// This could be MutexGuard, RwLockWriteGuard, or just `&mut Self::Storage`, depending on the
//     /// needs of the implementation. Maybe we can clean this up if and when GATs stabilize.
//     async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage>;

//     async fn load(&mut self) -> Result<WalletState<'a>, WalletError> {
//         let mut storage = self.storage().await;
//         if storage.exists() {
//             // If there is a stored wallet with this key pair, load it.
//             storage.load().await
//         } else {
//             // Otherwise, ask the network layer to create and register a brand new wallet.
//             drop(storage);
//             self.create().await
//         }
//     }

//     /// Make a change to the persisted state using a function describing a transaction.
//     ///
//     /// # Example
//     ///
//     /// ```ignore
//     /// backend.store(key_pair, |mut t| async move {
//     ///     t.store_snapshot(wallet_state).await?;
//     ///     // If this store fails, the effects of the previous store will be reverted.
//     ///     t.store_auditable_asset(wallet_state, asset).await?;
//     ///     Ok(t)
//     /// }).await?;
//     /// ```
//     async fn store<'l, F, Fut>(&'l mut self, update: F) -> Result<(), WalletError>
//     where
//         F: Send + Fn(StorageTransaction<'a, 'l, Self::Storage>) -> Fut,
//         Fut: Send + Future<Output = Result<StorageTransaction<'a, 'l, Self::Storage>, WalletError>>,
//         Self::Storage: 'l,
//     {
//         let storage = self.storage().await;
//         let fut = update(StorageTransaction::new(storage)).and_then(|mut txn| async move {
//             txn.storage.commit().await;
//             Ok(())
//         });
//         fut.await
//     }

//     // Querying the ledger
//     async fn create(&mut self) -> Result<WalletState<'a>, WalletError>;
//     async fn subscribe(&self, starting_at: u64) -> Self::EventStream;
//     async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError>;
//     async fn get_nullifier_proof(
//         &self,
//         root: set_hash::Hash,
//         nullifier: Nullifier,
//     ) -> Result<(bool, SetMerkleProof), WalletError>;

//     // Submit a transaction to a validator.
//     async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError>;
//     async fn post_memos(
//         &mut self,
//         block_id: u64,
//         txn_id: u64,
//         memos: Vec<ReceiverMemo>,
//         sig: Signature,
//     ) -> Result<(), WalletError>;
// }

// pub struct WalletSession<'a, Backend: WalletBackend<'a>> {
//     backend: Backend,
//     rng: ChaChaRng,
//     _marker: std::marker::PhantomData<&'a ()>,
// }

// #[derive(Debug, Snafu)]
// #[snafu(visibility = "pub")]
pub enum XfrError {
    InsufficientBalance,
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
    // InvalidBlock {
    //     source: ValidationError,
    // },
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
    // InvalidAuditorKey {
    //     my_key: AuditorPubKey,
    //     asset_key: AuditorPubKey,
    // },
    // InvalidFreezerKey {
    //     my_key: FreezerPubKey,
    //     asset_key: FreezerPubKey,
    // },
    NetworkError {
        source: phaselock::networking::NetworkError,
    },
    QueryServiceError {
        source: crate::node::QueryServiceError,
    },
    // ClientConfigError {
    //     source: <surf::Client as TryFrom<surf::Config>>::Error,
    // },
    // ConsensusError {
    //     #[snafu(source(false))]
    //     source: Result<phaselock::error::PhaseLockError, String>,
    // },
    PersistenceError {
        source: atomic_store::error::PersistenceError,
    },
    IoError {
        source: std::io::Error,
    },
    BincodeError {
        source: bincode::Error,
    },
    // EncryptionError {
    //     source: encryption::Error,
    // },
    KeyError {
        source: argon2::Error,
    },
    // #[snafu(display("{}", msg))]
    // Failed {
    //     msg: String,
    // },
}

// #[ser_test(arbitrary, ark(false))]
#[derive(Clone, Debug /*, Deserialize, Serialize, PartialEq*/)]
pub struct RecordInfo {
    ro: RecordOpening,
    uid: u64,
    nullifier: Nullifier,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    hold_until: Option<u64>,
}

// #[ser_test(ark(false))]
#[derive(Clone, Debug /*, Default, PartialEq, Serialize, Deserialize*/)]
// #[serde(from = "Vec<RecordInfo>", into = "Vec<RecordInfo>")]
pub struct RecordDatabase {
    // all records in the database, by uid
    record_info: HashMap<u64, RecordInfo>,

    // // record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    // // transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    // // makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    // asset_records: HashMap<(AssetCode, UserPubKey, FreezeFlag), BTreeSet<(u64, u64)>>,

    // record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: HashMap<Nullifier, u64>,
}

// #[ser_test(arbitrary)]
// #[tagged_blob("TXUID")]
// #[derive(
//     Arbitrary, Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize,
// )]
pub struct TransactionUID(ElaboratedTransactionHash);

// #[ser_test(arbitrary)]
// #[tagged_blob("TXN")]
// #[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct TransactionReceipt {
    uid: TransactionUID,
    // fee_nullifier: Nullifier,
    submitter: UserAddress,
}

#[derive(Debug /*, Clone*/)]
pub struct XfrState<'a> {
    pub prng: ChaChaRng,

    pub prover_keys: ProverKeySet<'a>,
    // key pairs for building/receiving transactions
    pub user_keys: UserKeyPair,
    // key pair for decrypting auditor memos
    pub auditor_keys: AuditorKeyPair,
    // key pair for computing nullifiers of records owned by someone else but which we can freeze or
    // unfreeze
    pub freezer_keys: FreezerKeyPair,
    // sequence number of the last event processed
    pub now: u64,
    // wallets run validation in tandem with the validators, so that they do not have to trust new
    // blocks received from the event stream
    pub validator: ValidatorState,

    // all records we care about, including records we own, records we have audited, and records we
    // can freeze or unfreeze
    pub records: RecordDatabase,

    // sparse nullifier set Merkle tree mirrored from validators
    pub nullifiers: SetMerkleTree,
    // sparse record Merkle tree mirrored from validators
    pub record_merkle_tree: MerkleTree,

    // // set of pending transactions
    // pub transactions: TransactionDatabase,

    // // asset definitions for which we are an auditor, indexed by code
    // pub(crate) auditable_assets: HashMap<AssetCode, AssetDefinition>,

    // maps defined asset code to asset definition, seed and description of the asset
    pub defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
}

impl<'a> XfrState<'a> {
    fn find_record(&self) -> Result<(RecordOpening, u64), XfrError> {
        let now = self.validator.prev_commit_time;

        for record in self.records.record_info {
            if record.1.ro.amount > 0 {
                return Ok((record.1.ro, record.1.uid));
            }
        }

        Err(XfrError::InsufficientBalance)
    }

    async fn generate_transfer(
        &mut self,
        receiver: UserPubKey,
        fee_rec: Option<(u64, RecordOpening)>,
        fee: u64,
    ) -> Result<TransactionReceipt, XfrError> {
        let (ro, uid) = self.find_record()?;

        let output = RecordOpening::new(
            &mut self.prng,
            ro.amount / 2,
            ro.asset_def,
            receiver,
            FreezeFlag::Unfrozen,
        );

        // prepare input
        let acc_member_witness = AccMemberWitness::lookup_from_tree(&self.record_merkle_tree, uid)
            .expect_ok()
            .unwrap()
            .1;
        let input = TransferNoteInput {
            ro,
            acc_member_witness,
            owner_keypair: &self.user_keys,
            cred: None,
        };

        // generate transfer note and receiver memos
        let (fee_ro, fee_uid) = self.find_native_record_for_fee(session, fee)?;

        let fee_input = FeeInput {
            ro: fee_ro,
            owner_keypair: &self.user_keys,
            acc_member_witness: AccMemberWitness::lookup_from_tree(
                &self.record_merkle_tree,
                fee_uid,
            )
            .expect_ok()
            .unwrap()
            .1,
        };

        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.prng, fee_input, fee).unwrap();

        const UNEXPIRED_VALID_UNTIL: u64 =
            2u64.pow(jf_txn::constants::MAX_TIMESTAMP_LEN as u32) - 1;
        let (txn, owner_memo_kp) = TransferNote::generate_non_native(
            &mut self.prng,
            vec![input],
            &[output],
            fee_input,
            UNEXPIRED_VALID_UNTIL,
            self.prover_keys,
        )
        .context(CryptoError)?;

        let outputs: Vec<_> = vec![fee_change_ro]
            .into_iter()
            .chain(outputs.into_iter())
            .collect();

        let recv_memos: Vec<_> = outputs
            .iter()
            .map(|ro| ReceiverMemo::from_ro(&mut session.rng, ro, &[]))
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
}
