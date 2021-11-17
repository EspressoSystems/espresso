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
    ElaboratedTransaction,
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
    errors::TxnApiError,
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
        RecordCommitment,
        RecordOpening,
        TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness,
    MerkleLeafProof,
    MerkleTree,
    Signature,
    TransactionNote,
};
// use jf_utils::tagged_blob;
// use key_set::KeySet;
// use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
// use serde::{Deserialize, Serialize};
// use snafu::ResultExt;
use std::collections::{BTreeSet, HashMap};
// use std::convert::TryFrom;
// use std::iter::FromIterator;
// use std::ops::{Index, IndexMut};
// use std::sync::Arc;

// #[derive(/*Debug,*/ Snafu)]
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

    // record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    // transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    // makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    asset_records: HashMap<(AssetCode, UserPubKey, FreezeFlag), BTreeSet<(u64, u64)>>,

    // record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: HashMap<Nullifier, u64>,
}

impl RecordDatabase {
    // fn assets(&'_ self) -> impl '_ + Iterator<Item = AssetDefinition> {
    //     self.record_info
    //         .values()
    //         .map(|rec| rec.ro.asset_def.clone())
    // }

    // /// Find records which can be the input to a transaction, matching the given parameters.
    // fn input_records<'a>(
    //     &'a self,
    //     asset: &AssetCode,
    //     owner: &UserPubKey,
    //     frozen: FreezeFlag,
    //     now: u64,
    // ) -> impl Iterator<Item = &'a RecordInfo> {
    //     self.asset_records
    //         .get(&(*asset, owner.clone(), frozen))
    //         .into_iter()
    //         .flatten()
    //         .rev()
    //         .filter_map(move |(_, uid)| {
    //             let record = &self.record_info[uid];
    //             if record.ro.amount == 0 || record.on_hold(now) {
    //                 // Skip useless dummy records and records that are on hold
    //                 None
    //             } else {
    //                 Some(record)
    //             }
    //         })
    // }
    // /// Find a record with exactly the requested amount, which can be the input to a transaction,
    // /// matching the given parameters.
    // fn input_record_with_amount(
    //     &self,
    //     asset: &AssetCode,
    //     owner: &UserPubKey,
    //     frozen: FreezeFlag,
    //     amount: u64,
    //     now: u64,
    // ) -> Option<&RecordInfo> {
    //     let unspent_records = self.asset_records.get(&(*asset, owner.clone(), frozen))?;
    //     let exact_matches = unspent_records.range((amount, 0)..(amount + 1, 0));
    //     for (match_amount, uid) in exact_matches {
    //         assert_eq!(*match_amount, amount);
    //         let record = &self.record_info[uid];
    //         assert_eq!(record.ro.amount, amount);
    //         if record.on_hold(now) {
    //             continue;
    //         }
    //         return Some(record);
    //     }

    //     None
    // }

    // fn record_with_nullifier(&self, nullifier: &Nullifier) -> Option<&RecordInfo> {
    //     let uid = self.nullifier_records.get(nullifier)?;
    //     self.record_info.get(uid)
    // }

    // fn record_with_nullifier_mut(&mut self, nullifier: &Nullifier) -> Option<&mut RecordInfo> {
    //     let uid = self.nullifier_records.get(nullifier)?;
    //     self.record_info.get_mut(uid)
    // }

    fn insert_record(&mut self, rec: RecordInfo) {
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

    fn insert_with_nullifier(&mut self, ro: RecordOpening, uid: u64, nullifier: Nullifier) {
        self.insert_record(RecordInfo {
            ro,
            uid,
            nullifier,
            hold_until: None,
        });
    }

    fn insert(&mut self, ro: RecordOpening, uid: u64, key_pair: &UserKeyPair) {
        let nullifier = key_pair.nullify(
            ro.asset_def.policy_ref().freezer_pub_key(),
            uid,
            &RecordCommitment::from(&ro),
        );
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    // fn insert_freezable(&mut self, ro: RecordOpening, uid: u64, key_pair: &FreezerKeyPair) {
    //     let nullifier = key_pair.nullify(&ro.pub_key, uid, &RecordCommitment::from(&ro));
    //     self.insert_with_nullifier(ro, uid, nullifier)
    // }

    // fn remove_by_nullifier(&mut self, nullifier: Nullifier) -> Option<RecordInfo> {
    //     self.nullifier_records.remove(&nullifier).map(|uid| {
    //         let record = self.record_info.remove(&uid).unwrap();

    //         // Remove the record from `asset_records`, and if the sub-collection it was in becomes
    //         // empty, remove the whole collection.
    //         let asset_key = &(
    //             record.ro.asset_def.code,
    //             record.ro.pub_key.clone(),
    //             record.ro.freeze_flag,
    //         );
    //         let asset_records = self.asset_records.get_mut(asset_key).unwrap();
    //         asset_records.remove(&(record.ro.amount, uid));
    //         if asset_records.is_empty() {
    //             self.asset_records.remove(asset_key);
    //         }

    //         record
    //     })
    // }
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

// #[ser_test(arbitrary, ark(false))]
// #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct PendingTransaction {
    receiver_memos: Vec<ReceiverMemo>,
    signature: Signature,
    freeze_outputs: Vec<RecordOpening>,
    timeout: u64,
    uid: TransactionUID,
    hash: ElaboratedTransactionHash,
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

    async fn get_nullifier_proof(
        &mut self,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), XfrError> {
        if let Some(ret) = self.nullifiers.contains(nullifier) {
            Ok(ret)
        } else {
            let (contains, proof) = self.nullifiers.contains(nullifier).unwrap();

            self.nullifiers.remember(nullifier, proof.clone()).unwrap();
            Ok((contains, proof))
        }
    }

    async fn prove_nullifier_unspent(
        &mut self,
        nullifier: Nullifier,
    ) -> Result<SetMerkleProof, XfrError> {
        let (spent, proof) = self.get_nullifier_proof(nullifier).await?;
        if spent {
            Err(XfrError::NullifierAlreadyPublished { nullifier })
        } else {
            Ok(proof)
        }
    }

    async fn generate_elaborated_transaction(
        &mut self,
        note: TransactionNote,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
    ) -> Result<ElaboratedTransaction, XfrError> {
        let mut nullifier_pfs = Vec::new();
        for n in note.nullifiers() {
            let proof = if let Some((contains, proof)) = self.nullifiers.contains(n) {
                if contains {
                    return Err(XfrError::NullifierAlreadyPublished { nullifier: n });
                } else {
                    proof
                }
            } else {
                let proof = self.prove_nullifier_unspent(n).await?;
                self.nullifiers.remember(n, proof.clone()).unwrap();
                proof
            };
            nullifier_pfs.push(proof);
        }

        Ok(ElaboratedTransaction {
            txn: note,
            proofs: nullifier_pfs,
        })
    }

    async fn generate_transfer(
        &mut self,
        receiver: UserPubKey,
        fee_rec: Option<(u64, RecordOpening)>,
        fee: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature, ElaboratedTransaction), XfrError> {
        let (ro, uid) = self.find_record()?;

        let mut outputs = vec![];
        let output = RecordOpening::new(
            &mut self.prng,
            ro.amount / 2,
            ro.asset_def,
            receiver,
            FreezeFlag::Unfrozen,
        );
        outputs.push(output);

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
        let (note, sig_key) = TransferNote::generate_non_native(
            &mut self.prng,
            vec![input],
            &outputs,
            fee_info,
            UNEXPIRED_VALID_UNTIL,
            self.prover_keys.xfr.key_for_size(3, 3).unwrap(),
        )
        .unwrap();

        let recv_memos = vec![&fee_out_rec]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.prng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        match self
            .generate_elaborated_transaction(
                TransactionNote::Transfer(Box::new(note)),
                recv_memos,
                sig,
                vec![],
            )
            .await
        {
            Ok(elaborated_txn) => Ok((recv_memos, sig, elaborated_txn)),
            Err(e) => Err(e),
        }
    }

    async fn decrypt_memos(
        &mut self,
        memo: ReceiverMemo,
        proof: Signature,
    ) -> Result<(), XfrError> {
        let comm = RecordCommitment::from_field_element(
            self.record_merkle_tree
                .get_leaf(fee_ix as u64)
                .expect_ok()
                .unwrap()
                .1
                .leaf
                .0,
        );
        if let Ok(record_opening) = memo.decrypt(&self.user_keys, &comm, &[]) {
            if !record_opening.is_dummy() {
                // If this record is for us (i.e. its corresponding memo decrypts under
                // our key) and not a dummy, then add it to our owned records.
                self.records.insert(record_opening, uid, &self.user_keys);
                if self
                    .record_merkle_tree
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
    }
}
