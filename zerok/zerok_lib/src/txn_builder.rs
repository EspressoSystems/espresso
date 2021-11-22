use crate::node::LedgerEvent;
use crate::set_merkle_tree::*;
use crate::{ElaboratedTransaction, ProverKeySet, ValidatorState};
use jf_txn::{
    errors::TxnApiError,
    keys::{AuditorKeyPair, FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, FeeInput, FreezeFlag, Nullifier, ReceiverMemo,
        RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness, MerkleLeafProof, MerkleTree, Signature, TransactionNote,
};
use phaselock::EventType;
use rand_chacha::ChaChaRng;
use std::collections::{BTreeSet, HashMap};
use zerok_lib::ElaboratedBlock;
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
    NetworkError {
        source: phaselock::networking::NetworkError,
    },
    QueryServiceError {
        source: crate::node::QueryServiceError,
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
    KeyError {
        source: argon2::Error,
    },
}

#[derive(Clone, Debug)]
pub struct RecordInfo {
    ro: RecordOpening,
    uid: u64,
    nullifier: Nullifier,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    hold_until: Option<u64>,
}

#[derive(Clone, Debug)]
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

    // maps defined asset code to asset definition, seed and description of the asset
    pub defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
}

impl<'a> XfrState<'a> {
    fn find_records(&self, num_records: usize) -> Result<Vec<(RecordOpening, u64)>, XfrError> {
        let mut records = Vec::new();

        for record in self.records.record_info.clone() {
            if records.len() == num_records {
                return Ok(records);
            }
            if record.1.ro.amount > 0 {
                records.push((record.1.ro, record.1.uid));
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

    pub async fn generate_transfer(
        &mut self,
        receiver: UserPubKey,
        fee: u64,
    ) -> Result<(Vec<ReceiverMemo>, Signature, ElaboratedTransaction), XfrError> {
        // Prepare inputs
        let input_records = self.find_records(2)?;
        let (ro, uid) = input_records[0].clone();
        let input = TransferNoteInput {
            ro: ro.clone(),
            acc_member_witness: AccMemberWitness::lookup_from_tree(&self.record_merkle_tree, uid)
                .expect_ok()
                .unwrap()
                .1,
            owner_keypair: &self.user_keys,
            cred: None,
        };

        let (fee_ro, fee_uid) = input_records[1].clone();
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

        // Prepere outputs
        let output = RecordOpening::new(
            &mut self.prng,
            ro.amount / 2,
            ro.asset_def,
            receiver,
            FreezeFlag::Unfrozen,
        );
        let outputs = vec![output];
        let (fee_info, fee_out) = TxnFeeInfo::new(&mut self.prng, fee_input, fee).unwrap();

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

        let recv_memos = vec![&fee_out]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.prng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        match self
            .generate_elaborated_transaction(TransactionNote::Transfer(Box::new(note)))
            .await
        {
            Ok(elaborated_txn) => Ok((recv_memos, sig, elaborated_txn)),
            Err(e) => Err(e),
        }
    }

    pub async fn handle_memos_event(&mut self, event: LedgerEvent) {
        match event {
            LedgerEvent::Memos { outputs } => {
                for (memo, comm, uid, proof) in outputs {
                    if let Ok(record_opening) = memo.decrypt(&self.user_keys, &comm, &[]) {
                        if !record_opening.is_dummy() {
                            // If this record is for us (i.e. its corresponding memo decrypts under
                            // our key) and not a dummy, then add it to our owned records.
                            self.records.insert(record_opening, uid, &self.user_keys);
                            if self
                                .record_merkle_tree
                                .remember(
                                    uid,
                                    &MerkleLeafProof::new(comm.to_field_element(), proof),
                                )
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

            event => {
                panic!("Expected memos event. Received: {:?}", event);
            }
        }
    }
}
