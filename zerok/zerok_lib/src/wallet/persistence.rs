use crate::key_set::OrderByOutputs;
use crate::set_merkle_tree::SetMerkleTree;
use crate::wallet::*;
use crate::{ProverKeySet, ValidatorState};
use async_std::sync::{Arc, Mutex};
use atomic_store::{
    load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader, RollingLog,
};
use jf_txn::keys::{AuditorKeyPair, FreezerKeyPair, UserKeyPair};
use jf_txn::structs::AssetDefinition;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// Serialization intermediate for the static part of a WalletState.
#[derive(Deserialize, Serialize)]
struct WalletStaticState<'a> {
    proving_keys: Arc<ProverKeySet<'a, OrderByOutputs>>,
    auditor_key_pair: AuditorKeyPair,
    freezer_key_pair: FreezerKeyPair,
}

impl<'a> From<&WalletState<'a>> for WalletStaticState<'a> {
    fn from(w: &WalletState<'a>) -> Self {
        Self {
            proving_keys: w.proving_keys.clone(),
            auditor_key_pair: w.auditor_key_pair.clone(),
            freezer_key_pair: w.freezer_key_pair.clone(),
        }
    }
}

// Serialization intermediate for the dynamic part of a WalletState.
#[derive(Deserialize, Serialize)]
struct WalletSnapshot {
    now: u64,
    validator: ValidatorState,
    records: Vec<(Nullifier, RecordInfo)>,
    nullifiers: SetMerkleTree,
    transactions_awaiting_memos: HashMap<TransactionUID, TransactionAwaitingMemos>,
    pending_txns: Vec<(
        TransactionUID,
        ElaboratedTransactionHash,
        PendingTransaction,
    )>,
}

impl<'a> From<&WalletState<'a>> for WalletSnapshot {
    fn from(w: &WalletState<'a>) -> Self {
        Self {
            now: w.now,
            validator: w.validator.clone(),
            records: w.records.iter().map(|(n, r)| (n, r.clone())).collect(),
            nullifiers: w.nullifiers.clone(),
            pending_txns: w
                .transactions
                .iter()
                .map(|(hash, uid)| (uid.clone(), hash.clone(), w.pending_txns[uid].clone()))
                .collect(),
            transactions_awaiting_memos: w.transactions_awaiting_memos.clone(),
        }
    }
}

type AppendLogHandle<T> = Arc<Mutex<AppendLog<BincodeLoadStore<T>>>>;
type RollingLogHandle<T> = Arc<Mutex<RollingLog<BincodeLoadStore<T>>>>;

pub struct AtomicWalletStorage {
    static_path: PathBuf,
    store: AtomicStore,
    dynamic_state: RollingLogHandle<WalletSnapshot>,
    dynamic_state_dirty: bool,
    auditable_assets: AppendLogHandle<AssetDefinition>,
    auditable_assets_dirty: bool,
    defined_assets: AppendLogHandle<(AssetDefinition, AssetCodeSeed, Vec<u8>)>,
    defined_assets_dirty: bool,
}

impl AtomicWalletStorage {
    pub fn new(directory: &Path) -> Result<Self, WalletError> {
        let mut loader = AtomicStoreLoader::load(directory, "wallet").context(PersistenceError)?;
        let dynamic_state = Arc::new(Mutex::new(
            RollingLog::load(&mut loader, Default::default(), "wallet_dyn", 1024)
                .context(PersistenceError)?,
        ));
        let auditable_assets = Arc::new(Mutex::new(
            AppendLog::load(&mut loader, Default::default(), "wallet_aud", 1024)
                .context(PersistenceError)?,
        ));
        let defined_assets = Arc::new(Mutex::new(
            AppendLog::load(&mut loader, Default::default(), "wallet_def", 1024)
                .context(PersistenceError)?,
        ));
        let store = AtomicStore::open(loader).context(PersistenceError)?;
        let mut static_path = PathBuf::from(directory);
        static_path.push("wallet_static");
        Ok(Self {
            static_path,
            store,
            dynamic_state,
            dynamic_state_dirty: false,
            auditable_assets,
            auditable_assets_dirty: false,
            defined_assets,
            defined_assets_dirty: false,
        })
    }

    pub async fn create(
        &mut self,
        key: &UserKeyPair,
        w: &WalletState<'_>,
    ) -> Result<(), WalletError> {
        let static_bytes = bincode::serialize(&WalletStaticState::from(w)).context(BincodeError)?;
        let mut static_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.static_path)
            .context(IoError)?;
        static_file.write_all(&static_bytes).context(IoError)?;
        self.store_snapshot(key, w).await?;
        self.commit(key).await;
        Ok(())
    }
}

#[async_trait]
impl<'a> WalletStorage<'a> for AtomicWalletStorage {
    fn exists(&self, _key: &UserKeyPair) -> bool {
        self.static_path.exists()
    }

    async fn load(&mut self, _key: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
        let mut static_file = File::open(&self.static_path).context(IoError)?;
        let mut static_bytes = Vec::new();
        static_file
            .read_to_end(&mut static_bytes)
            .context(IoError)?;
        let WalletStaticState {
            proving_keys,
            auditor_key_pair,
            freezer_key_pair,
        } = bincode::deserialize(&static_bytes).context(BincodeError)?;

        let dynamic_state = self
            .dynamic_state
            .lock()
            .await
            .load_latest()
            .context(PersistenceError)?;

        Ok(WalletState {
            // Static state
            proving_keys,
            auditor_key_pair,
            freezer_key_pair,

            // Dynamic state
            validator: dynamic_state.validator,
            now: dynamic_state.now,
            records: dynamic_state.records.into_iter().collect(),
            nullifiers: dynamic_state.nullifiers,
            expiring_txns: {
                // Expiring transactions are not stored, because we can reconstruct them from
                // `pending_txns` like so:
                let mut txns = BTreeMap::new();
                for (uid, _hash, txn) in &dynamic_state.pending_txns {
                    txns.entry(txn.timeout)
                        .or_insert_with(HashSet::default)
                        .insert(uid.clone());
                }
                txns
            },
            pending_txns: dynamic_state
                .pending_txns
                .iter()
                .map(|(uid, _hash, txn)| (uid.clone(), txn.clone()))
                .collect(),
            transactions: dynamic_state
                .pending_txns
                .into_iter()
                .map(|(uid, hash, _txn)| (hash, uid))
                .collect(),
            uids_awaiting_memos: {
                let mut uids = HashMap::new();
                for (txn_uid, txn) in &dynamic_state.transactions_awaiting_memos {
                    for uid in &txn.pending_uids {
                        uids.insert(*uid, txn_uid.clone());
                    }
                }
                uids
            },
            transactions_awaiting_memos: dynamic_state.transactions_awaiting_memos,

            // Monotonic state
            auditable_assets: self
                .auditable_assets
                .lock()
                .await
                .iter()
                .filter_map(|res| res.map(|def| (def.code, def)).ok())
                .collect(),
            defined_assets: self
                .defined_assets
                .lock()
                .await
                .iter()
                .filter_map(|res| {
                    res.map(|(def, seed, desc)| (def.code, (def, seed, desc)))
                        .ok()
                })
                .collect(),
        })
    }

    async fn store_snapshot(
        &mut self,
        _key: &UserKeyPair,
        w: &WalletState<'a>,
    ) -> Result<(), WalletError> {
        let mut dynamic_state = self.dynamic_state.lock().await;
        dynamic_state
            .store_resource(&WalletSnapshot::from(w))
            .context(PersistenceError)?;
        self.dynamic_state_dirty = true;
        Ok(())
    }

    async fn store_auditable_asset(
        &mut self,
        _key: &UserKeyPair,
        asset: &AssetDefinition,
    ) -> Result<(), WalletError> {
        let mut auditable_assets = self.auditable_assets.lock().await;
        auditable_assets
            .store_resource(asset)
            .context(PersistenceError)?;
        self.auditable_assets_dirty = true;
        Ok(())
    }

    async fn store_defined_asset(
        &mut self,
        _key: &UserKeyPair,
        asset: &AssetDefinition,
        seed: AssetCodeSeed,
        desc: &[u8],
    ) -> Result<(), WalletError> {
        let mut defined_assets = self.defined_assets.lock().await;
        defined_assets
            .store_resource(&(asset.clone(), seed, desc.to_vec()))
            .context(PersistenceError)?;
        self.defined_assets_dirty = true;
        Ok(())
    }

    async fn commit(&mut self, _key_pair: &UserKeyPair) {
        {
            let mut dynamic_state = self.dynamic_state.lock().await;
            let mut auditable_assets = self.auditable_assets.lock().await;
            let mut defined_assets = self.defined_assets.lock().await;

            if self.dynamic_state_dirty {
                dynamic_state.commit_version().unwrap();
            } else {
                dynamic_state.skip_version().unwrap();
            }

            if self.auditable_assets_dirty {
                auditable_assets.commit_version().unwrap();
            } else {
                auditable_assets.skip_version().unwrap();
            }

            if self.defined_assets_dirty {
                defined_assets.commit_version().unwrap();
            } else {
                defined_assets.skip_version().unwrap();
            }
        }

        self.store.commit_version().unwrap();

        self.dynamic_state_dirty = false;
        self.auditable_assets_dirty = false;
        self.defined_assets_dirty = false;
    }

    async fn revert(&mut self, _key_pair: &UserKeyPair) {
        self.dynamic_state.lock().await.revert_version().unwrap();
        self.auditable_assets.lock().await.revert_version().unwrap();
        self.defined_assets.lock().await.revert_version().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VerifierKeySet, MERKLE_HEIGHT, UNIVERSAL_PARAM};
    use jf_txn::{KeyPair, TransactionVerifyingKey};
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };
    use std::iter::{once, repeat_with};
    use tempdir::TempDir;
    use test_helpers::*;

    fn random_ro(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> RecordOpening {
        let amount = rng.next_u64();
        RecordOpening::new(
            rng,
            amount,
            AssetDefinition::native(),
            key_pair.pub_key(),
            FreezeFlag::Unfrozen,
        )
    }

    fn random_ros(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> Vec<RecordOpening> {
        repeat_with(|| random_ro(rng, key_pair)).take(3).collect()
    }

    fn random_memos(rng: &mut ChaChaRng, key_pair: &UserKeyPair) -> (Vec<ReceiverMemo>, Signature) {
        let memos = repeat_with(|| {
            let ro = random_ro(rng, key_pair);
            ReceiverMemo::from_ro(rng, &ro, &[]).unwrap()
        })
        .take(3)
        .collect::<Vec<_>>();
        let sig = sign_receiver_memos(&KeyPair::generate(rng), &memos).unwrap();
        (memos, sig)
    }

    fn random_txn_hash(rng: &mut ChaChaRng) -> ElaboratedTransactionHash {
        let mut hash = [0; 64];
        rng.fill_bytes(&mut hash);
        ElaboratedTransactionHash(phaselock::BlockHash::from(hash))
    }

    async fn get_test_state(name: &str) -> (UserKeyPair, WalletState<'static>, ChaChaRng, TempDir) {
        let mut rng = ChaChaRng::from_seed([0x42u8; 32]);

        // Pick a few different sizes. It doesn't matter since all we're going to be doing is
        // serializing and deserializing, but try to choose representative data.
        let xfr_sizes = [(1, 2), (2, 3), (3, 3)];

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_txn::proof::transfer::preprocess(
                &*UNIVERSAL_PARAM,
                num_inputs,
                num_outputs,
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
        let record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
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

        let key_pair = UserKeyPair::generate(&mut rng);
        let state = WalletState {
            proving_keys: Arc::new(ProverKeySet {
                xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
                mint: mint_prove_key,
            }),
            auditor_key_pair: AuditorKeyPair::generate(&mut rng),
            freezer_key_pair: FreezerKeyPair::generate(&mut rng),
            validator,
            now: 0,

            records: Default::default(),
            auditable_assets: Default::default(),
            nullifiers: Default::default(),
            defined_assets: Default::default(),
            pending_txns: Default::default(),
            expiring_txns: Default::default(),
            transactions: Default::default(),
            transactions_awaiting_memos: Default::default(),
            uids_awaiting_memos: Default::default(),
        };

        let dir = TempDir::new(name).unwrap();
        {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.create(&key_pair, &state).await.unwrap();
        }

        (key_pair, state, rng, dir)
    }

    #[async_std::test]
    async fn test_round_trip() -> std::io::Result<()> {
        let (key_pair, mut stored, mut rng, dir) = get_test_state("test_round_trip").await;

        // Create a new storage instance to load the wallet back from disk, to ensure that what we
        // load comes only from persistent storage and not from any in-memory state of the first
        // instance.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Modify some dynamic state and load the wallet again.
        let ro = random_ro(&mut rng, &key_pair);
        let comm = RecordCommitment::from(&ro);
        stored
            .validator
            .record_merkle_frontier
            .push(comm.to_field_element());
        stored
            .validator
            .past_record_merkle_roots
            .push_back(stored.validator.record_merkle_root);
        stored.validator.record_merkle_root =
            stored.validator.record_merkle_frontier.get_root_value();
        let mut nullifiers = SetMerkleTree::default();
        nullifiers.insert(Nullifier::random_for_test(&mut rng));
        stored.validator.nullifiers_root = nullifiers.hash();
        stored.nullifiers = nullifiers;
        stored.now += 1;
        stored.records.insert(
            ro,
            stored.validator.record_merkle_frontier.num_leaves(),
            &key_pair,
        );
        let (receiver_memos, signature) = random_memos(&mut rng, &key_pair);
        let txn = PendingTransaction {
            receiver_memos,
            signature,
            freeze_outputs: random_ros(&mut rng, &key_pair),
            timeout: 5000,
        };
        let txn_uid = random_txn_hash(&mut rng);
        let txn_hash = random_txn_hash(&mut rng);
        stored.pending_txns.insert(txn_uid.clone(), txn);
        stored
            .expiring_txns
            .insert(5000, once(txn_uid.clone()).collect());
        stored.transactions.insert(txn_hash, txn_uid.clone());
        stored.transactions_awaiting_memos.insert(
            txn_uid.clone(),
            TransactionAwaitingMemos {
                pending_uids: vec![1, 2, 3].into_iter().collect(),
            },
        );
        stored.uids_awaiting_memos.insert(1, txn_uid.clone());
        stored.uids_awaiting_memos.insert(2, txn_uid.clone());
        stored.uids_awaiting_memos.insert(3, txn_uid.clone());

        // Snapshot the modified dynamic state and then reload.
        {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.store_snapshot(&key_pair, &stored).await.unwrap();
            storage.commit(&key_pair).await;
        }
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Append to monotonic state and then reload.
        let asset =
            AssetDefinition::new(AssetCode::random(&mut rng).0, Default::default()).unwrap();
        stored.auditable_assets.insert(asset.code, asset.clone());
        {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage
                .store_auditable_asset(&key_pair, &asset)
                .await
                .unwrap();
            storage.commit(&key_pair).await;
        }
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        let (code, seed) = AssetCode::random(&mut rng);
        let asset = AssetDefinition::new(code, Default::default()).unwrap();
        stored
            .defined_assets
            .insert(asset.code, (asset.clone(), seed, vec![]));
        {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage
                .store_defined_asset(&key_pair, &asset, seed, &[])
                .await
                .unwrap();
            storage.commit(&key_pair).await;
        }
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        Ok(())
    }

    #[async_std::test]
    async fn test_revert() -> std::io::Result<()> {
        let (key_pair, mut stored, mut rng, dir) = get_test_state("test_revert").await;

        // Make a change to one of the data structures, but revert it.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();
            storage
                .store_auditable_asset(&key_pair, &AssetDefinition::native())
                .await
                .unwrap();
            storage.revert(&key_pair).await;
            // Make sure committing after a revert does not commit the reverted changes.
            storage.commit(&key_pair).await;
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        // Change multiple data structures and revert.
        let loaded = {
            let mut storage = AtomicWalletStorage::new(dir.path()).unwrap();

            let (code, seed) = AssetCode::random(&mut rng);
            let asset = AssetDefinition::new(code, Default::default()).unwrap();
            let ro = random_ro(&mut rng, &key_pair);
            let nullifier = key_pair.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                0,
                &RecordCommitment::from(&ro),
            );

            // Store some data.
            stored.records.insert(ro, 0, &key_pair);
            storage.store_snapshot(&key_pair, &stored).await.unwrap();
            storage
                .store_auditable_asset(&key_pair, &asset)
                .await
                .unwrap();
            storage
                .store_defined_asset(&key_pair, &asset, seed, &[])
                .await
                .unwrap();
            // Revert the changes.
            stored.records.remove_by_nullifier(nullifier).unwrap();
            storage.revert(&key_pair).await;

            // Commit after revert should be a no-op.
            storage.commit(&key_pair).await;
            storage.load(&key_pair).await.unwrap()
        };
        assert_wallet_states_eq(&stored, &loaded);

        Ok(())
    }
}
