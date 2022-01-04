#![cfg(test)]
#![allow(dead_code)]
use super::*;
use crate::{
    set_merkle_tree::SetMerkleTree,
    state::{
        key_set::{KeySet, OrderByOutputs},
        ProverKeySet, VerifierKeySet, MERKLE_HEIGHT,
    },
    universal_params::UNIVERSAL_PARAM,
};
use async_std::sync::{Arc, Mutex};
use jf_aap::{MerkleTree, TransactionVerifyingKey};
use rand_chacha::rand_core::RngCore;
use std::time::Instant;

#[async_trait]
pub trait MockNetwork<'a, L: Ledger> {
    fn now(&self) -> u64;
    fn submit(&mut self, block: Block<L>) -> Result<(), WalletError>;
    fn generate_event(&mut self, event: LedgerEvent<L>);
    fn last_event(&self) -> Option<LedgerEvent<L>>;
}

pub struct MockLedger<'a, L: Ledger, N: MockNetwork<'a, L>, S: WalletStorage<'a, L>> {
    network: N,
    current_block: Block<L>,
    block_size: usize,
    hold_next_transaction: bool,
    held_transaction: Option<Transaction<L>>,
    mangled: bool,
    storage: Vec<Arc<Mutex<S>>>,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, L: Ledger, N: MockNetwork<'a, L>, S: WalletStorage<'a, L>> MockLedger<'a, L, N, S> {
    pub fn new(network: N) -> Self {
        Self {
            network,
            current_block: Block::<L>::new(vec![]),
            block_size: 2,
            hold_next_transaction: false,
            held_transaction: None,
            mangled: false,
            storage: Default::default(),
            _phantom: Default::default(),
        }
    }

    pub fn network(&mut self) -> &mut N {
        &mut self.network
    }

    pub fn now(&self) -> u64 {
        self.network.now()
    }

    pub fn flush(&mut self) -> Result<(), WalletError> {
        if self.current_block.is_empty() {
            return Ok(());
        }

        let block = std::mem::replace(&mut self.current_block, Block::<L>::new(vec![]));
        self.network.submit(block)
    }

    pub fn hold_next_transaction(&mut self) {
        self.hold_next_transaction = true;
    }

    pub fn release_held_transaction(&mut self) -> Option<Transaction<L>> {
        if let Some(txn) = self.held_transaction.take() {
            self.submit(txn.clone()).unwrap();
            Some(txn)
        } else {
            None
        }
    }

    pub fn mangle(&mut self) {
        self.mangled = true;
    }

    pub fn unmangle(&mut self) {
        self.mangled = false;
    }

    pub fn submit(&mut self, txn: Transaction<L>) -> Result<(), WalletError> {
        if self.hold_next_transaction {
            self.held_transaction = Some(txn);
            self.hold_next_transaction = false;
        } else if self.mangled {
            let rejected = Block::<L>::new(vec![txn]);
            self.network.generate_event(LedgerEvent::<L>::Reject {
                block: rejected,
                error: ValidationError::Failed {},
            });
        } else {
            match self.current_block.add_transaction(txn.clone()) {
                Ok(()) => {
                    if self.current_block.len() >= self.block_size {
                        self.flush()?;
                    }
                }
                Err(error) => {
                    let rejected = Block::<L>::new(vec![txn]);
                    self.network.generate_event(LedgerEvent::<L>::Reject {
                        block: rejected,
                        error,
                    });
                }
            }
        }

        Ok(())
    }

    pub fn set_block_size(&mut self, size: usize) -> Result<(), WalletError> {
        self.block_size = size;
        if self.current_block.len() >= self.block_size {
            self.flush()?;
        }
        Ok(())
    }
}

// This function checks probabilistic equality for two wallet states, comparing hashes for fields
// that cannot directly be compared for equality. It is sufficient for tests that want to compare
// wallet states (like round-trip serialization tests) but since it is deterministic, we shouldn't
// make it into a PartialEq instance.
pub fn assert_wallet_states_eq<'a, L: Ledger>(w1: &WalletState<'a, L>, w2: &WalletState<'a, L>) {
    assert_eq!(w1.txn_state.now, w2.txn_state.now);
    assert_eq!(
        w1.txn_state.validator.commit(),
        w2.txn_state.validator.commit()
    );
    assert_eq!(w1.proving_keys, w2.proving_keys);
    assert_eq!(w1.txn_state.records, w2.txn_state.records);
    assert_eq!(w1.key_state, w2.key_state);
    assert_eq!(w1.auditable_assets, w2.auditable_assets);
    assert_eq!(
        w1.audit_keys.keys().collect::<Vec<_>>(),
        w2.audit_keys.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        w1.freeze_keys.keys().collect::<Vec<_>>(),
        w2.freeze_keys.keys().collect::<Vec<_>>()
    );
    assert_eq!(w1.txn_state.nullifiers, w2.txn_state.nullifiers);
    assert_eq!(
        w1.txn_state.record_mt.commitment(),
        w2.txn_state.record_mt.commitment()
    );
    assert_eq!(w1.defined_assets, w2.defined_assets);
    assert_eq!(w1.txn_state.transactions, w2.txn_state.transactions);
    assert_eq!(w1.key_scans, w2.key_scans);
}

#[async_trait]
pub trait SystemUnderTest<'a>: Default + Send + Sync {
    type Ledger: 'static + Ledger;
    type MockBackend: 'a + WalletBackend<'a, Self::Ledger> + Send + Sync;
    type MockNetwork: 'a + MockNetwork<'a, Self::Ledger> + Send;
    type MockStorage: 'a + WalletStorage<'a, Self::Ledger> + Send;

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
        seed: [u8; 32],
        storage: Arc<Mutex<Self::MockStorage>>,
        key_pair: UserKeyPair,
    ) -> Self::MockBackend;
    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork;
    async fn create_storage(&mut self) -> Self::MockStorage;

    async fn create_test_network(
        &mut self,
        xfr_sizes: &[(usize, usize)],
        initial_grants: Vec<u64>,
        now: &mut Instant,
    ) -> (
        Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        Vec<(Wallet<'a, Self::MockBackend, Self::Ledger>, UserAddress)>,
    ) {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);

        // Populate the unpruned record merkle tree with an initial record commitment for each
        // non-zero initial grant. Collect user-specific info (keys and record openings
        // corresponding to grants) in `users`, which will be used to create the wallets later.
        let mut record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        let mut users = vec![];
        let mut initial_records = vec![];
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
                users.push((key, vec![(ro.clone(), uid)]));
                initial_records.push((ro, uid));
            } else {
                users.push((key, vec![]));
            }
        }

        // Create the validator using the ledger state containing the initial grants, computed
        // above.
        println!(
            "Generating validator keys: {}s",
            now.elapsed().as_secs_f32()
        );
        *now = Instant::now();

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_aap::proof::transfer::preprocess(
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
            jf_aap::proof::mint::preprocess(&*UNIVERSAL_PARAM, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_aap::proof::freeze::preprocess(&*UNIVERSAL_PARAM, 2, MERKLE_HEIGHT).unwrap();
        let ledger = Arc::new(Mutex::new(MockLedger::new(
            self.create_network(
                VerifierKeySet {
                    xfr: KeySet::new(xfr_verif_keys.into_iter()).unwrap(),
                    mint: TransactionVerifyingKey::Mint(mint_verif_key),
                    freeze: KeySet::new(
                        vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
                    )
                    .unwrap(),
                },
                ProverKeySet {
                    xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                    mint: mint_prove_key,
                    freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
                },
                record_merkle_tree.clone(),
                initial_records,
            )
            .await,
        )));

        // Create a wallet for each user based on the validator and the per-user information
        // computed above.
        let mut wallets = Vec::new();
        for (key_pair, initial_grants) in users {
            let mut rng = ChaChaRng::from_rng(&mut rng).unwrap();
            let ledger = ledger.clone();
            let storage = Arc::new(Mutex::new(self.create_storage().await));
            ledger.lock().await.storage.push(storage.clone());

            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let mut wallet = Wallet::new(
                self.create_backend(ledger, initial_grants, seed, storage, key_pair.clone())
                    .await,
            )
            .await
            .unwrap();
            wallet.add_user_key(key_pair.clone(), 0).await.unwrap();
            wallets.push((wallet, key_pair.address()));
        }

        println!("Wallets set up: {}s", now.elapsed().as_secs_f32());
        *now = Instant::now();
        (ledger, wallets)
    }

    async fn sync(
        &self,
        ledger: &Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        wallets: &[(Wallet<'a, Self::MockBackend, Self::Ledger>, UserAddress)],
    ) {
        let t = {
            let mut ledger = ledger.lock().await;
            ledger.flush().unwrap();
            if let Some(LedgerEvent::Commit { block, .. }) = ledger.network().last_event() {
                // If the last event is a Commit, wait until all of the senders from the block
                // receive the Commit event and post the receiver memos, generating new Memos events.
                ledger.now() + (block.len() as u64)
            } else {
                ledger.now()
            }
        };
        self.sync_with(wallets, t).await;

        // Since we're syncing with the time stamp from the most recent event, the wallets should
        // be in a stable state once they have processed up to that event. Check that each wallet
        // has persisted all of its in-memory state at this point.
        let ledger = ledger.lock().await;
        for ((wallet, _), storage) in wallets.iter().zip(&ledger.storage) {
            let WalletSharedState { state, .. } = &*wallet.mutex.lock().await;
            assert_wallet_states_eq(state, &storage.lock().await.load().await.unwrap());
        }
    }

    async fn sync_with(
        &self,
        wallets: &[(Wallet<'a, Self::MockBackend, Self::Ledger>, UserAddress)],
        t: u64,
    ) {
        println!("waiting for sync point {}", t);
        future::join_all(wallets.iter().map(|(wallet, _)| wallet.sync(t))).await;
    }
}

mod aap_test;
mod cape_test;
mod tests;
