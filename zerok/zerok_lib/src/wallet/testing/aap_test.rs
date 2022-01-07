use super::*;
use crate::{
    api::FromError,
    node,
    set_merkle_tree::SetMerkleProof,
    state::{ElaboratedBlock, ElaboratedTransaction, ValidatorState},
};
use futures::channel::mpsc;
use itertools::izip;
use std::pin::Pin;

#[derive(Clone, Debug, Default)]
pub struct MockStorage<'a> {
    committed: Option<WalletState<'a>>,
    working: Option<WalletState<'a>>,
    txn_history: Vec<TransactionHistoryEntry<AAPLedger>>,
}

#[async_trait]
impl<'a> WalletStorage<'a, AAPLedger> for MockStorage<'a> {
    fn exists(&self) -> bool {
        self.committed.is_some()
    }

    async fn load(&mut self) -> Result<WalletState<'a>, WalletError> {
        Ok(self.committed.as_ref().unwrap().clone())
    }

    async fn store_snapshot(&mut self, state: &WalletState<'a>) -> Result<(), WalletError> {
        if let Some(working) = &mut self.working {
            working.txn_state = state.txn_state.clone();
            working.key_scans = state.key_scans.clone();
            working.key_state = state.key_state.clone();
        }
        Ok(())
    }

    async fn store_auditable_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError> {
        if let Some(working) = &mut self.working {
            working.auditable_assets.insert(asset.code, asset.clone());
        }
        Ok(())
    }

    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError> {
        if let Some(working) = &mut self.working {
            match key {
                RoleKeyPair::Auditor(key) => {
                    working.audit_keys.insert(key.pub_key(), key.clone());
                }
                RoleKeyPair::Freezer(key) => {
                    working.freeze_keys.insert(key.pub_key(), key.clone());
                }
                RoleKeyPair::User(key) => {
                    working.user_keys.insert(key.address(), key.clone());
                }
            }
        }
        Ok(())
    }

    async fn store_defined_asset(
        &mut self,
        asset: &AssetDefinition,
        seed: AssetCodeSeed,
        desc: &[u8],
    ) -> Result<(), WalletError> {
        if let Some(working) = &mut self.working {
            working
                .defined_assets
                .insert(asset.code, (asset.clone(), seed, desc.to_vec()));
        }
        Ok(())
    }

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<AAPLedger>,
    ) -> Result<(), WalletError> {
        self.txn_history.push(txn);
        Ok(())
    }

    async fn transaction_history(
        &mut self,
    ) -> Result<Vec<TransactionHistoryEntry<AAPLedger>>, WalletError> {
        Ok(self.txn_history.clone())
    }

    async fn commit(&mut self) {
        self.committed = self.working.clone();
    }

    async fn revert(&mut self) {
        self.working = self.committed.clone();
    }
}

pub struct MockAAPNetwork<'a> {
    validator: ValidatorState,
    nullifiers: SetMerkleTree,
    records: MerkleTree,
    subscribers: Vec<mpsc::UnboundedSender<LedgerEvent>>,
    committed_blocks: Vec<(ElaboratedBlock, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    address_map: HashMap<UserAddress, UserPubKey>,
    events: Vec<LedgerEvent>,
}

impl<'a> MockNetwork<'a, AAPLedger> for MockAAPNetwork<'a> {
    fn now(&self) -> u64 {
        self.events.len() as u64
    }

    fn submit(&mut self, block: ElaboratedBlock) -> Result<(), WalletError> {
        match self.validator.validate_and_apply(
            self.validator.prev_commit_time + 1,
            block.block.clone(),
            block.proofs.clone(),
        ) {
            Ok(mut uids) => {
                // Add nullifiers
                for txn in &block.block.0 {
                    for nullifier in txn.nullifiers() {
                        self.nullifiers.insert(nullifier);
                    }
                    for record in txn.output_commitments() {
                        self.records.push(record.to_field_element())
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

        Ok(())
    }

    fn post_memos(
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
                self.records
                    .get_leaf(*uid)
                    .expect_ok()
                    .map(|(_, proof)| (proof.leaf.0, proof.path))
                    .unwrap()
                    .1
            })
            .collect::<Vec<_>>();
        self.generate_event(LedgerEvent::<AAPLedger>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id)),
        });

        Ok(())
    }

    fn generate_event(&mut self, e: LedgerEvent) {
        println!(
            "generating event {}: {}",
            self.events.len(),
            match &e {
                LedgerEvent::Commit { .. } => "Commit",
                LedgerEvent::Reject { .. } => "Reject",
                LedgerEvent::Memos { .. } => "Memos",
            }
        );
        self.events.push(e.clone());
        self.subscribers = std::mem::take(&mut self.subscribers)
            .into_iter()
            .filter_map(|mut s| {
                if s.start_send(e.clone()).is_ok() {
                    // Errors indicate that the subscriber has disconnected, so we only want to
                    // retain the subscriber if the send is successful.
                    Some(s)
                } else {
                    None
                }
            })
            .collect();
    }
}

#[derive(Clone)]
pub struct MockAAPBackend<'a> {
    key_pair: UserKeyPair,
    ledger: Arc<Mutex<MockLedger<'a, AAPLedger, MockAAPNetwork<'a>, MockStorage<'a>>>>,
    initial_grants: Vec<(RecordOpening, u64)>,
    seed: [u8; 32],
    storage: Arc<Mutex<MockStorage<'a>>>,
}

#[async_trait]
impl<'a> WalletBackend<'a, AAPLedger> for MockAAPBackend<'a> {
    type EventStream = Pin<Box<dyn Stream<Item = LedgerEvent> + Send>>;
    type Storage = MockStorage<'a>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(&mut self) -> Result<WalletState<'a>, WalletError> {
        let state = {
            let mut ledger = self.ledger.lock().await;

            WalletState {
                proving_keys: ledger.network().proving_keys.clone(),
                txn_state: TransactionState {
                    validator: ledger.network().validator.clone(),

                    records: {
                        let mut db: RecordDatabase = Default::default();
                        for (ro, uid) in self.initial_grants.iter() {
                            db.insert(ro.clone(), *uid, &self.key_pair);
                        }
                        db
                    },
                    nullifiers: ledger.network().nullifiers.clone(),
                    record_mt: ledger.network().records.clone(),
                    merkle_leaf_to_forget: None,

                    now: 0,
                    transactions: Default::default(),
                },
                key_state: Default::default(),
                key_scans: Default::default(),
                auditable_assets: Default::default(),
                audit_keys: Default::default(),
                freeze_keys: Default::default(),
                user_keys: Default::default(),
                defined_assets: HashMap::new(),
            }
        };

        // Persist the initial state.
        let mut storage = self.storage().await;
        storage.committed = Some(state.clone());
        storage.working = Some(state.clone());

        Ok(state)
    }

    fn key_stream(&self) -> hd::KeyTree {
        let mut rng = ChaChaRng::from_seed(self.seed);
        hd::KeyTree::random(&mut rng).unwrap().0
    }

    async fn subscribe(&self, starting_at: u64) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;

        assert!(
            starting_at <= ledger.now(),
            "subscribing from a future state is not supported in the MockAAPBackend"
        );
        let past_events = ledger
            .network()
            .events
            .iter()
            .skip(starting_at as usize)
            .cloned()
            .collect::<Vec<_>>();

        let (sender, receiver) = mpsc::unbounded();
        ledger.network().subscribers.push(sender);

        Box::pin(iter(past_events).chain(receiver))
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(WalletError::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError> {
        let mut ledger = self.ledger.lock().await;
        if set.hash() == ledger.network().nullifiers.hash() {
            Ok(ledger.network().nullifiers.contains(nullifier).unwrap())
        } else {
            Err(WalletError::QueryServiceError {
                source: node::QueryServiceError::InvalidNullifierRoot {},
            })
        }
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<ElaboratedTransaction, WalletError> {
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
        let block = &network
            .committed_blocks
            .get(block_id as usize)
            .ok_or_else(|| {
                WalletError::from_query_service_error(node::QueryServiceError::InvalidBlockId {
                    index: block_id as usize,
                    num_blocks: network.committed_blocks.len(),
                })
            })?
            .0;

        if txn_id as usize >= block.block.0.len() {
            return Err(WalletError::from_query_service_error(
                node::QueryServiceError::InvalidTxnId {},
            ));
        }
        let txn = block.block.0[txn_id as usize].clone();
        let proofs = block.proofs[txn_id as usize].clone();
        Ok(ElaboratedTransaction { txn, proofs })
    }

    async fn register_user_key(&mut self, pub_key: &UserPubKey) -> Result<(), WalletError> {
        let mut ledger = self.ledger.lock().await;
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
    }

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
        self.ledger.lock().await.submit(txn)
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
            .await
            .post_memos(block_id, txn_id, memos, sig)
    }
}

#[derive(Default)]
pub struct AAPTest;

#[async_trait]
impl<'a> testing::SystemUnderTest<'a> for AAPTest {
    type Ledger = AAPLedger;
    type MockBackend = MockAAPBackend<'a>;
    type MockNetwork = MockAAPNetwork<'a>;
    type MockStorage = MockStorage<'a>;

    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        _initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        MockAAPNetwork {
            validator: ValidatorState::new(verif_crs, records.clone()),
            records,
            nullifiers: SetMerkleTree::default(),
            subscribers: Vec::new(),
            committed_blocks: Vec::new(),
            proving_keys: Arc::new(proof_crs),
            address_map: HashMap::default(),
            events: Vec::new(),
        }
    }

    async fn create_storage(&mut self) -> Self::MockStorage {
        Default::default()
    }

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
        seed: [u8; 32],
        storage: Arc<Mutex<Self::MockStorage>>,
        key_pair: UserKeyPair,
    ) -> Self::MockBackend {
        MockAAPBackend {
            ledger,
            initial_grants,
            seed,
            storage,
            key_pair,
        }
    }
}

// AAP-specific tests
mod aap_wallet_tests {
    use super::*;

    #[async_std::test]
    async fn test_resubmit() -> std::io::Result<()> {
        let mut t = AAPTest::default();
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment. wallets[1] will act as the receiver, and wallets[2] will be a third party
        // which generates RECORD_ROOT_HISTORY_SIZE-1 transfers while a transfer from wallets[0] is
        // pending, after which we will check if the pending transaction can be updated and
        // resubmitted.
        let (ledger, mut wallets) = t
            .create_test_network(
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
        ledger.lock().await.hold_next_transaction();
        let sender = wallets[0].1.clone();
        let receiver = wallets[1].1.clone();
        wallets[0]
            .0
            .transfer(&sender, &AssetCode::native(), &[(receiver.clone(), 1)], 1)
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
            let sender = wallets[2].1.clone();
            wallets[2]
                .0
                .transfer(&sender, &AssetCode::native(), &[(receiver.clone(), 1)], 1)
                .await
                .unwrap();
            t.sync(&ledger, &wallets).await;
        }

        // Check that the pending transaction eventually succeeds, after being automatically
        // resubmitted by the wallet.
        println!(
            "submitting invalid transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        let ledger_time = ledger.lock().await.now();
        ledger.lock().await.release_held_transaction().unwrap();
        ledger.lock().await.flush().unwrap();
        // Wait for the Reject event.
        t.sync_with(&wallets, ledger_time + 1).await;
        // Wait for the Commit and Memos events after the wallet resubmits.
        ledger.lock().await.flush().unwrap();
        t.sync_with(&wallets, ledger_time + 3).await;
        assert_eq!(
            wallets[0]
                .0
                .balance(&wallets[0].1, &AssetCode::native())
                .await,
            0
        );
        assert_eq!(
            wallets[1]
                .0
                .balance(&wallets[1].1, &AssetCode::native())
                .await,
            1 + (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64
        );

        Ok(())
    }
}
