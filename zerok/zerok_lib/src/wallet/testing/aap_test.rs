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
use test_helpers::MockWalletStorage;

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

impl<'a> MockAAPNetwork<'a> {
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

    fn last_event(&self) -> Option<LedgerEvent<AAPLedger>> {
        self.events.last().cloned()
    }
}

#[derive(Clone)]
pub struct MockAAPBackend<'a> {
    key_pair: UserKeyPair,
    ledger: Arc<Mutex<MockLedger<'a, AAPLedger, MockAAPNetwork<'a>, MockWalletStorage<'a>>>>,
    initial_grants: Vec<(RecordOpening, u64)>,
    seed: [u8; 32],
    storage: Arc<Mutex<MockWalletStorage<'a>>>,
}

#[async_trait]
impl<'a> WalletBackend<'a, AAPLedger> for MockAAPBackend<'a> {
    type EventStream = Pin<Box<dyn Stream<Item = LedgerEvent> + Send>>;
    type Storage = MockWalletStorage<'a>;

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
        storage.store_initial_state(&state);

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
            .network()
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
    type MockStorage = MockWalletStorage<'a>;

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
