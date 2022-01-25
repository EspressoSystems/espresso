use crate::{
    node,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{ElaboratedBlock, ElaboratedTransaction, ValidatorState},
    wallet::spectrum::SpectrumLedger,
};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use futures::stream::Stream;
use itertools::izip;
use jf_aap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    structs::{AssetCodeSeed, AssetDefinition, Nullifier, ReceiverMemo, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    hd, testing,
    testing::MockEventSource,
    txn_builder::{RecordDatabase, TransactionHistoryEntry, TransactionState},
    CryptoError, RoleKeyPair, WalletBackend, WalletError, WalletState, WalletStorage,
};
use snafu::ResultExt;
use std::collections::HashMap;
use std::pin::Pin;
use testing::{MockLedger, MockNetwork};

#[derive(Clone, Debug, Default)]
pub struct MockStorage<'a> {
    committed: Option<WalletState<'a, SpectrumLedger>>,
    working: Option<WalletState<'a, SpectrumLedger>>,
    txn_history: Vec<TransactionHistoryEntry<SpectrumLedger>>,
}

#[async_trait]
impl<'a> WalletStorage<'a, SpectrumLedger> for MockStorage<'a> {
    fn exists(&self) -> bool {
        self.committed.is_some()
    }

    async fn load(
        &mut self,
    ) -> Result<WalletState<'a, SpectrumLedger>, WalletError<SpectrumLedger>> {
        Ok(self.committed.as_ref().unwrap().clone())
    }

    async fn store_snapshot(
        &mut self,
        state: &WalletState<'a, SpectrumLedger>,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        if let Some(working) = &mut self.working {
            working.txn_state = state.txn_state.clone();
            working.key_scans = state.key_scans.clone();
            working.key_state = state.key_state.clone();
        }
        Ok(())
    }

    async fn store_auditable_asset(
        &mut self,
        asset: &AssetDefinition,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        if let Some(working) = &mut self.working {
            working.auditable_assets.insert(asset.code, asset.clone());
        }
        Ok(())
    }

    async fn store_key(&mut self, key: &RoleKeyPair) -> Result<(), WalletError<SpectrumLedger>> {
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
    ) -> Result<(), WalletError<SpectrumLedger>> {
        if let Some(working) = &mut self.working {
            working
                .defined_assets
                .insert(asset.code, (asset.clone(), seed, desc.to_vec()));
        }
        Ok(())
    }

    async fn store_transaction(
        &mut self,
        txn: TransactionHistoryEntry<SpectrumLedger>,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        self.txn_history.push(txn);
        Ok(())
    }

    async fn transaction_history(
        &mut self,
    ) -> Result<Vec<TransactionHistoryEntry<SpectrumLedger>>, WalletError<SpectrumLedger>> {
        Ok(self.txn_history.clone())
    }

    async fn commit(&mut self) {
        self.committed = self.working.clone();
    }

    async fn revert(&mut self) {
        self.working = self.committed.clone();
    }
}

pub struct MockSpectrumNetwork<'a> {
    validator: ValidatorState,
    nullifiers: SetMerkleTree,
    records: MerkleTree,
    committed_blocks: Vec<(ElaboratedBlock, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    address_map: HashMap<UserAddress, UserPubKey>,
    events: MockEventSource<SpectrumLedger>,
}

impl<'a> MockNetwork<'a, SpectrumLedger> for MockSpectrumNetwork<'a> {
    fn now(&self) -> EventIndex {
        self.events.now()
    }

    fn submit(&mut self, block: ElaboratedBlock) -> Result<(), WalletError<SpectrumLedger>> {
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
    ) -> Result<(), WalletError<SpectrumLedger>> {
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
        self.generate_event(LedgerEvent::<SpectrumLedger>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id)),
        });

        Ok(())
    }

    fn memos_source(&self) -> EventSource {
        EventSource::QueryService
    }

    fn generate_event(&mut self, e: LedgerEvent<SpectrumLedger>) {
        println!(
            "generating event {}: {}",
            self.now(),
            match &e {
                LedgerEvent::Commit { .. } => "Commit",
                LedgerEvent::Reject { .. } => "Reject",
                LedgerEvent::Memos { .. } => "Memos",
            }
        );
        self.events.publish(e);
    }
}

#[derive(Clone)]
pub struct MockSpectrumBackend<'a> {
    key_pair: UserKeyPair,
    ledger: Arc<Mutex<MockLedger<'a, SpectrumLedger, MockSpectrumNetwork<'a>, MockStorage<'a>>>>,
    initial_grants: Vec<(RecordOpening, u64)>,
    seed: [u8; 32],
    storage: Arc<Mutex<MockStorage<'a>>>,
}

#[async_trait]
impl<'a> WalletBackend<'a, SpectrumLedger> for MockSpectrumBackend<'a> {
    type EventStream =
        Pin<Box<dyn Stream<Item = (LedgerEvent<SpectrumLedger>, EventSource)> + Send>>;
    type Storage = MockStorage<'a>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(
        &mut self,
    ) -> Result<WalletState<'a, SpectrumLedger>, WalletError<SpectrumLedger>> {
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

                    now: Default::default(),
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

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;
        ledger.network().events.subscribe(from, to)
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, WalletError<SpectrumLedger>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(WalletError::<SpectrumLedger>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError<SpectrumLedger>> {
        let mut ledger = self.ledger.lock().await;
        if set.hash() == ledger.network().nullifiers.hash() {
            Ok(ledger.network().nullifiers.contains(nullifier).unwrap())
        } else {
            Err(node::QueryServiceError::InvalidNullifierRoot {}.into())
        }
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<ElaboratedTransaction, WalletError<SpectrumLedger>> {
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
        let block = &network
            .committed_blocks
            .get(block_id as usize)
            .ok_or_else(|| {
                WalletError::<SpectrumLedger>::from(node::QueryServiceError::InvalidBlockId {
                    index: block_id as usize,
                    num_blocks: network.committed_blocks.len(),
                })
            })?
            .0;

        if txn_id as usize >= block.block.0.len() {
            return Err(node::QueryServiceError::InvalidTxnId {}.into());
        }
        let txn = block.block.0[txn_id as usize].clone();
        let proofs = block.proofs[txn_id as usize].clone();
        Ok(ElaboratedTransaction { txn, proofs })
    }

    async fn register_user_key(
        &mut self,
        pub_key: &UserPubKey,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        let mut ledger = self.ledger.lock().await;
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
    }

    async fn submit(
        &mut self,
        txn: ElaboratedTransaction,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        self.ledger.lock().await.submit(txn)
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        self.ledger
            .lock()
            .await
            .post_memos(block_id, txn_id, memos, sig)
    }
}

#[derive(Default)]
pub struct SpectrumTest;

#[async_trait]
impl<'a> testing::SystemUnderTest<'a> for SpectrumTest {
    type Ledger = SpectrumLedger;
    type MockBackend = MockSpectrumBackend<'a>;
    type MockNetwork = MockSpectrumNetwork<'a>;
    type MockStorage = MockStorage<'a>;

    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        _initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        MockSpectrumNetwork {
            validator: ValidatorState::new(verif_crs, records.clone()),
            records,
            nullifiers: SetMerkleTree::default(),
            committed_blocks: Vec::new(),
            proving_keys: Arc::new(proof_crs),
            address_map: HashMap::default(),
            events: MockEventSource::new(EventSource::QueryService),
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
        MockSpectrumBackend {
            ledger,
            initial_grants,
            seed,
            storage,
            key_pair,
        }
    }

    fn universal_param(&self) -> &'a jf_aap::proof::UniversalParam {
        &*crate::universal_params::UNIVERSAL_PARAM
    }
}

// Spectrum-specific tests
#[cfg(test)]
mod spectrum_wallet_tests {
    use super::*;
    use jf_aap::structs::AssetCode;
    use std::time::Instant;
    use testing::SystemUnderTest;

    use testing::generic_wallet_tests;
    seahorse::instantiate_generic_wallet_tests!(SpectrumTest);

    #[async_std::test]
    async fn test_resubmit() -> std::io::Result<()> {
        let mut t = SpectrumTest::default();
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
        t.sync_with(
            &wallets,
            ledger_time.add_from_source(EventSource::QueryService, 1),
        )
        .await;
        // Wait for the Commit and Memos events after the wallet resubmits.
        ledger.lock().await.flush().unwrap();
        t.sync_with(
            &wallets,
            ledger_time.add_from_source(EventSource::QueryService, 3),
        )
        .await;
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
