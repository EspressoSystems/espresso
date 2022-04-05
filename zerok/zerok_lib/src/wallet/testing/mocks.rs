pub use seahorse::testing::MockLedger;

use crate::{
    ledger::EspressoLedger,
    node,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{ElaboratedBlock, ElaboratedTransaction, ValidatorState},
};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use futures::stream::Stream;
use itertools::izip;
use jf_cap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use reef::traits::Transaction as _;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    hd, testing,
    testing::MockEventSource,
    txn_builder::{PendingTransaction, RecordDatabase, TransactionInfo, TransactionState},
    CryptoSnafu, WalletBackend, WalletError, WalletState,
};
use snafu::ResultExt;
use std::collections::HashMap;
use std::pin::Pin;
use testing::{mocks::MockStorage, MockNetwork};

pub struct MockEspressoNetwork<'a> {
    validator: ValidatorState,
    nullifiers: SetMerkleTree,
    records: MerkleTree,
    committed_blocks: Vec<(ElaboratedBlock, Vec<Vec<u64>>)>,
    proving_keys: Arc<ProverKeySet<'a, key_set::OrderByOutputs>>,
    address_map: HashMap<UserAddress, UserPubKey>,
    events: MockEventSource<EspressoLedger>,
}

impl<'a> MockNetwork<'a, EspressoLedger> for MockEspressoNetwork<'a> {
    fn now(&self) -> EventIndex {
        self.events.now()
    }

    fn event(
        &self,
        index: EventIndex,
        source: EventSource,
    ) -> Result<LedgerEvent<EspressoLedger>, WalletError<EspressoLedger>> {
        match source {
            EventSource::QueryService => self.events.get(index),
            _ => Err(WalletError::Failed {
                msg: String::from("invalid event source"),
            }),
        }
    }

    fn submit(&mut self, block: ElaboratedBlock) -> Result<(), WalletError<EspressoLedger>> {
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
    ) -> Result<(), WalletError<EspressoLedger>> {
        let (block, block_uids) = &self.committed_blocks[block_id as usize];
        let txn = &block.block.0[txn_id as usize];
        let comms = txn.output_commitments();
        let uids = block_uids[txn_id as usize].clone();
        let kind = txn.kind();

        txn.verify_receiver_memos_signature(&memos, &sig)
            .context(CryptoSnafu)?;

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
        self.generate_event(LedgerEvent::<EspressoLedger>::Memos {
            outputs: izip!(memos, comms, uids, merkle_paths).collect(),
            transaction: Some((block_id, txn_id, kind)),
        });

        Ok(())
    }

    fn memos_source(&self) -> EventSource {
        EventSource::QueryService
    }

    fn generate_event(&mut self, e: LedgerEvent<EspressoLedger>) {
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
pub struct MockEspressoBackend<'a> {
    key_stream: hd::KeyTree,
    ledger: Arc<
        Mutex<
            MockLedger<
                'a,
                EspressoLedger,
                MockEspressoNetwork<'a>,
                MockStorage<'a, EspressoLedger>,
            >,
        >,
    >,
    initial_grants: Vec<(RecordOpening, u64)>,
    storage: Arc<Mutex<MockStorage<'a, EspressoLedger>>>,
}

#[async_trait]
impl<'a> WalletBackend<'a, EspressoLedger> for MockEspressoBackend<'a> {
    type EventStream =
        Pin<Box<dyn Stream<Item = (LedgerEvent<EspressoLedger>, EventSource)> + Send>>;
    type Storage = MockStorage<'a, EspressoLedger>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(
        &mut self,
    ) -> Result<WalletState<'a, EspressoLedger>, WalletError<EspressoLedger>> {
        let state = {
            let mut ledger = self.ledger.lock().await;

            WalletState {
                proving_keys: ledger.network().proving_keys.clone(),
                txn_state: TransactionState {
                    validator: ledger.network().validator.clone(),

                    records: {
                        let mut db: RecordDatabase = Default::default();
                        for (ro, uid) in self.initial_grants.iter() {
                            let key_pair = {
                                let mut ret = None;
                                let key_stream = self.key_stream.derive_sub_tree("user".as_bytes());

                                for i in 0u64..5 {
                                    let key_pair =
                                        key_stream.derive_user_key_pair(&i.to_le_bytes());
                                    if key_pair.pub_key() == ro.pub_key {
                                        ret = Some(key_pair);
                                        break;
                                    }
                                }

                                ret.unwrap()
                            };

                            db.insert(ro.clone(), *uid, &key_pair);
                        }
                        db
                    },
                    nullifiers: ledger.network().nullifiers.clone(),
                    record_mt: ledger.network().records.clone(),
                    merkle_leaf_to_forget: None,

                    now: ledger.now(),
                    transactions: Default::default(),
                },
                key_state: Default::default(),
                assets: Default::default(),
                freezing_accounts: Default::default(),
                sending_accounts: Default::default(),
                viewing_accounts: Default::default(),
            }
        };

        // Persist the initial state.
        let mut storage = self.storage().await;
        storage.initialize(state.clone(), state.clone()).unwrap();

        Ok(state)
    }

    fn key_stream(&self) -> hd::KeyTree {
        self.key_stream.clone()
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;
        ledger.network().events.subscribe(from, to)
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, WalletError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(WalletError::<EspressoLedger>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        if set.hash() == ledger.network().nullifiers.hash() {
            Ok(ledger.network().nullifiers.contains(nullifier).unwrap())
        } else {
            Err(node::QueryServiceError::InvalidNullifierRoot {}.into())
        }
    }

    async fn register_user_key(
        &mut self,
        key_pair: &UserKeyPair,
    ) -> Result<(), WalletError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        let pub_key = key_pair.pub_key();
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
    }

    async fn submit(
        &mut self,
        txn: ElaboratedTransaction,
        _info: TransactionInfo<EspressoLedger>,
    ) -> Result<(), WalletError<EspressoLedger>> {
        self.ledger.lock().await.submit(txn)
    }

    async fn finalize(
        &mut self,
        txn: PendingTransaction<EspressoLedger>,
        txid: Option<(u64, u64)>,
    ) {
        // -> Result<(), WalletError<EspressoLedger>>

        if let Some((block_id, txn_id)) = txid {
            let memos = txn
                .info
                .memos
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .unwrap();
            let sig = txn.info.sig;
            self.ledger
                .lock()
                .await
                .post_memos(block_id, txn_id, memos, sig)
                .unwrap()
        }
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), WalletError<EspressoLedger>> {
        dbg!(self.ledger.lock().await.get_initial_scan_state())
    }
}

#[derive(Default)]
pub struct EspressoTest;

#[async_trait]
impl<'a> testing::SystemUnderTest<'a> for EspressoTest {
    type Ledger = EspressoLedger;
    type MockBackend = MockEspressoBackend<'a>;
    type MockNetwork = MockEspressoNetwork<'a>;
    type MockStorage = MockStorage<'a, EspressoLedger>;

    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        println!("[espresso] creating network");
        let mut ret = MockEspressoNetwork {
            validator: ValidatorState::new(verif_crs, records.clone()),
            records,
            nullifiers: SetMerkleTree::default(),
            committed_blocks: Vec::new(),
            proving_keys: Arc::new(proof_crs),
            address_map: HashMap::default(),
            events: MockEventSource::new(EventSource::QueryService),
        };

        // TODO: should we make this deterministic?
        let mut rng = crate::testing::crypto_rng_from_seed([0x42u8; 32]);

        // Broadcast receiver memos for the records which are included in the tree from the start,
        // so that clients can access records they have been granted at ledger setup time in a
        // uniform way.
        let memo_outputs = initial_grants
            .into_iter()
            .map(|(ro, uid)| {
                let memo = ReceiverMemo::from_ro(&mut rng, &ro, &[]).unwrap();
                let (comm, merkle_path) = ret
                    .records
                    .get_leaf(uid)
                    .expect_ok()
                    .map(|(_, proof)| {
                        (
                            RecordCommitment::from_field_element(proof.leaf.0),
                            proof.path,
                        )
                    })
                    .unwrap();
                (memo, comm, uid, merkle_path)
            })
            .collect();
        ret.generate_event(LedgerEvent::Memos {
            outputs: memo_outputs,
            transaction: None,
        });

        println!("[espresso] created network");
        ret
    }

    async fn create_storage(&mut self) -> Self::MockStorage {
        Default::default()
    }

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
        key_stream: hd::KeyTree,
        storage: Arc<Mutex<Self::MockStorage>>,
    ) -> Self::MockBackend {
        MockEspressoBackend {
            ledger,
            initial_grants,
            storage,
            key_stream,
        }
    }
}

// Espresso-specific tests
#[cfg(test)]
mod espresso_wallet_tests {
    use super::*;
    use jf_cap::structs::AssetCode;
    use std::time::Instant;
    use testing::SystemUnderTest;

    use testing::generic_wallet_tests;
    seahorse::instantiate_generic_wallet_tests!(EspressoTest);

    #[async_std::test]
    async fn test_resubmit() -> std::io::Result<()> {
        let mut t = EspressoTest::default();
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment. wallets[1] will act as the receiver, and wallets[2] will be a third party
        // which generates RECORD_ROOT_HISTORY_SIZE-1 transfers while a transfer from wallets[0] is
        // pending, after which we will check if the pending transaction can be updated and
        // resubmitted.
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(2, 2)],
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
        let receiver = wallets[1].1.clone();
        wallets[0]
            .0
            .transfer(
                None,
                &AssetCode::native(),
                &[(receiver.first().unwrap().clone(), 1)],
                1,
            )
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
            wallets[2]
                .0
                .transfer(
                    None,
                    &AssetCode::native(),
                    &[(receiver.first().unwrap().clone(), 1)],
                    1,
                )
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
        assert_eq!(wallets[0].0.balance(&AssetCode::native()).await, 0);
        assert_eq!(
            wallets[1].0.balance(&AssetCode::native()).await,
            1 + (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64
        );

        Ok(())
    }
}
