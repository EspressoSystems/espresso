// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

pub use seahorse::testing::MockLedger;

use crate::node;
use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use espresso_core::{
    ledger::EspressoLedger,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{ElaboratedBlock, ElaboratedTransaction, ValidatorState},
};
use futures::stream::Stream;
use jf_cap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    sparse_merkle_tree::SparseMerkleTree,
    testing,
    testing::MockEventSource,
    txn_builder::{PendingTransaction, TransactionInfo, TransactionState},
    KeystoreBackend, KeystoreError, KeystoreState,
};
use std::collections::HashMap;
use std::pin::Pin;
use testing::MockNetwork;

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
    ) -> Result<LedgerEvent<EspressoLedger>, KeystoreError<EspressoLedger>> {
        match source {
            EventSource::QueryService => self.events.get(index),
            _ => Err(KeystoreError::Failed {
                msg: String::from("invalid event source"),
            }),
        }
    }

    fn submit(&mut self, block: ElaboratedBlock) -> Result<(), KeystoreError<EspressoLedger>> {
        match self.validator.validate_and_apply(
            self.validator.prev_commit_time + 1,
            block.block.clone(),
            block.proofs.clone(),
        ) {
            Ok((mut uids, _)) => {
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
        _block_id: u64,
        _txn_id: u64,
        _memos: Vec<ReceiverMemo>,
        _sig: Signature,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
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
    ledger: Arc<Mutex<MockLedger<'a, EspressoLedger, MockEspressoNetwork<'a>>>>,
    initial_grants: Vec<(RecordOpening, u64)>,
}

#[async_trait]
impl<'a> KeystoreBackend<'a, EspressoLedger> for MockEspressoBackend<'a> {
    type EventStream =
        Pin<Box<dyn Stream<Item = (LedgerEvent<EspressoLedger>, EventSource)> + Send>>;

    async fn create(
        &mut self,
    ) -> Result<KeystoreState<'a, EspressoLedger>, KeystoreError<EspressoLedger>> {
        let state = {
            let mut ledger = self.ledger.lock().await;

            KeystoreState {
                proving_keys: ledger.network().proving_keys.clone(),
                txn_state: TransactionState {
                    validator: ledger.network().validator.clone(),

                    records: Default::default(),
                    nullifiers: ledger.network().nullifiers.clone(),
                    record_mt: SparseMerkleTree::sparse(ledger.network().records.clone()),

                    now: ledger.now(),
                    transactions: Default::default(),
                },
                key_state: Default::default(),
                freezing_accounts: Default::default(),
                sending_accounts: Default::default(),
                viewing_accounts: Default::default(),
            }
        };
        Ok(state)
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        let mut ledger = self.ledger.lock().await;
        ledger.network().events.subscribe(from, to)
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, KeystoreError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        match ledger.network().address_map.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(KeystoreError::<EspressoLedger>::InvalidAddress {
                address: address.clone(),
            }),
        }
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), KeystoreError<EspressoLedger>> {
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
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        let pub_key = key_pair.pub_key();
        ledger
            .network()
            .address_map
            .insert(pub_key.address(), pub_key);
        Ok(())
    }

    async fn submit(
        &mut self,
        txn: ElaboratedTransaction,
        _info: TransactionInfo<EspressoLedger>,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        self.ledger.lock().await.submit(txn)
    }

    async fn finalize(
        &mut self,
        _txn: PendingTransaction<EspressoLedger>,
        _txid: Option<(u64, u64)>,
    ) {
        // -> Result<(), KeystoreError<EspressoLedger>>
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<EspressoLedger>> {
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

        let mut rng = espresso_core::testing::crypto_rng_from_seed([0x42u8; 32]);

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

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockBackend {
        MockEspressoBackend {
            ledger,
            initial_grants,
        }
    }
}

// Espresso-specific tests
#[cfg(all(test, feature = "slow-tests"))]
mod espresso_keystore_tests {
    use super::*;
    use testing::generic_keystore_tests;
    seahorse::instantiate_generic_keystore_tests!(EspressoTest);
}
