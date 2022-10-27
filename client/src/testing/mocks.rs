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

use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use espresso_core::{
    genesis::GenesisNote,
    ledger::EspressoLedger,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{
        ChainVariables, ElaboratedBlock, ElaboratedTransaction, EspressoTransaction,
        ValidationOutputs, ValidatorState,
    },
};
use futures::stream::Stream;
use itertools::izip;
use jf_cap::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    structs::{Nullifier, ReceiverMemo, RecordOpening},
    MerkleTree, Signature,
};
use key_set::{OrderByOutputs, ProverKeySet, VerifierKeySet};
use reef::Ledger;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    ledger_state::LedgerState,
    lw_merkle_tree::LWMerkleTree,
    testing,
    testing::MockEventSource,
    transactions::Transaction,
    KeystoreBackend, KeystoreError,
};
use std::collections::{BTreeMap, HashMap};
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

    fn state(&self) -> &ValidatorState {
        &self.validator
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

    fn submit(&mut self, block: ElaboratedBlock) -> Result<usize, KeystoreError<EspressoLedger>> {
        match self.validator.validate_and_apply(
            &(self.validator.prev_commit_time + 1),
            block.parent_state,
            block.block.clone(),
            block.proofs.clone(),
        ) {
            Ok(ValidationOutputs { mut uids, .. }) => {
                // Add nullifiers
                for txn in &block.block.0 {
                    for nullifier in txn.input_nullifiers() {
                        self.nullifiers.insert(nullifier);
                    }
                    for record in txn.output_commitments() {
                        self.records.push(record.to_field_element())
                    }
                }

                // Broadcast the new block
                let block_id = self.committed_blocks.len() as u64;
                self.generate_event(LedgerEvent::Commit {
                    block: block.clone(),
                    block_id,
                    state_comm: self.validator.commit(),
                    proof: self.validator.prev_commit_time,
                });

                // Store the block in the history
                let mut block_uids = vec![];
                for txn in block.block.0.iter() {
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());
                    assert_eq!(this_txn_uids.len(), txn.output_len());
                    block_uids.push(this_txn_uids);
                }
                self.committed_blocks.push((block.clone(), block_uids));

                // Broadcast the memos.
                let mut num_memos = 0;
                for (txn_id, memos) in block.memos.into_iter().enumerate() {
                    if let Some((memos, sig)) = memos {
                        self.post_memos(block_id, txn_id as u64, memos, sig)
                            .unwrap();
                        num_memos += 1;
                    }
                }
                Ok(num_memos)
            }
            Err(error) => {
                self.generate_event(LedgerEvent::Reject { block, error });
                Ok(0)
            }
        }
    }

    fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        let (block, uids) = match self.committed_blocks.get(block_id as usize) {
            Some(block) => block,
            None => {
                return Err(KeystoreError::Failed {
                    msg: String::from("invalid block ID"),
                });
            }
        };
        let txn = match block.block.0.get(txn_id as usize) {
            Some(txn) => txn,
            None => {
                return Err(KeystoreError::Failed {
                    msg: String::from("invalid transaction ID"),
                });
            }
        };
        let uids = &uids[txn_id as usize];

        // Validate the new memos.
        match txn {
            EspressoTransaction::Genesis(_) => {}
            EspressoTransaction::CAP(txn) => {
                if txn.verify_receiver_memos_signature(&memos, &sig).is_err() {
                    return Err(KeystoreError::Failed {
                        msg: String::from("invalid memos signature"),
                    });
                }
            }
            EspressoTransaction::Reward(_) => {}
        }

        if memos.len() != txn.output_len() {
            return Err(KeystoreError::Failed {
                msg: format!("wrong number of memos (expected {})", txn.output_len()),
            });
        }

        // Authenticate the validity of the records corresponding to the memos.
        let merkle_tree = &self.records;
        let merkle_paths = uids
            .iter()
            .map(|uid| merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path)
            .collect::<Vec<_>>();

        // Broadcast the new memos.
        let memos = izip!(
            memos,
            txn.output_commitments(),
            uids.iter().cloned(),
            merkle_paths
        )
        .collect::<Vec<_>>();
        let event = LedgerEvent::Memos {
            outputs: memos,
            transaction: Some((block_id as u64, txn_id as u64, txn.hash(), txn.kind())),
        };
        self.generate_event(event);

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
    ) -> Result<LedgerState<'a, EspressoLedger>, KeystoreError<EspressoLedger>> {
        let state = {
            let mut ledger = self.ledger.lock().await;

            LedgerState::new(
                ledger.network().proving_keys.clone(),
                ledger.now(),
                ledger.network().validator.clone(),
                LWMerkleTree::sparse(ledger.network().records.clone()),
                ledger.network().nullifiers.clone(),
            )
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
        block_id: u64,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), KeystoreError<EspressoLedger>> {
        let mut ledger = self.ledger.lock().await;
        assert_eq!(block_id, ledger.network().committed_blocks.len() as u64);
        if set.hash() == ledger.network().nullifiers.hash() {
            Ok(ledger.network().nullifiers.contains(nullifier).unwrap())
        } else {
            Err(KeystoreError::Failed {
                msg: "invalid nullifier root".into(),
            })
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
        mut txn: ElaboratedTransaction,
        txn_info: Transaction<EspressoLedger>,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        if let Some(signed_memos) = txn_info.memos() {
            txn.memos = Some((
                signed_memos.memos.iter().flatten().cloned().collect(),
                signed_memos.sig.clone(),
            ));
        }
        self.ledger.lock().await.submit(txn)
    }

    async fn finalize(&mut self, _txn: Transaction<EspressoLedger>, _txid: Option<(u64, u64)>) {
        // -> Result<(), KeystoreError<EspressoLedger>>
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<EspressoLedger>> {
        Ok((
            MerkleTree::new(EspressoLedger::merkle_height()).unwrap(),
            EventIndex::default(),
        ))
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
        let verif_crs = Arc::new(verif_crs);
        let mut ret = MockEspressoNetwork {
            validator: ValidatorState::default(),
            records: MerkleTree::new(records.height()).unwrap(),
            nullifiers: SetMerkleTree::default(),
            committed_blocks: Vec::new(),
            proving_keys: Arc::new(proof_crs),
            address_map: HashMap::default(),
            events: MockEventSource::new(EventSource::QueryService),
        };

        // Commit a [Genesis] block to initialize the ledger.
        let genesis = ElaboratedBlock::genesis(GenesisNote::new(
            ChainVariables::new(42, verif_crs),
            Arc::new(initial_grants.into_iter().map(|(ro, _)| ro).collect()),
            BTreeMap::new(),
        ));
        ret.submit(genesis).unwrap();
        assert_eq!(ret.validator.record_merkle_commitment, records.commitment());
        assert_eq!(ret.records.commitment(), records.commitment());

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
