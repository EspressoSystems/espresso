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

// There are design arguments for partitioning this into independent modules for each api,
// but doing so results in duplicated work and (temporary) allocation

use crate::node::{ConsensusEvent, EventStream};
use ark_serialize::CanonicalSerialize;
use async_executors::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_std::task::block_on;
use commit::Committable;
use espresso_availability_api::{
    data_source::UpdateAvailabilityData,
    query_data::{BlockQueryData, StateQueryData},
};
use espresso_catchup_api::data_source::UpdateCatchUpData;
use espresso_core::state::{BlockCommitment, TransactionCommitment, ValidatorState};
use espresso_metastate_api::data_source::UpdateMetaStateData;
use espresso_status_api::data_source::UpdateStatusData;
use futures::{
    future::RemoteHandle,
    task::{SpawnError, SpawnExt},
    StreamExt,
};
use hotshot::data::{BlockHash, LeafHash, QuorumCertificate};
use hotshot::types::EventType;
use hotshot::H_256;
use itertools::izip;
use jf_primitives::merkle_tree::FilledMTBuilder;
use seahorse::events::LedgerEvent;

pub trait UpdateQueryDataSourceTypes {
    type CU: UpdateCatchUpData + Sized + Send + Sync;
    type AV: UpdateAvailabilityData + Sized + Send + Sync;
    type MS: UpdateMetaStateData + Sized + Send + Sync;
    type ST: UpdateStatusData + Sized + Send + Sync;
    type EH: EventProcessedHandler + Sized + Send + Sync;
}
pub struct UpdateQueryDataSource<TYPES>
where
    TYPES: UpdateQueryDataSourceTypes,
{
    catchup_store: Arc<RwLock<TYPES::CU>>,
    availability_store: Arc<RwLock<TYPES::AV>>,
    meta_state_store: Arc<RwLock<TYPES::MS>>,
    status_store: Arc<RwLock<TYPES::ST>>,
    event_handler: Arc<RwLock<TYPES::EH>>,
    validator_state: ValidatorState,
    _event_task: Option<RemoteHandle<()>>,
}

pub trait EventProcessedHandler {
    fn on_event_processing_complete(&mut self);
}

impl<TYPES> UpdateQueryDataSource<TYPES>
where
    TYPES: UpdateQueryDataSourceTypes + 'static,
{
    pub fn new(
        event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,
        catchup_store: Arc<RwLock<TYPES::CU>>,
        availability_store: Arc<RwLock<TYPES::AV>>,
        meta_state_store: Arc<RwLock<TYPES::MS>>,
        status_store: Arc<RwLock<TYPES::ST>>,
        event_handler: Arc<RwLock<TYPES::EH>>,
        validator_state: ValidatorState,
    ) -> Arc<RwLock<Self>> {
        let instance = Arc::new(RwLock::new(Self {
            catchup_store,
            availability_store,
            meta_state_store,
            status_store,
            event_handler,
            validator_state,
            _event_task: None,
        }));
        if let Ok(task_handle) = launch_updates(event_source, instance.clone()) {
            let mut edit_handle = block_on(instance.write());
            edit_handle._event_task = Some(task_handle);
        }
        instance
    }

    fn update(&mut self, event: impl ConsensusEvent) {
        use EventType::*;
        if let Decide { block, state, qcs } = event.into_event() {
            let mut num_txns = 0usize;
            let mut cumulative_size = 0usize;

            for (mut block, state, qcert) in
                izip!(block.iter().cloned(), state.iter(), qcs.iter().cloned()).rev()
            {
                // A block has been committed. Update our mirror of the ValidatorState by applying
                // the new block, and generate a Commit event.

                let block_index = self.validator_state.prev_commit_time;
                let mut merkle_builder = FilledMTBuilder::from_frontier(
                    &self.validator_state.record_merkle_commitment,
                    &self.validator_state.record_merkle_frontier,
                )
                .unwrap();

                match self.validator_state.validate_and_apply(
                    self.validator_state.prev_commit_time + 1,
                    block.block.clone(),
                    block.proofs.clone(),
                ) {
                    // We update our ValidatorState for each block committed by the HotShot event
                    // source, so we shouldn't ever get out of sync.
                    Err(_) => panic!("state is out of sync with validator"),
                    Ok(_) if self.validator_state.commit() != state.commit() => {
                        panic!("state is out of sync with validator")
                    }

                    Ok((uids, nullifier_proofs)) => {
                        let records_from = if uids.is_empty() {
                            self.validator_state.record_merkle_commitment.num_leaves
                        } else {
                            uids[0]
                        };

                        let mut txn_hashes = Vec::new();
                        let mut nullifiers_delta = Vec::new();
                        for (txn, _proofs) in block.block.0.iter().zip(block.proofs.iter()) {
                            for n in txn.input_nullifiers() {
                                nullifiers_delta.push(n);
                            }
                            let hash = TransactionCommitment(txn.commit());
                            txn_hashes.push(hash);
                        }
                        num_txns += block.block.0.len();
                        cumulative_size += block.serialized_size();
                        let event_index;

                        // Update the nullifier proofs in the block so that clients do not have
                        // to worry about out of date nullifier proofs.
                        block.proofs = block
                            .block
                            .0
                            .iter()
                            .map(|txn| {
                                txn.input_nullifiers()
                                    .into_iter()
                                    .map(|n| nullifier_proofs.contains(n).unwrap().1)
                                    .collect()
                            })
                            .collect();

                        {
                            let mut events = vec![Some(LedgerEvent::Commit {
                                block: block.clone(),
                                block_id: block_index as u64,
                                state_comm: self.validator_state.commit(),
                            })];

                            // Get a Merkle tree with in-memory paths for each output in this block.
                            for output in block
                                .block
                                .0
                                .iter()
                                .flat_map(|txn| txn.output_commitments())
                            {
                                merkle_builder.push(output.to_field_element());
                            }
                            let merkle_tree = merkle_builder.build();
                            // Use the Merkle paths to construct the Memos events for this block.
                            let mut first_uid = 0;
                            for (txn_id, (txn, memos)) in
                                block.block.0.iter().zip(block.memos.iter()).enumerate()
                            {
                                let txn_uids = &uids[first_uid..first_uid + txn.output_len()];
                                first_uid += txn.output_len();
                                let merkle_paths = txn_uids
                                    .iter()
                                    .map(|uid| {
                                        merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path
                                    })
                                    .collect::<Vec<_>>();
                                events.push(Some(LedgerEvent::Memos {
                                    outputs: izip!(
                                        memos.clone(),
                                        txn.output_commitments(),
                                        txn_uids.iter().cloned(),
                                        merkle_paths
                                    )
                                    .collect(),
                                    transaction: Some((
                                        block_index,
                                        txn_id as u64,
                                        txn.hash(),
                                        txn.kind(),
                                    )),
                                }))
                            }

                            let mut catchup_store = block_on(self.catchup_store.write());
                            event_index = catchup_store.event_count() as u64;
                            if let Err(e) = catchup_store.append_events(events) {
                                tracing::warn!("append_events returned error {}", e);
                            }
                        }
                        {
                            let qcert_block_hash: [u8; H_256] =
                                qcert.block_hash.try_into().unwrap_or([0u8; H_256]);
                            let block_hash = BlockHash::<H_256>::from_array(qcert_block_hash);
                            let mut availability_store = block_on(self.availability_store.write());
                            if let Err(e) = availability_store.append_blocks(vec![(
                                Some(BlockQueryData {
                                    raw_block: block.clone(),
                                    block_hash: BlockCommitment(block.block.commit()),
                                    block_id: block_index as u64,
                                    records_from,
                                    record_count: uids.len() as u64,
                                    txn_hashes,
                                }),
                                Some(StateQueryData {
                                    state: state.clone(),
                                    commitment: state.commit(),
                                    block_id: block_index as u64,
                                    event_index,
                                }),
                                Some(QuorumCertificate {
                                    block_hash,
                                    leaf_hash: LeafHash::default(),
                                    view_number: qcert.view_number,
                                    stage: qcert.stage,
                                    signatures: qcert.signatures,
                                    genesis: qcert.genesis,
                                }),
                            )]) {
                                tracing::warn!("append_blocks returned error {}", e);
                            }
                        }
                        {
                            let mut meta_state_store = block_on(self.meta_state_store.write());
                            if let Err(e) = meta_state_store
                                .append_block_nullifiers(block_index as u64, nullifiers_delta)
                            {
                                tracing::warn!("append_block_nullifiers returned error {}", e);
                            }
                        }
                    }
                }
            }
            let mut status_store = block_on(self.status_store.write());
            status_store
                .edit_status(|vs| {
                    vs.cumulative_txn_count += num_txns as u64;
                    vs.cumulative_size += cumulative_size as u64;
                    Ok(())
                })
                .unwrap();
            drop(status_store);

            let mut on_handled = block_on(self.event_handler.write());
            on_handled.on_event_processing_complete();
        }
    }
}

fn launch_updates<TYPES>(
    mut event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,
    update_handle: Arc<RwLock<UpdateQueryDataSource<TYPES>>>,
) -> Result<RemoteHandle<()>, SpawnError>
where
    TYPES: UpdateQueryDataSourceTypes + 'static,
{
    AsyncStd::new().spawn_with_handle(async move {
        // Handle events as they come in from the network.
        while let Some(event) = event_source.next().await {
            update_handle.write().await.update(event);
        }
    })
}
