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
use espresso_core::state::{
    EspressoTransaction, EspressoTxnHelperProofs, TransactionCommitment, ValidatorState,
};
use espresso_metastate_api::data_source::UpdateMetaStateData;
use espresso_status_api::data_source::UpdateStatusData;
use futures::{
    future::RemoteHandle,
    task::{SpawnError, SpawnExt},
    Stream, StreamExt,
};
use itertools::izip;
use reef::traits::Transaction;
use seahorse::events::LedgerEvent;

pub type HotShotEvent = hotshot::types::EventType<ValidatorState>;

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
        event_source: impl 'static + Send + Unpin + Stream<Item = HotShotEvent>,
        catchup_store: Arc<RwLock<TYPES::CU>>,
        availability_store: Arc<RwLock<TYPES::AV>>,
        meta_state_store: Arc<RwLock<TYPES::MS>>,
        status_store: Arc<RwLock<TYPES::ST>>,
        event_handler: Arc<RwLock<TYPES::EH>>,
    ) -> Arc<RwLock<Self>> {
        let instance = Arc::new(RwLock::new(Self {
            catchup_store,
            availability_store,
            meta_state_store,
            status_store,
            event_handler,
            validator_state: Default::default(),
            _event_task: None,
        }));
        if let Ok(task_handle) = launch_updates(event_source, instance.clone()) {
            let mut edit_handle = block_on(instance.write());
            edit_handle._event_task = Some(task_handle);
        }
        instance
    }

    async fn update(&mut self, event: HotShotEvent) {
        if let HotShotEvent::Decide { leaf_chain } = event {
            let mut num_txns = 0usize;
            let mut cumulative_size = 0usize;
            for leaf in leaf_chain.iter().rev() {
                let mut block = leaf.deltas.clone();
                let state = &leaf.state;
                let qcert = leaf.justify_qc.clone();

                // Grab metadata for the new block from the state it is applying to.
                let block_index = self.validator_state.block_height;
                let nullifier_proofs = self
                    .validator_state
                    .update_nullifier_proofs(&block.block.0, block.proofs.clone())
                    .expect("failed to update nullifier proofs from HotShot block");
                let record_proofs = self.validator_state.update_records_frontier(&block.block.0);
                let records_from = self.validator_state.record_merkle_commitment.num_leaves;
                // Update the state.
                self.validator_state = state.clone();

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
                let continuation_event_index;

                // Update the nullifier proofs in the block so that clients do not have
                // to worry about out of date nullifier proofs.
                for (txn, proofs) in block.block.0.iter().zip(block.proofs.iter_mut()) {
                    if let EspressoTransaction::CAP(txn) = txn {
                        *proofs = EspressoTxnHelperProofs::CAP(
                            txn.input_nullifiers()
                                .into_iter()
                                .map(|n| nullifier_proofs.contains(n).unwrap().1)
                                .collect(),
                        );
                    }
                }

                let record_count = {
                    let mut events = vec![Some(LedgerEvent::Commit {
                        block: block.clone(),
                        block_id: block_index as u64,
                        state_comm: self.validator_state.commit(),
                    })];

                    // Construct the Memos events for this block.
                    let mut first_uid = records_from;
                    for (txn_id, (txn, memos)) in
                        block.block.0.iter().zip(block.memos.iter()).enumerate()
                    {
                        let output_len = txn.output_len() as u64;
                        let txn_uids = (first_uid..first_uid + output_len).collect::<Vec<_>>();
                        first_uid += output_len;
                        let merkle_paths = txn_uids
                            .iter()
                            .map(|uid| record_proofs.get_leaf(*uid).expect_ok().unwrap().1.path)
                            .collect::<Vec<_>>();
                        events.push(Some(LedgerEvent::Memos {
                            outputs: izip!(
                                memos.clone().map(|(memos, _)| memos).unwrap_or_default(),
                                txn.output_commitments(),
                                txn_uids,
                                merkle_paths
                            )
                            .collect(),
                            transaction: Some((block_index, txn_id as u64, txn.hash(), txn.kind())),
                        }))
                    }

                    let mut catchup_store = self.catchup_store.write().await;
                    if let Err(e) = catchup_store.append_events(events).await {
                        tracing::warn!("append_events returned error {}", e);
                    }
                    continuation_event_index = catchup_store.event_count() as u64;

                    first_uid - records_from
                };
                {
                    let mut availability_store = self.availability_store.write().await;
                    if let Err(e) = availability_store.append_blocks(vec![(
                        Some(BlockQueryData {
                            raw_block: block.clone(),
                            block_hash: block.commit().into(),
                            block_id: block_index as u64,
                            records_from,
                            record_count,
                            txn_hashes,
                        }),
                        Some(StateQueryData {
                            state: state.clone(),
                            commitment: state.commit(),
                            block_id: block_index as u64,
                            continuation_event_index,
                        }),
                        Some(qcert),
                    )]) {
                        tracing::warn!("append_blocks returned error {}", e);
                    }
                }
                {
                    let mut meta_state_store = self.meta_state_store.write().await;
                    if let Err(e) = meta_state_store
                        .append_block_nullifiers(block_index as u64, nullifiers_delta)
                    {
                        tracing::warn!("append_block_nullifiers returned error {}", e);
                    }
                }
            }
            let mut status_store = self.status_store.write().await;
            status_store
                .edit_status(|vs| {
                    vs.latest_block_id = self.validator_state.block_height as u64 - 1;
                    vs.decided_block_count += leaf_chain.len() as u64;
                    vs.cumulative_txn_count += num_txns as u64;
                    vs.cumulative_size += cumulative_size as u64;
                    Ok(())
                })
                .unwrap();
            drop(status_store);

            let mut on_handled = self.event_handler.write().await;
            on_handled.on_event_processing_complete();
        }
    }
}

fn launch_updates<TYPES>(
    mut event_source: impl 'static + Send + Unpin + Stream<Item = HotShotEvent>,
    update_handle: Arc<RwLock<UpdateQueryDataSource<TYPES>>>,
) -> Result<RemoteHandle<()>, SpawnError>
where
    TYPES: UpdateQueryDataSourceTypes + 'static,
{
    AsyncStd::new().spawn_with_handle(async move {
        // Handle events as they come in from the network.
        while let Some(event) = event_source.next().await {
            update_handle.write().await.update(event).await;
        }
    })
}
