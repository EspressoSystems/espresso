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
use espresso_availability_api::query_data::{BlockQueryData, StateQueryData};
use espresso_core::ledger::EspressoLedger;
use espresso_core::state::{
    BlockCommitment, ElaboratedBlock, TransactionCommitment, ValidationError, ValidatorState,
};
use futures::task::SpawnError;
use hotshot::types::EventType;
use hotshot::HotShotError;
use seahorse::events::LedgerEvent;

use crate::node::{ConsensusEvent, EventStream};
use espresso_availability_api::data_source::UpdateAvailabilityData;
use espresso_catchup_api::data_source::UpdateCatchUpData;
use espresso_metastate_api::data_source::UpdateMetaStateData;
use espresso_status_api::data_source::UpdateStatusData;
use futures::StreamExt;
use futures::{future::RemoteHandle, task::SpawnExt};
use reef::traits::Transaction;

pub struct UpdateQueryDataSource<CU, AV, MS, ST>
where
    CU: UpdateCatchUpData + Sized + Send + Sync,
    AV: UpdateAvailabilityData + Sized + Send + Sync,
    MS: UpdateMetaStateData + Sized + Send + Sync,
    ST: UpdateStatusData + Sized + Send + Sync,
{
    catchup_store: Arc<RwLock<CU>>,
    availability_store: Arc<RwLock<AV>>,
    meta_state_store: Arc<RwLock<MS>>,
    status_store: Arc<RwLock<ST>>,
    /// we need a copy of the validator state and proposed block to check for reject events
    validator_state: ValidatorState,
    proposed_block: ElaboratedBlock,
    _event_task: Option<RemoteHandle<()>>,
}

impl<CU, AV, MS, ST> UpdateQueryDataSource<CU, AV, MS, ST>
where
    CU: UpdateCatchUpData + Sized + Send + Sync + 'static,
    AV: UpdateAvailabilityData + Sized + Send + Sync + 'static,
    MS: UpdateMetaStateData + Sized + Send + Sync + 'static,
    ST: UpdateStatusData + Sized + Send + Sync + 'static,
{
    pub fn new(
        event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,
        catchup_store: Arc<RwLock<CU>>,
        availability_store: Arc<RwLock<AV>>,
        meta_state_store: Arc<RwLock<MS>>,
        status_store: Arc<RwLock<ST>>,
        validator_state: ValidatorState,
    ) -> Arc<RwLock<Self>> {
        let instance = Arc::new(RwLock::new(Self {
            catchup_store,
            availability_store,
            meta_state_store,
            status_store,
            validator_state,
            proposed_block: ElaboratedBlock::default(),
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
        match event.into_event() {
            Error { error } => {
                if matches!(
                    *error,
                    HotShotError::BadBlock { .. } | HotShotError::InconsistentBlock { .. }
                ) {
                    // If the error is due to a bad block, correllate it with the block that caused
                    // the error (`self.proposed` in our current hacky solution, but eventually
                    // saved somewhere in storage) and send the block through our mirror of the
                    // validator to get a helpful error.
                    let err = match self.validator_state.validate_and_apply(
                        self.validator_state.prev_commit_time + 1,
                        self.proposed_block.block.clone(),
                        self.proposed_block.proofs.clone(),
                    ) {
                        Err(err) => err,
                        Ok(_) => {
                            // Something weird happened: the validator reported a bad block, but our
                            // mirror of the ValidatorState accepts the block. It's unclear what
                            // this means, but we can report a generic error to the subscribers.
                            ValidationError::Failed {}
                        }
                    };
                    let mut catchup = block_on(self.catchup_store.write());
                    let _ =
                        catchup.append_events(&mut vec![LedgerEvent::<EspressoLedger>::Reject {
                            block: self.proposed_block.clone(),
                            error: err,
                        }]);
                }

                // HotShot errors that don't relate to blocks being rejected (view timeouts,
                // network errors, etc.) do not correspond to LedgerEvents.
            }

            Propose { block } => {
                self.proposed_block = (*block).clone();
            }

            Decide {
                block,
                state,
                qcs: _,
            } => {
                let mut num_txns = 0usize;
                let mut cumulative_size = 0usize;

                for (mut block, state) in block.iter().cloned().zip(state.iter()).rev() {
                    // A block has been committed. Update our mirror of the ValidatorState by applying
                    // the new block, and generate a Commit event.

                    let block_index = self.validator_state.prev_commit_time + 1;

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
                            {
                                let mut catchup_store = block_on(self.catchup_store.write());
                                event_index = catchup_store.event_count() as u64;
                                if let Err(e) =
                                    catchup_store.append_events(&mut vec![LedgerEvent::Commit {
                                        block: block.clone(),
                                        block_id: block_index as u64,
                                        state_comm: self.validator_state.commit(),
                                    }])
                                {
                                    // log for now... this should be propagated once we get rid of FullState
                                    tracing::warn!("append_events returned error {}", e);
                                }
                            }
                            {
                                let mut availability_store =
                                    block_on(self.availability_store.write());
                                if let Err(e) = availability_store.append_blocks(
                                    &mut vec![BlockQueryData {
                                        raw_block: block.clone(),
                                        block_hash: BlockCommitment(block.block.commit()),
                                        block_id: block_index as u64,
                                        records_from,
                                        record_count: uids.len() as u64,
                                        txn_hashes,
                                    }],
                                    &mut vec![StateQueryData {
                                        state: state.clone(),
                                        commitment: state.commit(),
                                        block_id: block_index as u64,
                                        event_index,
                                    }],
                                ) {
                                    // log for now... this should be propagated once we get rid of FullState
                                    tracing::warn!("append_blocks returned error {}", e);
                                }
                            }
                            {
                                let mut meta_state_store = block_on(self.meta_state_store.write());
                                if let Err(e) = meta_state_store
                                    .append_block_nullifiers(block_index as u64, nullifiers_delta)
                                {
                                    // log for now... this should be propagated once we get rid of FullState
                                    tracing::warn!("append_block_nullifiers returned error {}", e);
                                }
                            }

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
            }

            _ => {}
        }
    }
}

fn launch_updates<CU, AV, MS, ST>(
    mut event_source: EventStream<impl ConsensusEvent + Send + std::fmt::Debug + 'static>,
    update_handle: Arc<RwLock<UpdateQueryDataSource<CU, AV, MS, ST>>>,
) -> Result<RemoteHandle<()>, SpawnError>
where
    CU: UpdateCatchUpData + Sized + Send + Sync + 'static,
    AV: UpdateAvailabilityData + Sized + Send + Sync + 'static,
    MS: UpdateMetaStateData + Sized + Send + Sync + 'static,
    ST: UpdateStatusData + Sized + Send + Sync + 'static,
{
    AsyncStd::new().spawn_with_handle(async move {
        // Handle events as they come in from the network.
        while let Some(event) = event_source.next().await {
            update_handle.write().await.update(event);
        }
    })
}
