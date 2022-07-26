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

use async_std::sync::{Arc, RwLock};

use espresso_availability_api::data_source::UpdateAvailabilityData;
use espresso_catchup_api::data_source::UpdateCatchUpData;
use espresso_metastate_api::data_source::UpdateMetaStateData;
use espresso_status_api::data_source::UpdateStatusData;

pub struct UpdateQueryDataSource<CU, AV, MS, ST>
where
    CU: UpdateCatchUpData + Sized + Send + Sync,
    AV: UpdateAvailabilityData + Sized + Send + Sync,
    MS: UpdateMetaStateData + Sized + Send + Sync,
    ST: UpdateStatusData + Sized + Send + Sync,
{
    pub catchup_store: Arc<RwLock<CU>>,
    pub availability_store: Arc<RwLock<AV>>,
    pub meta_state_store: Arc<RwLock<MS>>,
    pub status_store: Arc<RwLock<ST>>,
}

// fn update(&mut self, event: impl ConsensusEvent) {
//     use EventType::*;
//     match event.into_event() {
//         Error { error } => {
//             if matches!(
//                 *error,
//                 HotShotError::BadBlock { .. } | HotShotError::InconsistentBlock { .. }
//             ) {
//                 // If the error is due to a bad block, correllate it with the block that caused
//                 // the error (`self.proposed` in our current hacky solution, but eventually
//                 // saved somewhere in storage) and send the block through our mirror of the
//                 // validator to get a helpful error.
//                 let err = match self.validator.validate_and_apply(
//                     self.validator.prev_commit_time + 1,
//                     self.proposed.block.clone(),
//                     self.proposed.proofs.clone(),
//                 ) {
//                     Err(err) => err,
//                     Ok(_) => {
//                         // Something weird happened: the validator reported a bad block, but our
//                         // mirror of the ValidatorState accepts the block. It's unclear what
//                         // this means, but we can report a generic error to the subscribers.
//                         ValidationError::Failed {}
//                     }
//                 };
//                 self.send_event(LedgerEvent::<EspressoLedger>::Reject {
//                     block: self.proposed.clone(),
//                     error: err,
//                 });
//             }

//             // HotShot errors that don't relate to blocks being rejected (view timeouts,
//             // network errors, etc.) do not correspond to LedgerEvents.
//         }

//         Propose { block } => {
//             self.proposed = (*block).clone();
//         }

//         Decide {
//             block,
//             state,
//             qcs: _,
//         } => {
//             for (mut block, state) in block.iter().cloned().zip(state.iter()).rev() {
//                 // A block has been committed. Update our mirror of the ValidatorState by applying
//                 // the new block, and generate a Commit event.

//                 match self.validator.validate_and_apply(
//                     self.validator.prev_commit_time + 1,
//                     block.block.clone(),
//                     block.proofs.clone(),
//                 ) {
//                     // We update our ValidatorState for each block committed by the HotShot event
//                     // source, so we shouldn't ever get out of sync.
//                     Err(_) => panic!("state is out of sync with validator"),
//                     Ok(_) if self.validator.commit() != state.commit() => {
//                         panic!("state is out of sync with validator")
//                     }

//                     Ok((mut uids, nullifier_proofs)) => {
//                         let records_from = if uids.is_empty() {
//                             self.validator.record_merkle_commitment.num_leaves
//                         } else {
//                             uids[0]
//                         };
//                         let hist_index = self.full_persisted.state_iter().len();
//                         assert!(hist_index > 0);
//                         let block_index = hist_index - 1;

//                         self.full_persisted.store_for_commit(&block, state);
//                         self.past_nullifiers
//                             .insert(self.validator.nullifiers_root(), hist_index);
//                         self.block_hashes
//                             .insert(Vec::from(block.hash().as_ref()), block_index);
//                         let block_uids = block
//                             .block
//                             .0
//                             .iter()
//                             .map(|txn| {
//                                 // Split the uids corresponding to this transaction off the front of
//                                 // the list of uids for the whole block.
//                                 let mut this_txn_uids = uids.split_off(txn.output_len());
//                                 std::mem::swap(&mut this_txn_uids, &mut uids);
//                                 assert_eq!(this_txn_uids.len(), txn.output_len());
//                                 this_txn_uids
//                             })
//                             .collect::<Vec<_>>();
//                         self.full_persisted.store_block_uids(&block_uids);
//                         self.full_persisted
//                             .store_memos(&vec![None; block.block.0.len()]);

//                         // Add the results of this block to our current state.
//                         let mut nullifiers =
//                             self.full_persisted.get_latest_nullifier_set().unwrap();
//                         let mut txn_hashes = Vec::new();
//                         let mut nullifiers_delta = Vec::new();
//                         for (txn, proofs) in block.block.0.iter().zip(block.proofs.iter()) {
//                             for n in txn.nullifiers() {
//                                 nullifiers.insert(n);
//                                 nullifiers_delta.push(n);
//                             }
//                             for o in txn.output_commitments() {
//                                 self.records_pending_memos.push(o.to_field_element());
//                             }

//                             let hash = TransactionCommitment(
//                                 ElaboratedTransaction {
//                                     txn: txn.clone(),
//                                     proofs: proofs.clone(),
//                                 }
//                                 .hash(),
//                             );
//                             txn_hashes.push(hash);
//                         }
//                         self.num_txns += block.block.0.len();
//                         self.cumulative_size += block.serialized_size();
//                         assert_eq!(nullifiers.hash(), self.validator.nullifiers_root());
//                         assert_eq!(
//                             self.records_pending_memos.commitment(),
//                             self.validator.record_merkle_commitment
//                         );
//                         self.full_persisted.store_nullifier_set(&nullifiers);
//                         self.full_persisted.commit_accepted();
//                         let event_index;
//                         {
//                             let mut catchup_store = block_on(self.catchup_store.write());
//                             event_index = catchup_store.event_count() as u64;
//                             if let Err(e) =
//                                 catchup_store.append_events(&mut vec![LedgerEvent::Commit {
//                                     block: block.clone(),
//                                     block_id: block_index as u64,
//                                     state_comm: self.validator.commit(),
//                                 }])
//                             {
//                                 // log for now... this should be propagated once we get rid of FullState
//                                 tracing::warn!("append_events returned error {}", e);
//                             }
//                         }
//                         {
//                             let mut availability_store =
//                                 block_on(self.availability_store.write());
//                             if let Err(e) = availability_store.append_blocks(
//                                 &mut vec![BlockQueryData {
//                                     raw_block: block.clone(),
//                                     block_hash: BlockCommitment(block.block.commit()),
//                                     block_id: block_index as u64,
//                                     records_from,
//                                     record_count: uids.len() as u64,
//                                     txn_hashes,
//                                 }],
//                                 &mut vec![StateQueryData {
//                                     state: state.clone(),
//                                     commitment: state.commit(),
//                                     block_id: block_index as u64,
//                                     event_index,
//                                 }],
//                             ) {
//                                 // log for now... this should be propagated once we get rid of FullState
//                                 tracing::warn!("append_blocks returned error {}", e);
//                             }
//                         }
//                         {
//                             let mut meta_state_store = block_on(self.meta_state_store.write());
//                             if let Err(e) = meta_state_store
//                                 .append_block_nullifiers(block_index as u64, nullifiers_delta)
//                             {
//                                 // log for now... this should be propagated once we get rid of FullState
//                                 tracing::warn!("append_block_nullifiers returned error {}", e);
//                             }
//                         }

//                         // Update the nullifier proofs in the block so that clients do not have
//                         // to worry about out of date nullifier proofs.
//                         block.proofs = block
//                             .block
//                             .0
//                             .iter()
//                             .map(|txn| {
//                                 txn.nullifiers()
//                                     .into_iter()
//                                     .map(|n| nullifier_proofs.contains(n).unwrap().1)
//                                     .collect()
//                             })
//                             .collect();

//                         // Notify subscribers of the new block.
//                         self.send_event(LedgerEvent::Commit {
//                             block,
//                             block_id: block_index as u64,
//                             state_comm: self.validator.commit(),
//                         });
//                     }
//                 }
//             }
//         }

//         _ => {}
//     }
// }
