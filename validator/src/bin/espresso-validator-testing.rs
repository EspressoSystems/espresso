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

#![deny(warnings)]

use async_std::{
    sync::Arc,
    task::{sleep, spawn_blocking},
};
use clap::Parser;
use espresso_core::{
    genesis::GenesisNote,
    state::{ChainVariables, SetMerkleTree, ValidatorState},
    testing::MultiXfrRecordSpecTransaction,
    testing::{MultiXfrRecordSpec, MultiXfrTestState, TestTxSpec, TxnPrintInfo},
    universal_params::VERIF_CRS,
};
use espresso_validator::{validator::*, *};
use hotshot::{traits::State, types::EventType};
use std::time::Duration;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "Espresso validator for testing",
    about = "Runs a validator for a given rounds of consensus for testing purposes."
)]
struct Options {
    /// Node with `node_opt.id = 0` will be the transaction submitter.
    #[command(flatten)]
    node_opt: NodeOpt,

    /// Number of successful transactions to submit.
    #[arg(long, short)]
    pub num_txns: u64,
}

fn genesis_for_test() -> (GenesisNote, MultiXfrTestState) {
    let mut state = MultiXfrTestState::initialize(
        GENESIS_SEED,
        10,
        10,
        (
            MultiXfrRecordSpec {
                asset_def_ix: 0,
                owner_key_ix: 0,
                asset_amount: 100,
            },
            vec![
                MultiXfrRecordSpec {
                    asset_def_ix: 1,
                    owner_key_ix: 0,
                    asset_amount: 50,
                },
                MultiXfrRecordSpec {
                    asset_def_ix: 0,
                    owner_key_ix: 0,
                    asset_amount: 70,
                },
            ],
        ),
    )
    .unwrap();

    // [GenesisNote] doesn't support a non-empty nullifiers set, so we clear the nullifiers set in
    // our test state. This effectively "unspends" the records which were used to set up the initial
    // state. This is fine for testing purposes.
    state.nullifiers = SetMerkleTree::default();
    let genesis = GenesisNote::new(
        ChainVariables::new(42, VERIF_CRS.clone()),
        Arc::new(state.records().collect()),
    );
    state.validator = ValidatorState::genesis(genesis.clone());
    (genesis, state)
}

async fn generate_transaction(
    mut state: MultiXfrTestState,
    round: u64,
) -> (MultiXfrTestState, MultiXfrRecordSpecTransaction) {
    spawn_blocking(move || {
        let mut txs = state
            .generate_transactions(
                vec![(
                    TestTxSpec::TwoInput {
                        rec0: 0,
                        rec1: 0,
                        key0: 0,
                        key1: 0,
                        diff: -2,
                    },
                    false,
                )],
                TxnPrintInfo::new_no_time(round as usize, 1),
            )
            .unwrap();
        (state, txs.remove(0))
    })
    .await
}

async fn generate_transactions(
    num_txns: u64,
    own_id: usize,
    mut hotshot: Consensus,
    mut state: MultiXfrTestState,
) {
    #[cfg(target_os = "linux")]
    let bytes_per_page = procfs::page_size().unwrap() as u64;
    #[cfg(target_os = "linux")]
    tracing::debug!("{} bytes per page", bytes_per_page);

    let fence = || std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

    let report_mem = || {
        fence();
        #[cfg(target_os = "linux")]
        {
            let process_stats = procfs::process::Process::myself().unwrap().statm().unwrap();
            tracing::debug!(
                "{:.3}MiB | raw: {:?}",
                ((process_stats.size * bytes_per_page) as f64) / ((1u64 << 20) as f64),
                process_stats
            );
        }
        fence();
    };

    hotshot.start().await;

    // Start consensus for each transaction
    let mut final_commitment = None;
    let mut round = 0;
    while round < num_txns {
        info!("Starting round {}", round + 1);
        report_mem();
        info!("Commitment: {}", hotshot.get_state().await.commit());

        if own_id == 0 {
            // If we're the designated transaction submitter (i.e. node 0), submit a transaction and
            // wait for it to complete.
            info!("  - Submitting a transaction");
            let (new_state, mut txn) = generate_transaction(state, round).await;
            state = new_state;
            hotshot
                .submit_transaction(txn.transaction.clone())
                .await
                .unwrap();
            let mut empty_blocks = 0;
            loop {
                info!("Waiting for HotShot event");
                let event = hotshot
                    .next_event()
                    .await
                    .expect("HotShot unexpectedly closed");
                if let EventType::Decide { leaf_chain } = &event.event {
                    let mut success = false;
                    info!("decide with {} leaves", leaf_chain.len());
                    if let Some(leaf) = leaf_chain.last() {
                        if leaf.state.block_height > state.validator.block_height + 1 {
                            panic!(
                                "missed a block, submitter is behind and cannot build a transaction"
                            );
                        }
                    }
                    for leaf in leaf_chain.iter().rev() {
                        // Add the block.
                        if leaf.deltas.is_empty() {
                            state
                                .validate_and_apply(
                                    leaf.deltas.clone(),
                                    &leaf.view_number,
                                    0.0,
                                    TxnPrintInfo::new_no_time(round as usize, 1),
                                )
                                .unwrap();
                            empty_blocks += 1;
                            info!("got empty block ({} since last commit)", empty_blocks);
                            if empty_blocks >= ValidatorState::HISTORY_SIZE {
                                // If the transaction has expired due to empty blocks, sumit a new
                                // one. We could update the same one and fix all its nullifier
                                // proofs, but for testing it doesn't matter and its simpler to just
                                // build a new transaction.
                                info!("transaction expired, submitting a new one");
                                (state, txn) = generate_transaction(state, round).await;
                                hotshot
                                    .submit_transaction(txn.transaction.clone())
                                    .await
                                    .unwrap();
                                empty_blocks = 0;
                            }
                        } else if leaf.deltas.block.0[0].is_genesis() {
                            // Nothing to do, the genesis transaction is already accounted for in
                            // our mock state.
                        } else {
                            // In this demo, the only (non-genesis) blocks should be empty blocks
                            // and the singleton block that we submitted.
                            assert_eq!(leaf.deltas.block.0.len(), 1);
                            assert_eq!(txn.transaction.txn, leaf.deltas.block.0[0]);
                            let mut blk = state.validator.next_block();
                            let kixs = txn.keys_and_memos.iter().map(|(kix, _)| *kix).collect();
                            state
                                .try_add_transaction(
                                    &mut blk,
                                    txn.transaction.clone(),
                                    txn.index,
                                    kixs,
                                    TxnPrintInfo::new_no_time(round as usize, 1),
                                )
                                .unwrap();
                            state
                                .validate_and_apply(
                                    blk,
                                    &leaf.view_number,
                                    0.0,
                                    TxnPrintInfo::new_no_time(round as usize, 1),
                                )
                                .unwrap();
                            println!(
                                "  - Round {} completed. Commitment: {}",
                                round + 1,
                                leaf.state.commit()
                            );
                            round += 1;
                            success = true;
                        }
                    }
                    if success {
                        final_commitment = Some(leaf_chain.first().unwrap().state.commit());
                        break;
                    }
                } else {
                    info!("EVENT: {:?}", event);
                }
            }
        } else {
            // If we're a replica, just wait until we see a non-empty, non-genesis block.
            loop {
                info!("Waiting for HotShot event");
                let event = hotshot
                    .next_event()
                    .await
                    .expect("HotShot unexpectedly closed");
                if let EventType::Decide { leaf_chain } = &event.event {
                    if let Some(leaf) = leaf_chain.first() {
                        info!(
                            "replica got block (block height {}, transaction count {})",
                            leaf.state.block_height, leaf.state.transaction_count
                        );
                        if leaf.state.transaction_count > (round + 1) as usize {
                            // Update round to account for all committed transactions, excluding the
                            // genesis transaction.
                            let commit = leaf_chain.first().unwrap().state.commit();
                            println!("  - Round {} completed. Commitment: {}", round + 1, commit);
                            final_commitment = Some(commit);
                            round = (leaf.state.transaction_count - 1) as u64;
                            break;
                        }
                    }
                } else {
                    info!("EVENT: {:?}", event);
                }
            }
        }
    }

    info!("All rounds completed.");
    // !!!!!!     WARNING !!!!!!!
    // If the output below is changed, update the message for main() in
    // src/bin/multi-machine-automation.rs as well
    if let Some(commitment) = final_commitment {
        println!(
            // THINK TWICE BEFORE CHANGING THIS
            "Final commitment: {}",
            commitment
        );
    }
    // !!!!!! END WARNING !!!!!!!

    // Wait for other nodes to catch up.
    sleep(Duration::from_secs(10)).await;
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let options = Options::parse();
    let id = options.node_opt.id;
    let (genesis, state) = genesis_for_test();
    let hotshot = init(genesis, options.node_opt).await?;
    generate_transactions(options.num_txns, id, hotshot, state).await;
    Ok(())
}
