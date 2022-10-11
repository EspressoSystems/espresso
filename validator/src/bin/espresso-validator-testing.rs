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

use async_std::task::{sleep, spawn_blocking};
use clap::Parser;
use espresso_core::testing::MultiXfrRecordSpecTransaction;
use espresso_core::{
    state::ElaboratedBlock,
    testing::{MultiXfrTestState, TestTxSpec, TxnPrintInfo},
};
use espresso_validator::{simulation::*, *};
use hotshot::types::EventType;
use std::time::Duration;
use tagged_base64::TaggedBase64;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "Espresso validator for testing",
    about = "Runs a validator for a given rounds of consensus for testing purposes."
)]
struct Options {
    #[command(flatten)]
    simulation_opt: SimulationOpt,

    /// Number of transactions to generate.
    #[arg(long, short)]
    pub num_txns: u64,
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

    // Start consensus for each transaction
    let mut round = 0;
    let mut succeeded_round = 0;
    let mut txn: Option<MultiXfrRecordSpecTransaction> = None;
    let mut txn_proposed_round = 0;
    let mut final_commitment = None;
    while succeeded_round < num_txns {
        info!("Starting round {}", round + 1);
        report_mem();
        info!(
            "Commitment: {}",
            hotshot.get_state().await.unwrap().unwrap().commit()
        );

        // Generate a transaction if the node ID is 0 and if there isn't a keystore to generate it.
        if own_id == 0 {
            if let Some(tx) = txn.as_ref() {
                info!("  - Reproposing a transaction");
                if txn_proposed_round + 5 < round {
                    hotshot
                        .submit_transaction(tx.transaction.clone())
                        .await
                        .unwrap();
                    txn_proposed_round = round;
                }
            } else {
                info!("  - Proposing a transaction");
                let (new_state, mut transactions) = spawn_blocking(move || {
                    let txs = state
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
                    (state, txs)
                })
                .await;
                state = new_state;
                let transaction = transactions.remove(0);
                hotshot
                    .submit_transaction(transaction.transaction.clone())
                    .await
                    .unwrap();
                txn = Some(transaction);
                txn_proposed_round = round;
            }
        }

        hotshot.start().await;
        let success = loop {
            info!("Waiting for HotShot event");
            let event = hotshot
                .next_event()
                .await
                .expect("HotShot unexpectedly closed");

            match event.event {
                EventType::Decide {
                    block: _,
                    state,
                    qcs: _,
                } => {
                    if !state.is_empty() {
                        succeeded_round += 1;
                        let commitment = TaggedBase64::new("COMM", state[0].commit().as_ref())
                            .unwrap()
                            .to_string();
                        println!(
                            "  - Round {} completed. Commitment: {}",
                            succeeded_round, commitment
                        );
                        final_commitment = Some(commitment);
                        break true;
                    }
                }
                EventType::ViewTimeout { view_number: _ } => {
                    info!("  - Round {} timed out.", round + 1);
                    break false;
                }
                EventType::Error { error } => {
                    info!("  - Round {} error: {}", round + 1, error);
                    break false;
                }
                _ => {
                    info!("EVENT: {:?}", event);
                }
            }
        };

        if success {
            // Add the transaction if the node ID is 0 (i.e., the transaction is proposed by the
            // current node), and there is no attached keystore.
            if let Some(txn) = core::mem::take(&mut txn) {
                info!("  - Adding the transaction");
                let mut blk = ElaboratedBlock::default();
                let kixs = txn.keys_and_memos.into_iter().map(|(kix, _)| kix).collect();
                state
                    .try_add_transaction(
                        &mut blk,
                        txn.transaction,
                        txn.index,
                        kixs,
                        TxnPrintInfo::new_no_time(round as usize, 1),
                    )
                    .unwrap();
                state
                    .validate_and_apply(blk, 0.0, TxnPrintInfo::new_no_time(round as usize, 1))
                    .unwrap();
            }
        }

        round += 1;
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
    let id = options.simulation_opt.id;
    let (hotshot, state) = init(
        SimulationMode::Test(options.num_txns),
        options.simulation_opt,
    )
    .await?;
    generate_transactions(options.num_txns, id, hotshot, state.unwrap()).await;
    Ok(())
}
