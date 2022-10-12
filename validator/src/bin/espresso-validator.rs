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
use espresso_core::{
    state::ValidatorState,
    testing::{MultiXfrRecordSpecTransaction, MultiXfrTestState, TestTxSpec, TxnPrintInfo},
};
use espresso_esqs::full_node::{self, EsQS};
use espresso_validator::*;
use futures::future::pending;
use hotshot::{traits::State, types::EventType};
use jf_cap::keys::UserPubKey;
use std::process::exit;
use std::time::Duration;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "Multi-machine consensus",
    about = "Simulates consensus among multiple machines"
)]
struct Options {
    #[command(flatten)]
    node_opt: NodeOpt,

    #[command(flatten)]
    consensus_opt: ConsensusOpt,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_ID", requires("num-nodes"))]
    pub id: usize,

    /// Location of the current node.
    ///
    /// If not provided, the IP address will be used for dashboard display.
    #[clap(long, env = "ESPRESSO_VALIDATOR_LOCATION")]
    pub location: Option<String>,

    /// Number of nodes, including a fixed number of bootstrap nodes and a dynamic number of non-
    /// bootstrap nodes.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_NUM_NODES")]
    pub num_nodes: usize,

    /// Public key which should own a faucet record in the genesis block.
    ///
    /// For each given public key, the ledger will be initialized with a record of 2^32 native
    /// tokens, owned by the public key.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native
    /// token records.
    #[arg(long, env = "ESPRESSO_FAUCET_PUB_KEYS", value_delimiter = ',')]
    pub faucet_pub_key: Vec<UserPubKey>,

    /// Number of transactions to generate.
    ///
    /// If not provided, the validator will wait for externally submitted transactions.
    #[arg(long, short, conflicts_with("faucet-pub-key"))]
    pub num_txn: Option<u64>,

    /// Whether to color log output with ANSI color codes.
    #[arg(long, env = "ESPRESSO_COLORED_LOGS")]
    pub colored_logs: bool,

    /// Unique identifier for this instance of Espresso.
    #[arg(long, env = "ESPRESSO_VALIDATOR_CHAIN_ID", default_value = "0")]
    pub chain_id: u16,

    #[command(subcommand)]
    pub esqs: Option<full_node::Command>,
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
    num_txn: u64,
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
    while round < num_txn {
        info!("Starting round {}", round + 1);
        report_mem();
        info!("Commitment: {}", hotshot.get_state().await.commit());

        if own_id == 0 {
            // If we're the proposer, propose a transaction and wait for it to complete.
            info!("  - Proposing a transaction");
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

                match event.event {
                    EventType::Decide { leaf_chain } => {
                        let mut success = false;
                        info!("decide with {} leaves", leaf_chain.len());
                        if let Some(leaf) = leaf_chain.last() {
                            if leaf.state.block_height > state.validator.block_height + 1 {
                                panic!("missed a block, proposer is behind and cannot build a transaction");
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
                                    // If the transaction has expired due to empty blocks, propose
                                    // a new one. We could update the same one and fix all its
                                    // nullifier proofs, but for testing it doesn't matter and its
                                    // simpler to just build a new transaction.
                                    info!("transaction expired, proposing a new one");
                                    (state, txn) = generate_transaction(state, round).await;
                                    hotshot
                                        .submit_transaction(txn.transaction.clone())
                                        .await
                                        .unwrap();
                                    empty_blocks = 0;
                                }
                            } else if leaf.deltas.block.0[0].is_genesis() {
                                // Nothing to do, the genesis transaction is already accounted for
                                // in our mock state.
                            } else {
                                // In this demo, the only (non-genesis) blocks should be empty
                                // blocks and the singleton block that we submitted.
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

                                round += 1;
                                success = true;
                            }
                        }
                        if success {
                            let commit = leaf_chain.first().unwrap().state.commit();
                            println!("  - Round {} completed. Commitment: {}", round + 1, commit);
                            final_commitment = Some(commit);
                            break;
                        }
                    }
                    _ => {
                        info!("EVENT: {:?}", event);
                    }
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

                match event.event {
                    EventType::Decide { leaf_chain } => {
                        if let Some(leaf) = leaf_chain.first() {
                            info!(
                                "replica got block (block height {}, transaction count {})",
                                leaf.state.block_height, leaf.state.transaction_count
                            );
                            if leaf.state.transaction_count > (round + 1) as usize {
                                // Update round to account for all committed transactions, excluding
                                // the genesis transaction.
                                round = (leaf.state.transaction_count - 1) as u64;
                                let commit = leaf_chain.first().unwrap().state.commit();
                                println!(
                                    "  - Round {} completed. Commitment: {}",
                                    round + 1,
                                    commit
                                );
                                final_commitment = Some(commit);
                                break;
                            }
                        }
                    }
                    _ => {
                        info!("EVENT: {:?}", event);
                    }
                }
            }
        }
    }

    info!("All rounds completed.");
    // !!!!!!     WARNING !!!!!!!
    // If the output below is changed, update the message for main() in
    // src/bin/multi_machine_automation.rs as well
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
    if let Err(msg) = options.node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(options.colored_logs)
        .init();

    let own_id = options.id;
    // Initialize the state and hotshot
    let (genesis, state) = if options.num_txn.is_some() {
        // If we are going to generate transactions, we need to initialize the ledger with a
        // test state.
        let (genesis, state) = genesis_for_test();
        (genesis, Some(state))
    } else {
        (
            genesis(options.chain_id, options.faucet_pub_key.clone()),
            None,
        )
    };
    let keys = gen_keys(&options.consensus_opt, options.num_nodes);
    let priv_key = keys[own_id].private.clone();
    let known_nodes = keys.into_iter().map(|pair| pair.public).collect();

    let hotshot = init_validator(
        &options.node_opt,
        &options.consensus_opt,
        priv_key,
        known_nodes,
        genesis,
        own_id,
    )
    .await;
    let data_source =
        open_data_source(&options.node_opt, own_id, options.location, hotshot.clone());

    // Start an EsQS server if requested.
    if let Some(esqs) = &options.esqs {
        Some(EsQS::new(esqs, data_source, hotshot.clone())?)
    } else {
        None
    };

    if let Some(num_txn) = options.num_txn {
        generate_transactions(num_txn, own_id, hotshot, state.unwrap()).await;
    } else {
        run_consensus(hotshot, pending::<()>()).await;
    }

    Ok(())
}
