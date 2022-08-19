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
use dirs::data_local_dir;
use espresso_core::testing::MultiXfrRecordSpecTransaction;
use espresso_core::{
    state::ElaboratedBlock,
    testing::{MultiXfrTestState, TestTxSpec, TxnPrintInfo},
};
use espresso_validator::full_node_data_source::QueryData;
use espresso_validator::*;
use futures::{future::pending, StreamExt};
use hotshot::types::EventType;
use jf_cap::keys::UserPubKey;
use std::env;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;
use tagged_base64::TaggedBase64;
use tracing::info;
use validator_node::node::Validator;

#[derive(Parser)]
#[clap(
    name = "Multi-machine consensus",
    about = "Simulates consensus among multiple machines"
)]
struct Options {
    #[clap(flatten)]
    node_opt: NodeOpt,

    #[clap(flatten)]
    consensus_opt: ConsensusOpt,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    #[clap(long, short, env = "ESPRESSO_VALIDATOR_ID")]
    #[clap(requires("num-nodes"))]
    pub id: usize,

    /// Number of nodes, including a fixed number of bootstrap nodes and a dynamic number of non-
    /// bootstrap nodes.
    #[clap(long, short, env = "ESPRESSO_VALIDATOR_NUM_NODES")]
    pub num_nodes: usize,

    /// Public key which should own a faucet record in the genesis block.
    ///
    /// For each given public key, the ledger will be initialized with a record of 2^32 native
    /// tokens, owned by the public key.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native
    /// token records.
    #[clap(long, env = "ESPRESSO_FAUCET_PUB_KEYS", value_delimiter = ',')]
    pub faucet_pub_key: Vec<UserPubKey>,

    /// Number of transactions to generate.
    ///
    /// If not provided, the validator will wait for externally submitted transactions.
    #[clap(long, short, conflicts_with("faucet-pub-key"))]
    pub num_txn: Option<u64>,

    /// Wait for web server to exit after transactions complete.
    #[clap(long)]
    pub wait: bool,

    /// Whether to color log output with ANSI color codes.
    #[clap(long, env = "ESPRESSO_COLORED_LOGS")]
    pub colored_logs: bool,

    #[clap(subcommand)]
    pub esqs: Option<full_node_esqs::Command>,
}

async fn generate_transactions(
    num_txn: u64,
    own_id: usize,
    hotshot: Node,
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

    let mut events = hotshot.subscribe();

    // Start consensus for each transaction
    let mut round = 0;
    let mut succeeded_round = 0;
    let mut txn: Option<MultiXfrRecordSpecTransaction> = None;
    let mut txn_proposed_round = 0;
    let mut final_commitment = None;
    while succeeded_round < num_txn {
        info!("Starting round {}", round + 1);
        report_mem();
        info!(
            "Commitment: {}",
            hotshot.current_state().await.unwrap().unwrap().commit()
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

        hotshot.start_consensus().await;
        let success = loop {
            info!("Waiting for HotShot event");
            let event = events.next().await.expect("HotShot unexpectedly closed");

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
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in txn.keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                state
                    .try_add_transaction(
                        &mut blk,
                        txn.transaction,
                        txn.index,
                        owner_memos,
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

fn default_store_path(node_id: usize) -> PathBuf {
    let mut data_dir = data_local_dir()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("./")));
    data_dir.push("espresso");
    data_dir.push("validator");
    data_dir.push(format!("node{}", node_id));
    data_dir
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let options = Options::from_args();
    if let Err(msg) = options.node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(options.colored_logs)
        .init();

    // Get the consensus configuration.
    let store_path = options
        .node_opt
        .store_path
        .clone()
        .unwrap_or_else(|| default_store_path(options.id));
    let data_source = async_std::sync::Arc::new(async_std::sync::RwLock::new(
        QueryData::new(&store_path).unwrap(),
    ));

    let own_id = options.id;
    // Initialize the state and hotshot
    let (genesis, state) = if options.num_txn.is_some() {
        // If we are going to generate transactions, we need to initialize the ledger with a
        // test state.
        let (genesis, state) = GenesisState::new_for_test();
        (genesis, Some(state))
    } else {
        (GenesisState::new(options.faucet_pub_key.clone()), None)
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
        data_source.clone(),
    )
    .await;

    // Start an EsQS server if requested.
    if let Some(esqs) = &options.esqs {
        async_std::task::spawn(full_node_esqs::init_server(esqs, data_source)?);
    }

    // If we are running a full node, also host a query API to inspect the accumulated state.
    let web_server = if let Node::Full(node) = &hotshot {
        Some(
            init_web_server(&options.node_opt, node.clone())
                .expect("Failed to initialize web server"),
        )
    } else {
        None
    };

    if let Some(num_txn) = options.num_txn {
        generate_transactions(num_txn, own_id, hotshot, state.unwrap()).await;
    } else {
        hotshot.run(pending::<()>()).await;
    }

    if options.wait {
        if let Some(join_handle) = web_server {
            join_handle.await.unwrap_or_else(|err| {
                panic!("web server exited with an error: {}", err);
            });
        }
    }

    Ok(())
}
