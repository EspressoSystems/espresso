// Copyright © 2021 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]

use espresso_validator::*;
use futures::StreamExt;
use jf_cap::keys::UserPubKey;
use phaselock::types::EventType;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use tracing::info;
use zerok_lib::{
    node::{QueryService, Validator},
    state::{ElaboratedBlock, ElaboratedTransaction},
    testing::{MultiXfrTestState, TxnPrintInfo},
};

#[derive(StructOpt)]
#[structopt(
    name = "Multi-machine consensus",
    about = "Simulates consensus among multiple machines"
)]
struct Options {
    #[structopt(flatten)]
    node_opt: NodeOpt,

    /// Path to the node configuration file.
    #[structopt(long = "config", short = "c")]
    pub config: Option<PathBuf>,

    /// Path to the universal parameter file.
    #[structopt(long = "universal_param_path", short = "u")]
    pub universal_param_path: Option<String>,

    /// Whether to generate and store public keys for all nodes.
    ///
    /// Public keys will be stored under the directory specified by `pk_path`.
    ///
    /// Skip this option if public key files already exist.
    #[structopt(long = "gen_pk", short = "g")]
    #[structopt(conflicts_with("id"))]
    pub gen_pk: bool,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    ///
    /// Skip this option if only want to generate public key files.
    #[structopt(long = "id", short = "i")]
    #[structopt(conflicts_with("gen_pk"))]
    pub id: Option<u64>,

    /// Public key which should own a faucet record in the genesis block.
    ///
    /// For each given public key, the ledger will be initialized with a record of 2^32 native
    /// tokens, owned by the public key.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native
    /// token records.
    #[structopt(long)]
    pub faucet_pub_key: Vec<UserPubKey>,

    /// Number of transactions to generate.
    ///
    /// If not provided, the validator will wait for externally submitted transactions.
    #[structopt(long = "num_txn", short = "n", conflicts_with("faucet_pub_key"))]
    pub num_txn: Option<u64>,

    /// Wait for web server to exit after transactions complete.
    #[structopt(long)]
    pub wait: bool,
}

/// Returns the default path to the node configuration file.
fn default_config_path() -> PathBuf {
    const CONFIG_FILE: &str = "src/node-config.toml";
    let dir = project_path();
    [&dir, Path::new(CONFIG_FILE)].iter().collect()
}

async fn generate_transactions(
    num_txn: u64,
    own_id: u64,
    mut phaselock: Node,
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

    let mut events = phaselock.subscribe();

    // Start consensus for each transaction
    let mut round = 0;

    // When `num_txn` is set, run `num_txn` rounds.
    // Otherwise, keeping running till the process is killed.
    let mut txn: Option<(usize, _, _, ElaboratedTransaction)> = None;
    let mut txn_proposed_round = 0;
    let mut final_commitment = "".to_string();
    while round < num_txn {
        info!("Starting round {}", round + 1);
        report_mem();
        info!("Commitment: {}", phaselock.current_state().await.commit());

        // Generate a transaction if the node ID is 0 and if there isn't a wallet to generate it.
        if own_id == 0 {
            if let Some(tx) = txn.as_ref() {
                info!("  - Reproposing a transaction");
                if txn_proposed_round + 5 < round {
                    // TODO
                    phaselock.submit_transaction(tx.clone().3).await.unwrap();
                    txn_proposed_round = round;
                }
            } else {
                info!("  - Proposing a transaction");
                let (new_state, mut transactions) = async_std::task::spawn_blocking(move || {
                    let txs = state
                        .generate_transactions(
                            vec![(true, 0, 0, 0, 0, -2)],
                            TxnPrintInfo::new_no_time(round as usize, 1),
                        )
                        .unwrap();
                    (state, txs)
                })
                .await;
                state = new_state;
                txn = Some(transactions.remove(0));
                phaselock
                    .submit_transaction(txn.clone().unwrap().3)
                    .await
                    .unwrap();
                txn_proposed_round = round;
            }
        }

        phaselock.start_consensus().await;
        let success = loop {
            info!("Waiting for PhaseLock event");
            let event = events.next().await.expect("PhaseLock unexpectedly closed");

            match event.event {
                EventType::Decide { block: _, state } => {
                    if !state.is_empty() {
                        let commitment = TaggedBase64::new("COMM", state[0].commit().as_ref())
                            .unwrap()
                            .to_string();
                        info!("  - Round {} completed. Commitment: {}", round, commitment);
                        final_commitment = commitment;
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
            // current node), and there is no attached wallet.
            if let Some((ix, keys_and_memos, sig, t)) = core::mem::take(&mut txn) {
                info!("  - Adding the transaction");
                let mut blk = ElaboratedBlock::default();
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                // If we're running a full node, publish the receiver memos.
                if let Node::Full(node) = &mut phaselock {
                    node.write()
                        .await
                        .post_memos(round, ix as u64, owner_memos.clone(), sig)
                        .await
                        .unwrap();
                }

                state
                    .try_add_transaction(
                        &mut blk,
                        t,
                        ix,
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
    if !final_commitment.is_empty() {
        println!(
            // THINK TWICE BEFORE CHANGING THIS
            "Final commitment: {}",
            final_commitment
        );
    }
    // !!!!!! END WARNING !!!!!!!
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Get configuration
    let options = Options::from_args();
    let config_path = options.config.unwrap_or_else(default_config_path);
    let config = ConsensusConfig::from_file(&config_path);

    // Override the path to the universal parameter file if it's specified
    if let Some(dir) = options.universal_param_path.as_ref() {
        std::env::set_var("UNIVERSAL_PARAM_PATH", dir);
    }

    if options.gen_pk {
        gen_pub_keys(&options.node_opt, &config);
    }

    // TODO !nathan.yospe, jeb.bearer - add option to reload vs init
    let load_from_store = options.node_opt.load_from_store;
    if load_from_store {
        info!("restoring from persisted session");
    } else {
        info!("initializing new session");
    }

    if let Some(own_id) = options.id {
        // Initialize the state and phaselock
        let (genesis, state) = if options.num_txn.is_some() {
            // If we are going to generate transactions, we need to initialize the ledger with a
            // test state.
            let (genesis, state) = GenesisState::new_for_test();
            (genesis, Some(state))
        } else {
            (
                GenesisState::new(
                    &mut ChaChaRng::from_entropy(),
                    options.faucet_pub_key.clone(),
                ),
                None,
            )
        };
        let phaselock = init_validator(&options.node_opt, &config, genesis, own_id as usize).await;

        // If we are running a full node, also host a query API to inspect the accumulated state.
        let web_server = if let Node::Full(node) = &phaselock {
            Some(
                init_web_server(&options.node_opt, own_id, node.clone())
                    .expect("Failed to initialize web server"),
            )
        } else {
            None
        };

        // !!!!!!     WARNING !!!!!!!
        // If the output below is changed, update the message for line.trim() in Validator::new as well
        println!(/* THINK TWICE BEFORE CHANGING THIS */ "  - Starting consensus");
        // !!!!!! END WARNING !!!!!!!

        if let Some(num_txn) = options.num_txn {
            generate_transactions(num_txn, own_id, phaselock, state.unwrap()).await;
        } else {
            phaselock.start_consensus().await;

            // Wait for transactions to be submitted
            let mut events = phaselock.subscribe();
            while let Some(event) = events.next().await {
                match event.event {
                    EventType::Decide { block: _, state } => {
                        if !state.is_empty() {
                            let commitment = TaggedBase64::new("COMM", state[0].commit().as_ref())
                                .unwrap()
                                .to_string();
                            info!(". - Committed state {}", commitment);
                        }
                    }
                    EventType::ViewTimeout { view_number } => {
                        info!("  - Round {} timed out.", view_number);
                    }
                    EventType::Error { error } => {
                        info!("  - Phaselock error: {}", error);
                    }
                    _ => {
                        info!("EVENT: {:?}", event);
                    }
                }
            }
        }

        if options.wait {
            if let Some(join_handle) = web_server {
                join_handle.await.unwrap_or_else(|err| {
                    panic!("web server exited with an error: {}", err);
                });
            }
        }
    }

    Ok(())
}
