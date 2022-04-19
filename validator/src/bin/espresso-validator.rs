// Copyright © 2021 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]

use espresso_validator::*;
use futures::StreamExt;
use phaselock::types::EventType;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use tracing::info;
use zerok_lib::{
    node::{QueryService, Validator},
    state::{ElaboratedBlock, ElaboratedTransaction},
    testing::TxnPrintInfo,
};

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Get configuration
    let options = NodeOpt::from_args();
    let node_config = get_node_config(&options);

    // Override the path to the universal parameter file if it's specified
    if let Some(dir) = options.universal_param_path.as_ref() {
        std::env::set_var("UNIVERSAL_PARAM_PATH", dir);
    }

    if options.gen_pk {
        gen_pub_keys(&options, &node_config);
    }

    // TODO !nathan.yospe, jeb.bearer - add option to reload vs init
    let load_from_store = options.load_from_store;
    if load_from_store {
        info!("restoring from persisted session");
    } else {
        info!("initializing new session");
    }

    if let Some(own_id) = options.id {
        // Initialize the state and phaselock
        let (mut state, mut phaselock) = init_validator(&options, &node_config, own_id).await;
        let mut events = phaselock.subscribe();

        // If we are running a full node, also host a query API to inspect the accumulated state.
        let web_server = if let Node::Full(node) = &phaselock {
            Some(
                init_web_server(&options, own_id, node.clone())
                    .expect("Failed to initialize web server"),
            )
        } else {
            None
        };

        #[cfg(target_os = "linux")]
        let bytes_per_page = procfs::page_size().unwrap() as u64;
        #[cfg(target_os = "linux")]
        debug!("{} bytes per page", bytes_per_page);

        let fence = || std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        let report_mem = || {
            fence();
            #[cfg(target_os = "linux")]
            {
                let process_stats = procfs::process::Process::myself().unwrap().statm().unwrap();
                debug!(
                    "{:.3}MiB | raw: {:?}",
                    ((process_stats.size * bytes_per_page) as f64) / ((1u64 << 20) as f64),
                    process_stats
                );
            }
            fence();
        };

        // Start consensus for each transaction
        let mut round = 0;
        let mut succeeded_rounds = 0;
        let num_txn = options.num_txn;

        // When `num_txn` is set, run `num_txn` rounds.
        // Otherwise, keeping running till the process is killed.
        let mut txn: Option<(usize, _, _, ElaboratedTransaction)> = None;
        let mut txn_proposed_round = 0;
        while num_txn
            .map(|count| succeeded_rounds < count)
            .unwrap_or(true)
        {
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
                } else if let Some(mut true_state) = core::mem::take(&mut state) {
                    info!("  - Proposing a transaction");
                    let (true_state, mut transactions) =
                        async_std::task::spawn_blocking(move || {
                            let txs = true_state
                                .generate_transactions(
                                    vec![(true, 0, 0, 0, 0, -2)],
                                    TxnPrintInfo::new_no_time(round as usize, 1),
                                )
                                .unwrap();
                            (true_state, txs)
                        })
                        .await;
                    txn = Some(transactions.remove(0));
                    state = Some(true_state);
                    phaselock
                        .submit_transaction(txn.clone().unwrap().3)
                        .await
                        .unwrap();
                    txn_proposed_round = round;
                }
            }

            // !!!!!!     WARNING !!!!!!!
            // If the output below is changed, update the message for line.trim() in Validator::new as well
            println!(/* THINK TWICE BEFORE CHANGING THIS */ "  - Starting consensus");
            // !!!!!! END WARNING !!!!!!!
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
                            succeeded_rounds += 1;
                            // !!!!!!     WARNING !!!!!!!
                            // If the output below is changed, update the message for main() in
                            // src/multi_machine_automation.rs as well
                            println!(
                                /* THINK TWICE BEFORE CHANGING THIS */
                                "  - Round {} completed. Commitment: {}",
                                succeeded_rounds, commitment
                            );
                            // !!!!!! END WARNING !!!!!!!
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
                    let state = state.as_mut().unwrap();
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

        info!("All rounds completed");

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
