// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use async_std::task::{sleep, spawn_blocking};
use clap::Parser;
use escargot::CargoBuild;
use espresso_esqs::full_node;
use espresso_validator::{div_ceil, NodeOpt, QUORUM_THRESHOLD, STAKE_PER_NODE};
use std::env;
use std::io::{BufRead, BufReader};
use std::process::{exit, Command, Stdio};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "Multi-machine consensus automation",
    about = "Automates the consensus among multiple machines"
)]
struct Options {
    #[command(flatten)]
    node_opt: NodeOpt,

    /// Number of transactions to generate.
    ///
    /// If this option is provided, runs the `espresso-validator-testing` executable to generate
    /// transactions. Otherwise, runs the `espresso-validator` executable and waits for externally
    /// submitted transactions.
    #[arg(long, short, conflicts_with("faucet-pub-key"))]
    pub num_txns: Option<u64>,

    #[arg(long, short)]
    verbose: bool,

    /// Number of nodes to run only `fail_after_txn` rounds.
    ///
    /// If not provided, all nodes will keep running till `num_txns` rounds are completed.
    #[arg(long)]
    num_fail_nodes: Option<usize>,

    /// Number of rounds that all nodes will be running, after which `num_fail_nodes` nodes will be
    /// killed.
    ///
    /// If not provided, all nodes will keep running till `num_txns` rounds are completed.
    #[arg(long, requires("num-fail-nodes"))]
    fail_after_txn: Option<usize>,
}

fn cargo_run(bin: impl AsRef<str>) -> Command {
    CargoBuild::new()
        .bin(bin.as_ref())
        .current_release()
        .run()
        .expect("Failed to build.")
        .command()
}

#[async_std::main]
async fn main() {
    // Construct arguments to pass to the multi-machine demo.
    let options = Options::parse();
    if let Err(msg) = options.node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }

    // With clap, environment variables override command line arguments, but we are going
    // to construct a command line for each child, so the child processes shouldn't get their
    // options from the environment. Clear the environment variables corresponding to each option
    // that we will set explicitly in the command line.
    env::remove_var("ESPRESSO_VALIDATOR_ID");
    env::remove_var("ESPRESSO_VALIDATOR_SECRET_KEY_SEED");
    env::remove_var("ESPRESSO_VALIDATOR_BOOTSTRAP_NODES");
    env::remove_var("ESPRESSO_VALIDATOR_PUB_KEY_PATH");
    env::remove_var("ESPRESSO_FAUCET_PUB_KEY");
    env::remove_var("ESPRESSO_VALIDATOR_STORE_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_WEB_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_API_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_QUERY_PORT");
    env::remove_var("ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME");
    env::remove_var("ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME");
    env::remove_var("ESPRESSO_VALIDATOR_NEXT_VIEW_TIMEOUT");
    env::remove_var("ESPRESSO_VALIDATOR_TIMEOUT_RATIO");
    env::remove_var("ESPRESSO_VALIDATOR_ROUND_START_DELAY");
    env::remove_var("ESPRESSO_VALIDATOR_START_DELAY");
    env::remove_var("ESPRESSO_VALIDATOR_MAX_TRANSACTIONS");
    env::remove_var("ESPRESSO_VALIDATOR_NONBOOTSTRAP_PORT");

    let mut args = vec![];
    if options.node_opt.reset_store_state {
        args.push("--reset-store-state");
    }
    let store_path;
    if let Some(path) = &options.node_opt.store_path {
        store_path = path.display().to_string();
        args.push("--store-path");
        args.push(&store_path);
    }
    let cdn;
    if let Some(url) = &options.node_opt.cdn {
        if url.host_str() != Some("localhost") {
            panic!(
                "for automated local testing, CDN host must be `localhost' \
                (note that a scheme is required for URL parsing, e.g. tcp://localhost:80)"
            );
        }
        cdn = url.to_string();
        args.push("--cdn");
        args.push(&cdn);
    }
    if options.node_opt.libp2p {
        args.push("--libp2p");
    }
    let min_propose_time = format!("{}ms", options.node_opt.min_propose_time.as_millis());
    args.push("--min-propose-time");
    args.push(&min_propose_time);
    let max_propose_time = format!("{}ms", options.node_opt.max_propose_time.as_millis());
    args.push("--max-propose-time");
    args.push(&max_propose_time);
    let next_view_timeout = format!("{}ms", options.node_opt.next_view_timeout.as_millis());
    args.push("--next-view-timeout");
    args.push(&next_view_timeout);
    let timeout_ratio = options.node_opt.timeout_ratio.to_string();
    args.push("--timeout-ratio");
    args.push(&timeout_ratio);
    let round_start_delay = format!("{}ms", options.node_opt.round_start_delay.as_millis());
    args.push("--round-start-delay");
    args.push(&round_start_delay);
    let start_delay = format!("{}ms", options.node_opt.start_delay.as_millis());
    args.push("--start-delay");
    args.push(&start_delay);
    let max_transactions = options.node_opt.max_transactions.to_string();
    args.push("--max-transactions");
    args.push(&max_transactions);
    let num_nodes_str = options.node_opt.num_nodes.to_string();
    let num_nodes = num_nodes_str.parse::<usize>().unwrap();
    let faucet_pub_keys = options
        .node_opt
        .faucet_pub_key
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>();
    for pub_key in &faucet_pub_keys {
        args.push("--faucet-pub-key");
        args.push(pub_key);
    }

    let (num_txn_str, exe) = match options.num_txns {
        Some(num_txns) => (num_txns.to_string(), "espresso-validator-testing"),
        None => ("".to_string(), "espresso-validator"),
    };
    let (num_fail_nodes, fail_after_txn_str) = match options.num_fail_nodes {
        Some(num_fail_nodes) => {
            assert!(num_fail_nodes <= num_nodes);
            if num_fail_nodes == 0 {
                (0, "".to_string())
            } else {
                let fail_after_txn_str = options
                    .fail_after_txn
                    .expect("`fail-after-txn` isn't specified when `num-failed-nodes` is nonzero")
                    .to_string();
                (num_fail_nodes, fail_after_txn_str)
            }
        }
        None => (0, "".to_string()),
    };

    // Start a CDN server if one is required.
    let cdn = options.node_opt.cdn.as_ref().map(|url| {
        let port = url.port_or_known_default().unwrap().to_string();
        let num_nodes = options.node_opt.num_nodes.to_string();
        let mut cdn_args = vec!["-p", &port, "-n", &num_nodes];
        if !options.node_opt.libp2p {
            // If we're not using libp2p (we're just using the CDN for networking) we don't need a
            // long startup delay, because as soon as all the nodes join the CDN, the network is
            // ready.
            cdn_args.push("--start-delay");
            cdn_args.push("5s");
        }
        if options.verbose {
            println!("cdn-server {}", cdn_args.join(" "));
        }
        let mut process = cargo_run("cdn-server")
            .args(cdn_args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start the CDN");
        let mut stdout = BufReader::new(process.stdout.take().unwrap());
        let verbose = options.verbose;

        // Collect output from the process as it runs. If we don't do this eagerly, the CDN can
        // block when its output pipe fills up causing deadlock.
        spawn_blocking(move || loop {
            let mut line = String::new();
            if stdout
                .read_line(&mut line)
                .expect("Failed to read stdout for CDN")
                == 0
            {
                break;
            }
            if verbose {
                print!("[CDN] {}", line);
            }
        });

        process
    });

    // Start the consensus for each node.
    let first_fail_id = num_nodes - num_fail_nodes;
    let mut processes: Vec<_> = (0..num_nodes)
        .map(|id| {
            let mut this_args = args.clone();
            let id_str = id.to_string();
            this_args.push("--id");
            // Use `id_str` rather than `node_opt.id` since the latter is arbitrarily set as 0.
            this_args.push(&id_str);
            this_args.push("--num-nodes");
            this_args.push(&num_nodes_str);
            if id >= first_fail_id {
                this_args.push("--num-txns");
                this_args.push(&fail_after_txn_str);
            } else if !num_txn_str.is_empty() {
                this_args.push("--num-txns");
                this_args.push(&num_txn_str);
            }
            let mut esqs_args = vec![];
            if let Some(full_node::Command::Esqs(opt)) = &options.node_opt.esqs {
                esqs_args = vec!["esqs".to_string(), "-p".to_string(), opt.port.to_string()];
                if let Some(path) = &opt.metastate.api_path {
                    esqs_args.push("--metastate-api-path".to_string());
                    esqs_args.push(path.display().to_string());
                }
                if let Some(path) = &opt.status.api_path {
                    esqs_args.push("--status-api-path".to_string());
                    esqs_args.push(path.display().to_string());
                }
            }
            for arg in &esqs_args {
                this_args.push(arg);
            }
            if options.verbose {
                println!("{} {}", exe, this_args.join(" "));
            }
            (
                id,
                cargo_run(exe)
                    .args(this_args)
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap_or_else(|_| panic!("Failed to start the validator for node {}", id)),
            )
        })
        .collect();

    // Collect output from each process as they run. If we don't do this eagerly, validators can
    // block when their output pipes fill up causing deadlock.
    let mut outputs = processes
        .iter_mut()
        .map(|(id, p)| {
            let mut stdout = BufReader::new(p.stdout.take().unwrap());
            let id = *id;
            let verbose = options.verbose;
            spawn_blocking(move || {
                let mut lines = Vec::new();
                let mut line = String::new();
                loop {
                    if stdout
                        .read_line(&mut line)
                        .unwrap_or_else(|_| panic!("Failed to read stdout for node {}", id))
                        == 0
                    {
                        break;
                    }
                    if verbose {
                        print!("[{}] {}", id, line);
                    }
                    lines.push(std::mem::take(&mut line));
                }
                lines
            })
        })
        .collect::<Vec<_>>();

    // Check each process.
    let mut commitment = None;
    let mut succeeded_nodes = 0;
    let mut finished_nodes = 0;
    let threshold = div_ceil!(QUORUM_THRESHOLD, STAKE_PER_NODE) as usize;
    let expect_failure = num_fail_nodes as usize > num_nodes - threshold;
    println!(
        "Waiting for validators to finish ({}/{}/{})",
        num_nodes, num_fail_nodes, threshold
    );
    while succeeded_nodes < threshold && finished_nodes < num_nodes {
        // If the consensus is expected to fail, not all processes will complete.
        if expect_failure && (finished_nodes >= num_fail_nodes as usize) {
            break;
        }
        // Pause before checking the exit status.
        sleep(Duration::from_secs(10)).await;
        for ((id, mut p), output) in core::mem::take(&mut processes)
            .into_iter()
            .zip(core::mem::take(&mut outputs))
        {
            match p.try_wait() {
                Ok(Some(_)) => {
                    // Check whether the commitments are the same.
                    if options.num_txns.is_some() {
                        let lines = output.await;
                        if id < first_fail_id as usize {
                            for line in lines {
                                if line.starts_with("Final commitment:") {
                                    let strs: Vec<&str> = line.split(' ').collect();
                                    let final_commitment = strs.last().unwrap_or_else(|| {
                                        panic!("Failed to parse commitment for node {}", id)
                                    });
                                    println!(
                                        "Validator {} finished with commitment {}",
                                        id, final_commitment
                                    );
                                    if let Some(comm) = commitment.clone() {
                                        assert_eq!(comm, final_commitment.to_string());
                                    } else {
                                        commitment = Some(final_commitment.to_string());
                                    }
                                    succeeded_nodes += 1;
                                }
                            }
                        } else {
                            println!("Validator {} finished", id);
                        }
                    }
                    finished_nodes += 1;
                }
                Ok(None) => {
                    // Add back unfinished process and output.
                    processes.push((id, p));
                    outputs.push(output);
                }
                Err(e) => {
                    println!("Error attempting to wait for validator {}: {}", id, e);
                    // Add back unfinished process and output.
                    processes.push((id, p));
                    outputs.push(output);
                }
            }
        }
    }

    // Kill processes that are still running.
    for (id, mut p) in processes {
        p.kill()
            .unwrap_or_else(|_| panic!("Failed to kill node {}", id));
        p.wait()
            .unwrap_or_else(|_| panic!("Failed to wait for node {} to exit", id));
    }
    if let Some(mut p) = cdn {
        p.kill().expect("Failed to kill CDN");
        p.wait().expect("failed to wait for CDN to exit");
    }

    // Check whether the number of succeeded nodes meets the threshold.
    assert!(succeeded_nodes >= threshold);
    println!("Consensus completed for all nodes")
}

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use super::*;
    use portpicker::pick_unused_port;
    use std::time::Instant;

    async fn automate(
        num_nodes: u64,
        num_txns: u64,
        num_fail_nodes: u64,
        fail_after_txn: u64,
        expect_success: bool,
        libp2p: bool,
    ) {
        println!(
            "Testing {} txns with {}/{} nodes failed after txn {}",
            num_txns, num_fail_nodes, num_nodes, fail_after_txn
        );
        // Views slow down as we add more nodes. This is a safe formula that allows ample time
        // without overly slowing down the test.
        let num_nodes = &num_nodes.to_string();
        let num_txns = &num_txns.to_string();
        let num_fail_nodes = &num_fail_nodes.to_string();
        let fail_after_txn = &fail_after_txn.to_string();
        let cdn_port = pick_unused_port().unwrap();
        let cdn_url = &format!("tcp://localhost:{}", cdn_port);
        // Set a fairly short view timeout by default (so that tests with leader failure don't take
        // too long) but allow this to be overridden in the environment, so that we can test a slow
        // target (like the coverage target) and still complete views within the timeout.
        let next_view_timeout =
            env::var("ESPRESSO_TEST_VIEW_TIMEOUT").unwrap_or_else(|_| "30s".to_string());
        // Set a fairly short timeout for proposing empty blocks by default. Each transaction we
        // propose requires 2 empty blocks to be committed. Allow this to be overridden in the
        // environment so that we can test a slow target without transactions becoming invalidated
        // faster than we can build them.
        let max_propose_time =
            env::var("ESPRESSO_TEST_MAX_PROPOSE_TIME").unwrap_or_else(|_| "10s".to_string());
        let mut args = vec![
            // Set an arbitrary ID. The automation code will use IDs from 0 to `num_nodes - 1` to
            // run the validator executable.
            "--id",
            "0",
            "--cdn",
            cdn_url,
            "--num-nodes",
            num_nodes,
            "--num-txns",
            num_txns,
            "--num-fail-nodes",
            num_fail_nodes,
            "--fail-after-txn",
            fail_after_txn,
            // Set the shortest possible rounds. Since we only propose one transaction at a time in
            // this test, we want the leader to propose a block as soon as they get a transaction.
            "--min-propose-time",
            "0s",
            "--min-transactions",
            "1",
            "--max-propose-time",
            &max_propose_time,
            "--next-view-timeout",
            &next_view_timeout,
            "--reset-store-state",
            "--verbose",
        ];
        if libp2p {
            args.push("--libp2p");
        }
        let now = Instant::now();
        let status = cargo_run("multi-machine-automation")
            .args(args)
            .status()
            .expect("Failed to execute the multi-machine automation");
        println!(
            "Completed {} txns in {} s",
            num_txns,
            now.elapsed().as_secs_f32()
        );
        assert_eq!(expect_success, status.success());
    }

    // This test is disabled until the libp2p networking implementation is fixed.
    #[async_std::test]
    async fn test_automation_libp2p() {
        automate(7, 5, 1, 3, true, true).await;
        automate(7, 5, 3, 1, false, true).await;
        automate(11, 2, 0, 0, true, true).await;

        // Disabling the following test cases to avoid exceeding the time limit.
        // automate(5, 0, 0, true).await;
        // automate(5, 2, 2, true).await;
        // automate(50, 2, 10, true).await;
    }

    #[async_std::test]
    async fn test_automation_cdn() {
        automate(7, 5, 1, 3, true, false).await;
        automate(7, 5, 3, 1, false, false).await;
        automate(11, 2, 0, 0, true, false).await;
    }
}
