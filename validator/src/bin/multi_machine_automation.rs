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

use async_std::task::{sleep, spawn_blocking};
use escargot::CargoBuild;
use espresso_validator::{ConsensusConfig, NodeOpt, SecretKeySeed};
use jf_cap::keys::UserPubKey;
use std::env;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use structopt::StructOpt;
use tide::http::Url;

#[derive(StructOpt)]
#[structopt(
    name = "Multi-machine consensus",
    about = "Simulates consensus among multiple machines"
)]
struct Options {
    #[structopt(flatten)]
    node_opt: NodeOpt,

    /// Path to the node configuration file.
    #[structopt(long, short, env = "ESPRESSO_VALIDATOR_CONFIG_PATH")]
    pub config: Option<PathBuf>,

    /// Override `seed` from the node configuration file.
    #[structopt(long, env = "ESPRESSO_VALIDATOR_SECRET_KEY_SEED")]
    pub secret_key_seed: Option<SecretKeySeed>,

    /// Override `nodes` from the node configuration file.
    #[structopt(long, env = "ESPRESSO_VALIDATOR_NODES", value_delimiter = ",")]
    pub nodes: Option<Vec<Url>>,

    /// Path to public keys.
    ///
    /// Public keys will be stored under the specified directory, file names starting
    /// with `pk_`.
    #[structopt(long, short, env = "ESPRESSO_VALIDATOR_PUB_KEY_PATH")]
    pub pk_path: Option<PathBuf>,

    /// Public key which should own a faucet record in the genesis block.
    ///
    /// For each given public key, the ledger will be initialized with a record of 2^32 native
    /// tokens, owned by the public key.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native
    /// token records.
    #[structopt(long, env = "ESPRESSO_FAUCET_PUB_KEYS", value_delimiter = ",")]
    pub faucet_pub_key: Vec<UserPubKey>,

    /// Number of transactions to generate.
    ///
    /// If not provided, the validator will wait for externally submitted transactions.
    #[structopt(long, short, conflicts_with("faucet-pub-key"))]
    pub num_txn: Option<u64>,

    /// Wait for web server to exit after transactions complete.
    #[structopt(long, short)]
    pub wait: bool,

    #[structopt(long, short)]
    verbose: bool,

    /// Number of nodes to run only `fail_after_txn` rounds.
    ///
    /// If not provided, all nodes will keep running till `num_txn` rounds are completed.
    #[structopt(long)]
    num_fail_nodes: Option<u64>,

    /// Number of rounds that all nodes will be running, after which `num_fail_nodes` nodes will be
    /// killed.
    ///
    /// If not provided, all nodes will keep running till `num_txn` rounds are completed.
    #[structopt(long, requires("num-fail-nodes"))]
    fail_after_txn: Option<u64>,
}

fn cargo_run(bin: impl AsRef<str>) -> Command {
    CargoBuild::new()
        .bin(bin.as_ref())
        .current_release()
        .current_target()
        .run()
        .expect("Failed to build.")
        .command()
}

#[async_std::main]
async fn main() {
    // Construct arguments to pass to the multi-machine demo.
    let options = Options::from_args();

    // With StructOpt/CLAP, environment variables override command line arguments, but we are going
    // to construct a command line for each child, so the child processes shouldn't get their
    // options from the environment. Clear the environment variables corresponding to each option
    // that we will set explicitly in the command line.
    env::remove_var("ESPRESSO_VALIDATOR_CONFIG_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_SECRET_KEY_SEED");
    env::remove_var("ESPRESSO_VALIDATOR_NODES");
    env::remove_var("ESPRESSO_VALIDATOR_PUB_KEY_PATH");
    env::remove_var("ESPRESSO_FAUCET_PUB_KEY");
    env::remove_var("ESPRESSO_VALIDATOR_STORE_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_WEB_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_API_PATH");
    env::remove_var("ESPRESSO_VALIDATOR_PORT");

    let mut args = vec![];
    if options.node_opt.reset_store_state {
        args.push("--reset-store-state");
    }
    if options.node_opt.full {
        args.push("--full");
    }
    if options.wait {
        args.push("--wait");
    }
    let store_path;
    if let Some(path) = &options.node_opt.store_path {
        store_path = path.display().to_string();
        args.push("--store-path");
        args.push(&store_path);
    }
    let web_path;
    if let Some(path) = &options.node_opt.web_path {
        web_path = path.display().to_string();
        args.push("--assets");
        args.push(&web_path);
    }
    let api_path;
    if let Some(path) = &options.node_opt.api_path {
        api_path = path.display().to_string();
        args.push("--api");
        args.push(&api_path);
    }
    let config_path;
    if let Some(path) = &options.config {
        config_path = path.display().to_string();
        args.push("--config");
        args.push(&config_path);
    }
    let secret_key_seed;
    if let Some(seed) = &options.secret_key_seed {
        secret_key_seed = seed.to_string();
        args.push("--secret-key-seed");
        args.push(&secret_key_seed);
    }
    let nodes = options.nodes.as_ref().map(|nodes| {
        nodes
            .iter()
            .map(|node| node.to_string())
            .collect::<Vec<_>>()
            .join(",")
    });
    if let Some(nodes) = &nodes {
        args.push("--nodes");
        args.push(nodes);
    }
    let pk_path;
    if let Some(path) = &options.pk_path {
        pk_path = path.display().to_string();
        args.push("--pk-path");
        args.push(&pk_path);
    }
    let faucet_pub_keys = options
        .faucet_pub_key
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>();
    for pub_key in &faucet_pub_keys {
        args.push("--faucet-pub-key");
        args.push(pub_key);
    }
    let num_txn_str = match options.num_txn {
        Some(num_txn) => num_txn.to_string(),
        None => "".to_string(),
    };

    // Read node info from node configuration file.
    let num_nodes = match &options.nodes {
        Some(nodes) => nodes.len(),
        None => match &options.config {
            Some(path) => ConsensusConfig::from_file(path).nodes.len(),
            None => 7,
        },
    };
    let (num_fail_nodes, fail_after_txn_str) = match options.num_fail_nodes {
        Some(num_fail_nodes) => {
            assert!(num_fail_nodes <= num_nodes as u64);
            if num_fail_nodes == 0 {
                (0, "".to_string())
            } else {
                let fail_after_txn_str = options
                    .fail_after_txn
                    .expect("`fail_after_txn` isn't specified when `num_failed_nodes` is nonzero.")
                    .to_string();
                (num_fail_nodes, fail_after_txn_str)
            }
        }
        None => (0, "".to_string()),
    };

    // Start the consensus for each node.
    let first_fail_id = num_nodes - num_fail_nodes as usize;
    let mut processes: Vec<_> = (0..num_nodes)
        .map(|id| {
            let mut this_args = args.clone();
            let id_str = id.to_string();
            this_args.push("--id");
            this_args.push(&id_str);
            if id >= first_fail_id as usize {
                this_args.push("--num-txn");
                this_args.push(&fail_after_txn_str);
            } else if !num_txn_str.is_empty() {
                this_args.push("--num-txn");
                this_args.push(&num_txn_str);
            }
            if options.verbose {
                println!("espresso-validator {}", this_args.join(" "));
            }
            (
                id,
                cargo_run("espresso-validator")
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
    let threshold = ((num_nodes * 2) / 3) + 1;
    let expect_failure = num_fail_nodes as usize > num_nodes - threshold;
    println!("Waiting for validators to finish");
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
                    if options.num_txn.is_some() {
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
                    println!("Validator {} failed: {}", id, e);
                    finished_nodes += 1;
                }
            }
        }
    }

    // Kill processes that are still running.
    for (id, mut p) in processes {
        p.kill()
            .unwrap_or_else(|_| panic!("Failed to kill node {}", id));
    }

    // Check whether the number of succeeded nodes meets the threshold.
    assert!(succeeded_nodes >= threshold);
    println!("Consensus completed for all nodes")
}

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use super::*;
    use std::time::Instant;

    async fn automate(
        num_txn: u64,
        num_fail_nodes: u64,
        fail_after_txn: u64,
        expect_success: bool,
    ) {
        println!(
            "Testing {} txns with {}/7 nodes failed after txn {}",
            num_txn, num_fail_nodes, fail_after_txn
        );
        let num_txn = &num_txn.to_string();
        let num_fail_nodes = &num_fail_nodes.to_string();
        let fail_after_txn = &fail_after_txn.to_string();
        let args = vec![
            "--num-txn",
            num_txn,
            "--num-fail-nodes",
            num_fail_nodes,
            "--fail-after-txn",
            fail_after_txn,
            "--reset-store-state",
            "--verbose",
        ];
        let now = Instant::now();
        let status = cargo_run("multi_machine_automation")
            .args(args)
            .status()
            .expect("Failed to execute the multi-machine automation");
        println!(
            "Completed {} txns in {} s",
            num_txn,
            now.elapsed().as_secs_f32()
        );
        assert_eq!(expect_success, status.success());
    }

    #[async_std::test]
    async fn test_automation() {
        automate(5, 1, 3, true).await;
        automate(5, 3, 1, false).await;

        // Disabling the following test cases to avoid exceeding the time limit.
        // automate(5, 0, 0, true).await;
        // automate(5, 2, 2, true).await;
        // automate(50, 2, 10, true).await;
    }
}
