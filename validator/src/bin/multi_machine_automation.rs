use async_std::task::spawn_blocking;
use escargot::CargoBuild;
use espresso_validator::{project_path, ConsensusConfig, NodeOpt};
use jf_cap::keys::UserPubKey;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "Multi-machine consensus",
    about = "Simulates consensus among multiple machines"
)]
struct Options {
    #[structopt(flatten)]
    node_opt: NodeOpt,

    /// Path to the node configuration file.
    #[structopt(long, short)]
    pub config: Option<PathBuf>,

    /// Path to the universal parameter file.
    #[structopt(long, short)]
    pub universal_param_path: Option<PathBuf>,

    /// Path to public keys.
    ///
    /// Public keys will be stored under the specified directory, file names starting
    /// with `pk_`.
    #[structopt(long, short)]
    pub pk_path: Option<PathBuf>,

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
    #[structopt(long)]
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
    let universal_param_path;
    if let Some(path) = &options.universal_param_path {
        universal_param_path = path.display().to_string();
        args.push("--universal-param-path");
        args.push(&universal_param_path);
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
    let (num_fail_nodes, fail_after_txn_str) = match options.num_fail_nodes {
        Some(num_fail_nodes) => {
            let fail_after_txn_str = options
                .fail_after_txn
                .expect("`fail_after_txn` isn't specified when `num_failed_nodes` is.")
                .to_string();
            (num_fail_nodes, fail_after_txn_str)
        }
        None => (0, "".to_string()),
    };

    // Read node info from node configuration file.
    let num_nodes = match &options.config {
        None => 7,
        Some(path) => ConsensusConfig::from_file(path).nodes.len(),
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
    let outputs = processes
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
    let mut commitment = "".to_string();
    let mut succeeded_nodes = 0;
    for ((id, mut p), output) in processes.into_iter().zip(outputs) {
        println!("waiting for validator {}", id);
        let process: Result<ExitStatus, _> = p.wait();
        process.unwrap_or_else(|_| panic!("Failed to run the validator for node {}", id));
        // Check whether the commitments are the same.
        if options.num_txn.is_some() {
            let lines = output.await;
            if id < first_fail_id as usize {
                for line in lines {
                    if line.starts_with("Final commitment:") {
                        let strs: Vec<&str> = line.split(' ').collect();
                        let comm = strs.last().unwrap_or_else(|| {
                            panic!("Failed to parse commitment for node {}", id)
                        });
                        println!("Validator {} finished with commitment {}", id, comm);
                        if commitment.is_empty() {
                            commitment = comm.to_string();
                        } else {
                            assert_eq!(comm, &commitment);
                        }
                        succeeded_nodes += 1;
                        break;
                    }
                }
            }
        }
    }

    // Check whether the number of succeeded nodes meets the threshold.
    let threshold = ((num_nodes * 2) / 3) + 1;
    assert!(succeeded_nodes >= threshold);
    println!("Consensus completed for all nodes")
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Instant;

    async fn automate(
        num_txn: u64,
        num_fail_nodes: u64,
        fail_after_txn: u64,
        expect_success: bool,
    ) {
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
    async fn test_small_fail_none() {
        automate(5, 0, 0, true).await;
    }

    #[async_std::test]
    async fn test_large_fail_none() {
        automate(50, 0, 0, true).await;
    }

    #[async_std::test]
    async fn test_small_fail_one() {
        automate(5, 1, 3, true).await;
    }

    #[async_std::test]
    async fn test_small_fail_some() {
        automate(5, 2, 2, true).await;
    }

    #[async_std::test]
    async fn test_small_fail_many() {
        automate(5, 3, 1, false).await;
    }

    // #[async_std::test]
    // async fn test_large_fail_some() {
    //     automate(50, 1, 1, true).await;
    //     // automate(5, 2, 2, true).await;
    // }
}
