use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{ChildStdout, Command, ExitStatus, Stdio};
use structopt::StructOpt;
use toml::Value;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Multi-machine consensus automation",
    about = "Simulates the multi-machine consensus with a single-command"
)]
struct NodeOpt {
    /// Number of transactions to generate.
    #[structopt(long = "num_txn", short = "n")]
    num_txn: u64,

    /// Path to the node configuration file.
    #[structopt(
                long = "config",
                short = "c",
                default_value = ""      // See fn default_config_path().
            )]
    config: String,

    /// Path to public keys.
    ///
    /// Public keys will be stored under the specified directory, file names starting
    /// with `pk_`.
    #[structopt(
                long = "pk_path", 
                short = "p", 
                default_value = ""      // See fn default_pk_path().
            )]
    pk_path: String,
}

#[async_std::main]
async fn main() {
    let num_txn = NodeOpt::from_args().num_txn;
    let config = NodeOpt::from_args().config;

    // Read node info from node configuration file.
    let num_nodes = if config.is_empty() {
        7
    } else {
        let path = PathBuf::from(&config);
        let mut config_str = String::new();
        File::open(&path)
            .expect("Failed to find node config file")
            .read_to_string(&mut config_str)
            .unwrap_or_else(|err| panic!("Failed to read node config file: {}", err));
        let node_config: Value =
            toml::from_str(&config_str).expect("Error while reading node config file");
        node_config["nodes"]
            .as_table()
            .expect("Missing nodes info")
            .len()
    };

    // Start the consensus for each node.
    let processes: Vec<_> = (0..num_nodes)
        .map(|id| {
            (
                id,
                Command::new("./multi_machine")
                    .args([
                        "--id",
                        &id.to_string(),
                        "--num_txn",
                        &num_txn.to_string(),
                        "--config",
                        &config,
                        "--pk_path",
                        &NodeOpt::from_args().pk_path,
                    ])
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap_or_else(|_| {
                        panic!("Failed to start the multi_machine demo for node {}", id)
                    }),
            )
        })
        .collect();

    // Check whether the commitments are the same.
    let mut commitment = "".to_string();
    let mut succeeded_nodes = 0;
    for (id, mut p) in processes {
        let process: Result<ExitStatus, _> = p.wait();
        process.unwrap_or_else(|_| panic!("Failed to run the multi_machine demo for node {}", id));
        let mut stdout: BufReader<ChildStdout> = BufReader::new(p.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            stdout
                .read_line(&mut line)
                .unwrap_or_else(|_| panic!("Failed to read stdout for node {}", id));
            let line = std::mem::take(&mut line);
            let trimmed_line = line.trim();
            if trimmed_line
                .trim()
                .starts_with(&format!("- Round {} completed. Commitment:", num_txn))
            {
                let strs: Vec<&str> = trimmed_line.split(' ').collect();
                let comm = strs
                    .last()
                    .unwrap_or_else(|| panic!("Failed to parse commitment for node {}", id));
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

    // Check whether the number of succeeded nodes meets the threshold.
    let threshold = ((num_nodes * 2) / 3) + 1;
    assert!(succeeded_nodes >= threshold);
    println!("Consensus completed for all nodes")
}
