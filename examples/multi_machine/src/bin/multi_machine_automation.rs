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
    /// Path to the node configuration file.
    #[structopt(
        long = "config",
        short = "c",
        default_value = ""      // See fn default_config_path().
    )]
    config: String,

    /// Path to the universal parameter file.
    #[structopt(long = "universal_param_path", short = "u")]
    universal_param_path: Option<String>,

    /// Whether to generate and store public keys for all nodes.
    ///
    /// Public keys will be stored under the directory specified by `pk_path`.
    ///
    /// Skip this option if public key files already exist.
    #[structopt(long = "gen_pk", short = "g")]
    gen_pk: bool,

    /// Whether to load from persisted state.
    ///
    #[structopt(long = "load_from_store", short = "l")]
    load_from_store: bool,

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

    /// Path to persistence files.
    ///
    /// Persistence files will be nested under the specified directory
    #[structopt(
        long = "store_path", 
        short = "s", 
        default_value = ""      // See fn default_store_path().
    )]
    store_path: String,

    /// Whether the current node should run a full node.
    #[structopt(long = "full", short = "f")]
    full: bool,

    /// Path to assets including web server files.
    #[structopt(
        long = "assets",
        default_value = ""      // See fn default_web_path().
    )]
    web_path: String,

    /// Path to API specification and messages.
    #[structopt(
        long = "api",
        default_value = ""      // See fn default_api_path().
    )]
    api_path: String,

    /// Use an external wallet to generate transactions.
    ///
    /// The argument is the path to the wallet's public key. If this option is given, the ledger
    /// will be initialized with a record of 2^32 native tokens, owned by the wallet's public key.
    /// The demo will then wait for the wallet to generate some transactions and submit them to the
    /// validators using the network API.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native token
    /// records for different wallets.
    #[structopt(short, long = "wallet")]
    wallet_pk_path: Option<Vec<PathBuf>>,

    /// Number of transactions to generate.
    ///
    /// Skip this option if want to keep generating transactions till the process is killed.
    #[structopt(long = "num_txn", short = "n")]
    num_txn: Option<u64>,

    /// Wait for web server to exit after transactions complete.
    #[structopt(long)]
    wait: bool,
}

#[async_std::main]
async fn main() {
    // Construct arguments to pass to the multi-machine demo.
    let config = NodeOpt::from_args().config;
    let gen_pk = NodeOpt::from_args().gen_pk.to_string();
    let load_from_store = NodeOpt::from_args().load_from_store.to_string();
    let pk_path = NodeOpt::from_args().pk_path;
    let store_path = NodeOpt::from_args().store_path;
    let full = NodeOpt::from_args().full.to_string();
    let web_path = NodeOpt::from_args().web_path;
    let api_path = NodeOpt::from_args().api_path;
    let wait = NodeOpt::from_args().wait.to_string();
    let mut args = vec![
        "--config",
        &config,
        "--gen_pk",
        &gen_pk,
        "--load_from_store",
        &load_from_store,
        "--pk_path",
        &pk_path,
        "--store_path",
        &store_path,
        "--full",
        &full,
        "--web_path",
        &web_path,
        "--api_path",
        &api_path,
        "--wait",
        &wait,
    ];
    let universal_param_path;
    if let Some(path) = NodeOpt::from_args().universal_param_path {
        universal_param_path = path;
        args.push("--universal_param_path");
        args.push(&universal_param_path);
    }
    let wallet_pk_path;
    if let Some(path) = NodeOpt::from_args().wallet_pk_path {
        wallet_pk_path = format!("{:?}", path);
        args.push("--wallet_pk_path");
        args.push(&wallet_pk_path);
    }
    let num_txn;
    if let Some(num) = NodeOpt::from_args().num_txn {
        num_txn = num.to_string();
        args.push("--num_txn");
        args.push(&num_txn);
    }

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
            let mut this_args = args.clone();
            let id_str = id.to_string();
            this_args.push("--id");
            this_args.push(&id_str);
            (
                id,
                Command::new("./multi_machine")
                    .args(this_args)
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap_or_else(|_| {
                        panic!("Failed to start the multi_machine demo for node {}", id)
                    }),
            )
        })
        .collect();

    // Check each process.
    let mut commitment = "".to_string();
    let mut succeeded_nodes = 0;
    for (id, mut p) in processes {
        let process: Result<ExitStatus, _> = p.wait();
        process.unwrap_or_else(|_| panic!("Failed to run the multi_machine demo for node {}", id));
        let mut stdout: BufReader<ChildStdout> = BufReader::new(p.stdout.take().unwrap());
        let mut line = String::new();
        // Check whether the commitments are the same.
        if let Some(num_txn) = NodeOpt::from_args().num_txn {
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
    }

    // Check whether the number of succeeded nodes meets the threshold.
    let threshold = ((num_nodes * 2) / 3) + 1;
    assert!(succeeded_nodes >= threshold);
    println!("Consensus completed for all nodes")
}
