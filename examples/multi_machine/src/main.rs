// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use phaselock::{
    event::EventType, message::Message, networking::w_network::WNetwork,
    traits::storage::memory_storage::MemoryStorage, PhaseLock, PhaseLockConfig, PubKey,
};
use rand_xoshiro::{rand_core::SeedableRng, Xoshiro256StarStar};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;
use std::io::{prelude::*, Read};
use std::path::Path;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;
use toml::Value;
use tracing::debug;
use zerok_lib::{
    node::*, ElaboratedBlock, ElaboratedTransaction, MultiXfrRecordSpec, MultiXfrTestState,
};

const STATE_SEED: [u8; 32] = [0x7au8; 32];
const TRANSACTION_COUNT: u64 = 3;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Multi-machine concensus",
    about = "Simulates consensus among multiple machines"
)]
struct NodeOpt {
    /// Path to the node configuration file.
    #[structopt(
        long = "config",
        short = "c",
        default_value = "../../examples/multi_machine/src/node-config.toml"
    )]
    config: String,

    /// Whether to generate and store public keys for all nodes.
    ///
    /// Public keys will be stored under `examples/multi_machine/src`, file names starting
    /// with `pk_`.
    ///
    /// Skip this option if public key files already exist.
    #[structopt(long = "generate_keys", short = "g")]
    generate_keys: bool,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    ///
    /// Skip this option if only want to generate public key files.
    #[structopt(long = "id", short = "i")]
    id: Option<u64>,

    /// Whether the current node should run a full node.
    #[structopt(long = "full", short = "f")]
    full: bool,
}

/// Gets public key of a node from its public key file.
fn get_public_key(node_id: u64) -> PubKey {
    let path_str = format!("../../examples/multi_machine/src/pk_{}", node_id);
    let path = Path::new(&path_str);
    let mut pk_file = File::open(&path)
        .unwrap_or_else(|_| panic!("Cannot find public key file: {}", path.display()));
    let mut pk_str = String::new();
    pk_file
        .read_to_string(&mut pk_str)
        .unwrap_or_else(|err| panic!("Error while reading public key file: {}", err));
    serde_json::from_str(&pk_str).expect("Error while reading public key")
}

/// Gets IP address and port number of a node from node configuration file.
fn get_host(node_config: Value, node_id: u64) -> (String, u16) {
    let node = &node_config["nodes"][node_id.to_string()];
    let ip = node["ip"].as_str().expect("Missing IP info").to_owned();
    let port = node["port"].as_integer().expect("Missing port info") as u16;
    (ip, port)
}

/// Trys to get a networking implementation with the given id and port number.
///
/// Also starts the background task.
async fn get_networking<
    T: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug + 'static,
>(
    node_id: u64,
    port: u16,
) -> (WNetwork<T>, PubKey) {
    let pub_key = get_public_key(node_id);
    debug!(?pub_key);
    let network = WNetwork::new(pub_key.clone(), port, None).await;
    if let Ok(n) = network {
        let (c, sync) = futures::channel::oneshot::channel();
        match n.generate_task(c) {
            Some(task) => {
                task.into_iter().for_each(|n| {
                    async_std::task::spawn(n);
                });
                sync.await.expect("sync.await failed");
            }
            None => {
                panic!("Failed to launch networking task");
            }
        }
        return (n, pub_key);
    }
    panic!("Failed to open a port");
}

/// Creates the initial state and phaselock for simulation.
async fn init_state_and_phaselock(
    public_keys: tc::PublicKeySet,
    secret_key_share: tc::SecretKeyShare,
    nodes: u64,
    threshold: u64,
    node_id: u64,
    networking: WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, 64>>,
    full_node: bool,
) -> (MultiXfrTestState, Box<dyn Validator>) {
    // Create the initial state
    let state = MultiXfrTestState::initialize(
        STATE_SEED,
        10,
        10,
        (
            MultiXfrRecordSpec {
                asset_def_ix: 0,
                owner_key_ix: 0,
                asset_amount: 100,
            },
            vec![
                MultiXfrRecordSpec {
                    asset_def_ix: 1,
                    owner_key_ix: 0,
                    asset_amount: 50,
                },
                MultiXfrRecordSpec {
                    asset_def_ix: 0,
                    owner_key_ix: 0,
                    asset_amount: 70,
                },
            ],
        ),
    )
    .unwrap();

    // Create the initial phaselock
    let known_nodes: Vec<_> = (0..nodes).map(get_public_key).collect();

    let config = PhaseLockConfig {
        total_nodes: nodes as u32,
        threshold: threshold as u32,
        max_transactions: 100,
        known_nodes,
        next_view_timeout: 10000,
        timeout_ratio: (11, 10),
        round_start_delay: 1,
    };
    debug!(?config);
    let genesis = ElaboratedBlock::default();
    let (_, phaselock) = PhaseLock::init(
        genesis,
        public_keys,
        secret_key_share,
        node_id,
        config,
        state.validator.clone(),
        networking,
        MemoryStorage::default(),
    )
    .await;
    debug!("phaselock launched");

    let validator = if full_node {
        Box::new(FullNode::new(phaselock, state.validator.clone(), state.nullifiers.clone()).await)
            as Box<dyn Validator>
    } else {
        Box::new(phaselock) as Box<dyn Validator>
    };

    (state, validator)
}

#[async_std::main]
async fn main() {
    // Setup tracing
    tracing_subscriber::fmt::init();

    // Read configuration file path and node id from options
    let config_path_str = NodeOpt::from_args().config;
    let path = Path::new(&config_path_str);

    // Read node info from node configuration file
    let mut config_file = File::open(&path)
        .unwrap_or_else(|_| panic!("Cannot find node config file: {}", path.display()));
    let mut config_str = String::new();
    config_file
        .read_to_string(&mut config_str)
        .unwrap_or_else(|err| panic!("Error while reading node config file: {}", err));
    let node_config: Value = toml::from_str(&config_str).expect("Error while reading node config");
    let seed = node_config["seed"]
        .as_integer()
        .expect("Missing seed value") as u64;
    let nodes = node_config["nodes"]
        .as_table()
        .expect("Missing nodes info")
        .len() as u64;
    let threshold = ((nodes * 2) / 3) + 1;

    // Generate key sets
    let mut rng = Xoshiro256StarStar::seed_from_u64(seed);
    let secret_keys = tc::SecretKeySet::random(threshold as usize - 1, &mut rng);
    let public_keys = secret_keys.public_keys();

    // Generate public key for each node
    if NodeOpt::from_args().generate_keys {
        for node_id in 0..nodes {
            let pub_key = PubKey::from_secret_key_set_escape_hatch(&secret_keys, node_id);
            let pub_key_str = serde_json::to_string(&pub_key)
                .unwrap_or_else(|err| panic!("Error while serializing the public key: {}", err));
            let mut pk_file =
                File::create(format!("../../examples/multi_machine/src/pk_{}", node_id))
                    .unwrap_or_else(|err| {
                        panic!("Error while creating a public key file: {}", err)
                    });
            pk_file
                .write_all(pub_key_str.as_bytes())
                .unwrap_or_else(|err| {
                    panic!("Error while writing to the public key file: {}", err)
                });
        }
        println!("Public key files created");
    }

    if let Some(own_id) = NodeOpt::from_args().id {
        println!("Current node: {}", own_id);
        let secret_key_share = secret_keys.secret_key_share(own_id);

        // Get networking information
        let (own_network, _) =
            get_networking(own_id, get_host(node_config.clone(), own_id).1).await;
        #[allow(clippy::type_complexity)]
        let mut other_nodes: Vec<(u64, PubKey, String, u16)> = Vec::new();
        for id in 0..nodes {
            if id != own_id {
                let (ip, port) = get_host(node_config.clone(), id);
                let pub_key = get_public_key(id);
                other_nodes.push((id, pub_key, ip, port));
            }
        }

        // Connect the networking implementations
        for (id, pub_key, ip, port) in other_nodes {
            let socket = format!("{}:{}", ip, port);
            while own_network
                .connect_to(pub_key.clone(), &socket)
                .await
                .is_err()
            {
                debug!("  - Retrying");
                async_std::task::sleep(std::time::Duration::from_millis(10_000)).await;
            }
            println!("  - Connected to node {}", id);
        }

        // Wait for the networking implementations to connect
        while (own_network.connection_table_size().await as u64) < nodes - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        println!("All nodes connected to network");

        // Initialize the state and phaselock
        let (mut state, phaselock) = init_state_and_phaselock(
            public_keys,
            secret_key_share,
            nodes,
            threshold,
            own_id,
            own_network,
            NodeOpt::from_args().full,
        )
        .await;
        let mut events = phaselock.subscribe().await;

        // Start consensus for each transaction
        for round in 0..TRANSACTION_COUNT {
            println!("Starting round {}", round + 1);

            // Generate a transaction if the node ID is 0
            let mut txn = None;
            if own_id == 0 {
                println!("  - Proposing a transaction");
                let mut transactions = state
                    .generate_transactions(
                        round as usize,
                        vec![(true, 0, 0, 0, 0, -2)],
                        TRANSACTION_COUNT as usize,
                    )
                    .unwrap();
                txn = Some(transactions.remove(0));
                phaselock
                    .submit_transaction(txn.clone().unwrap().2)
                    .await
                    .unwrap();
            }

            // Start consensus
            // Note: wait until the transaction is proposed before starting consensus. Otherwise,
            // the node will never reaches decision.
            // Issue: https://gitlab.com/translucence/systems/system/-/issues/15.
            let mut line = String::new();
            println!("Hit the return key when ready to start the consensus...");
            std::io::stdin().read_line(&mut line).unwrap();
            phaselock.start_consensus().await;
            println!("  - Starting consensus");
            loop {
                println!("Waiting for PhaseLock event");
                let event = events.next().await.expect("PhaseLock unexpectedly closed");

                if let EventType::Decide { block: _, state } = event.event {
                    let commitment = TaggedBase64::new("LEDG", &state.commit())
                        .unwrap()
                        .to_string();
                    println!("  - Current commitment: {}", commitment);
                    break;
                } else {
                    println!("EVENT: {:?}", event);
                }
            }

            // Add the transaction if the node ID is 0
            if let Some((ix, keys_and_memos, t)) = txn {
                println!("  - Adding the transaction");
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

                state
                    .try_add_transaction(
                        &mut blk,
                        t,
                        round as usize,
                        ix,
                        TRANSACTION_COUNT as usize,
                        owner_memos,
                        kixs,
                    )
                    .unwrap();
                state
                    .validate_and_apply(blk, round as usize, TRANSACTION_COUNT as usize, 0.0)
                    .unwrap();
            }

            println!("  - Round {} completed.", round + 1);
        }

        println!("All rounds completed.");
    };
}
