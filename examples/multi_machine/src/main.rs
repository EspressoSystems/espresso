// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use phaselock::{
    event::{Event, EventType},
    handle::PhaseLockHandle,
    message::Message,
    networking::w_network::WNetwork,
    traits::storage::memory_storage::MemoryStorage,
    PhaseLock, PhaseLockConfig, PubKey,
};
use rand_xoshiro::{rand_core::SeedableRng, Xoshiro256StarStar};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;
use toml::Value;
use tracing::debug;
use zerok_lib::{
    ElaboratedBlock, ElaboratedTransaction, MultiXfrRecordSpec, MultiXfrTestState, ValidatorState,
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

    /// Id of the current node.
    /// If the node ID is 0, it will propose and try to add transactions.
    #[structopt(long = "id", short = "i")]
    id: u64,
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
    sks: &tc::SecretKeySet,
    node_id: u64,
    port: u16,
) -> (WNetwork<T>, PubKey) {
    let pub_key = PubKey::from_secret_key_set_escape_hatch(sks, node_id);
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
    sks: &tc::SecretKeySet,
    nodes: u64,
    threshold: u64,
    node_id: u64,
    networking: WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, 64>>,
) -> (MultiXfrTestState, PhaseLockHandle<ElaboratedBlock, 64>) {
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
    let known_nodes: Vec<_> = (0..nodes)
        .map(|x| PubKey::from_secret_key_set_escape_hatch(sks, x))
        .collect();

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
        sks.public_keys(),
        sks.secret_key_share(node_id),
        node_id,
        config,
        state.validator.clone(),
        networking,
        MemoryStorage::default(),
    )
    .await;
    debug!("phaselock launched");

    (state, phaselock)
}

#[async_std::main]
async fn main() {
    // Setup tracing
    tracing_subscriber::fmt::init();

    // Read configuration file path and node id from options
    let config_path_str = NodeOpt::from_args().config;
    let path = Path::new(&config_path_str);
    let own_id = NodeOpt::from_args().id;
    println!("Spawning network for node {}", own_id);

    // Read node info from node configuration file
    let mut config_file = File::open(&path)
        .unwrap_or_else(|_| panic!("Cannot find node config file: {}", path.display()));
    let mut config_str = String::new();
    config_file
        .read_to_string(&mut config_str)
        .unwrap_or_else(|err| panic!("Error while reading node config: [{}]", err));
    let node_config: Value =
        toml::from_str(&config_str).expect("Error while reading node config file");

    // Get secret key set
    let seed: u64 = node_config["seed"]
        .as_integer()
        .expect("Missing seed value") as u64;
    let nodes = node_config["nodes"]
        .as_table()
        .expect("Missing nodes info")
        .len() as u64;
    let threshold = ((nodes * 2) / 3) + 1;
    let mut rng = Xoshiro256StarStar::seed_from_u64(seed);
    let sks = tc::SecretKeySet::random(threshold as usize - 1, &mut rng);

    // Get networking information
    let (own_network, _) =
        get_networking(&sks, own_id, get_host(node_config.clone(), own_id).1).await;
    #[allow(clippy::type_complexity)]
    let mut other_nodes: Vec<(u64, PubKey, String, u16)> = Vec::new();
    for id in 0..nodes {
        if id != own_id {
            let (ip, port) = get_host(node_config.clone(), id);
            let pub_key = PubKey::from_secret_key_set_escape_hatch(&sks, id);
            other_nodes.push((id, pub_key, ip, port));
        }
    }

    // Connect the networking implementations
    for (id, key, ip, port) in other_nodes {
        let socket = format!("{}:{}", ip, port);
        while own_network.connect_to(key.clone(), &socket).await.is_err() {
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
    let (mut state, mut phaselock) =
        init_state_and_phaselock(&sks, nodes, threshold, own_id, own_network).await;

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
                    vec![(0, 0, 0, 0, -2)],
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
        println!("Hit any key when ready to start the consensus...");
        std::io::stdin().read_line(&mut line).unwrap();
        phaselock.start().await;
        println!("  - Starting consensus");
        let mut event: Event<ElaboratedBlock, ValidatorState> = phaselock
            .next_event()
            .await
            .expect("PhaseLock unexpectedly closed");
        while !matches!(event.event, EventType::Decide { .. }) {
            event = phaselock
                .next_event()
                .await
                .expect("PhaseLock unexpectedly closed");
        }
        if let EventType::Decide { block: _, state } = event.event {
            let commitment = TaggedBase64::new("LEDG", &state.commit())
                .unwrap()
                .to_string();
            println!("  - Current commitment: {}", commitment);
        } else {
            unreachable!();
        }

        // Add the transaction if the node ID is 0
        if let Some((ix, (owner_memos, k1_ix, k2_ix), t)) = txn {
            println!("  - Adding the transaction");
            let mut blk = ElaboratedBlock::default();
            state
                .try_add_transaction(
                    &mut blk,
                    t,
                    round as usize,
                    ix,
                    TRANSACTION_COUNT as usize,
                    owner_memos,
                    vec![k1_ix, k2_ix],
                )
                .unwrap();
            state
                .validate_and_apply(blk, round as usize, TRANSACTION_COUNT as usize, 0.0)
                .unwrap();
        }

        println!("  - Round {} completed.", round + 1);
    }

    println!("All rounds completed.");
}
