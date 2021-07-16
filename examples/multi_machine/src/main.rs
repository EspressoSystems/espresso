// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use async_std::task::spawn;
use futures::channel::oneshot;
use futures::future::join_all;
use futures::FutureExt;
use tracing::{debug, error, info};
use structopt::StructOpt;
use phaselock::message::Message;
use phaselock::networking::w_network::WNetwork;
use phaselock::{PhaseLock, PhaseLockConfig, PubKey};
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;
use zerok_lib::{
    ElaboratedBlock, ElaboratedTransaction, MultiXfrRecordSpec, MultiXfrTestState, ValidatorState,
};
// use demo_1::*;

const TRANSACTION_COUNT: u64 = 3;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Multi-machine concensus",
    about = "Simulates consensus among multiple machines"
)]
struct NodeOpt {
    /// Path to the node configuration file
    #[structopt(
        long = "config",
        short = "c",
        default_value = "../../../examples/node-config.toml"
    )]
    config: String,

    /// Id of the current node
    #[structopt(long = "id", short = "i", default_value = "1")]
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
    networking: WNetwork<Message<DEntryBlock, Transaction, H_256>>,
) -> (State, PhaseLockHandle<DEntryBlock, H_256>) {
    // Create the initial state
    let balances: BTreeMap<Account, Balance> = vec![
        ("Joe", 1_000_000),
        ("Nathan M", 500_000),
        ("John", 400_000),
        ("Nathan Y", 600_000),
        ("Ian", 0),
    ]
    .into_iter()
    .map(|(x, y)| (x.to_string(), y))
    .collect();
    let state = State {
        balances,
        nonces: BTreeSet::default(),
    };

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
    let phaselock = PhaseLock::new(
        genesis,
        &sks,
        node_id,
        config,
        state,
        networking,
    );
    debug!("phaselock launched");

    (state, phaselock)
}

async fn consense(round: u64, phaselock: PhaseLock<ElaboratedBlock, 64>) {
    info!("Consensing");

    // Issuing new views
    debug!("Issuing new view messages");
    phaselock.next_view(round, None).await;

    // Running a round of consensus
    debug!("Running round {}", round + 1);
    phaselock.run_round(id + 1, None)
    .await
    .unwrap_or_else(|_| panic!("Round {} failed", id + 1));
}

#[async_std::main]
async fn main() {
    // Setup tracing listener
    common::setup_tracing();

    // Read configuration file path and node id from options
    let config_path_str = NodeOpt::from_args().config;
    let path = Path::new(&config_path_str);
    let own_id = NodeOpt::from_args().id;
    println!("  - Spawning network for node {}", own_id);

    // Read node info from node configuration file
    let mut config_file =
        File::open(&path).expect(&format!("Cannot find node config file: {}", path.display()));
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
    for id in 1..(nodes + 1) {
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
            println!("  - Retrying");
            debug!("Retrying");
            async_std::task::sleep(std::time::Duration::from_millis(10_000)).await;
        }
        println!("  - Connected to node {}", id);
        debug!("Connected to node {}", id);
    }

    // Wait for the networking implementations to connect
    while (own_network.connection_table_size().await as u64) < nodes - 1 {
        async_std::task::sleep(std::time::Duration::from_millis(10)).await;
    }
    println!("All nodes connected to network");
    debug!("All nodes connected to network");

    // Initialize the state and phaselock
    let (mut own_state, mut phaselock) =
        init_state_and_phaselock(&sks, nodes, threshold, own_id, own_network).await;
    phaselock.start().await;

    // Build transactions
    let mut transactions = test_state
    .generate_transactions(
        i as usize,
        vec![(0, 0, 0, 0, -2)],
        TRANSACTION_COUNT as usize,
    )
    .unwrap();

    // Start consensus
    for round in 0..TRANSACTION_COUNT {
        let transaction = transactions.remove(0);

        // Propose the transaction
        propose_transaction(i as usize, phaselock, transaction.2.clone()).await;

        consense(round, &phaselocks).await;

        let (ix, (owner_memos, k1_ix, k2_ix), txn) = transaction;
        let mut blk = ElaboratedBlock::default();
        test_state
            .try_add_transaction(
                &mut blk,
                txn,
                i as usize,
                ix,
                TRANSACTION_COUNT as usize,
                owner_memos,
                k1_ix,
                k2_ix,
            )
            .unwrap();
        test_state
            .validate_and_apply(blk, i as usize, TRANSACTION_COUNT as usize, 0.0)
            .unwrap();
    }
    log_transaction(&phaselocks).await;
}
