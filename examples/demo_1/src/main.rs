// Copyright © 2021 Translucence Research, Inc. All rights reserved.

#![deny(warnings)]
//! This program demonstrates use of Hot Stuff in a trivial application.
//!
//! TODO - Add transaction validity checking.

use async_std::task::spawn;
use futures::channel::oneshot;
use futures::future::join_all;
use futures::FutureExt;
use tracing::{debug, error, info};

use phaselock::message::Message;
use phaselock::networking::w_network::WNetwork;
use phaselock::traits::storage::memory_storage::MemoryStorage;
use phaselock::{PhaseLock, PhaseLockConfig, PubKey};
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;
use zerok_lib::{
    ElaboratedBlock, ElaboratedTransaction, MultiXfrRecordSpec, MultiXfrTestState, ValidatorState,
};

/// Generates the `SecretKeySet` for this BFT instance
pub fn gen_keys(threshold: usize) -> tc::SecretKeySet {
    tc::SecretKeySet::random(threshold, &mut rand::thread_rng())
}

/// Attempts to create a network connection with a random port
pub async fn try_network<
    T: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug + 'static,
>(
    key: PubKey,
) -> (WNetwork<T>, u16) {
    // TODO: Actually attempt to open the port and find a new one if it doens't work
    let port = rand::thread_rng().gen_range(2000, 5000);
    (
        WNetwork::new(key, port, None)
            .await
            .expect("Failed to create network"),
        port,
    )
}

/// Attempts to create a phaselock instance
pub async fn try_phaselock(
    keys: &tc::SecretKeySet,
    total: usize,
    threshold: usize,
    node_number: usize,
    initial_state: ValidatorState,
) -> (
    PhaseLock<ElaboratedBlock, 64>,
    PubKey,
    u16,
    WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, 64>>,
) {
    let genesis = ElaboratedBlock::default();
    let pub_key_set = keys.public_keys();
    let known_nodes = (0..total as u64)
        .map(|i| PubKey::from_secret_key_set_escape_hatch(keys, i))
        .collect();
    let pub_key = PubKey::from_secret_key_set_escape_hatch(keys, node_number as u64);
    let config = PhaseLockConfig {
        total_nodes: total as u32,
        threshold: threshold as u32,
        max_transactions: 100,
        known_nodes,
        next_view_timeout: 40_000,
        timeout_ratio: (2, 1),
        round_start_delay: 1,
    };
    let (networking, port) = try_network(pub_key.clone()).await;
    let phaselock = PhaseLock::new(
        genesis,
        pub_key_set,
        keys.secret_key_share(node_number),
        node_number as u64,
        config,
        initial_state,
        networking.clone(),
        MemoryStorage::default(),
    )
    .await;
    (phaselock, pub_key, port, networking)
}

const VALIDATOR_COUNT: usize = 5;
const TEST_SEED: [u8; 32] = [0x7au8; 32];
const TRANSACTION_COUNT: u64 = 50;

// type TransactionSpecification = u64;
type MultiXfrValidator = (
    PhaseLock<ElaboratedBlock, 64>,
    PubKey,
    u16,
    WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, 64>>,
);

fn load_ignition_keys() {
    info!("Loading universal parameters and stuff");
}

/// Calculates the number of signatures required to meet the
/// threshold for threshold cryptography.
///
/// Note, the threshold_crypto crate internally adds one to this
/// value. It takes one more signature than the threshold to
/// generate a threshold signature.
fn calc_signature_threshold(validator_count: usize) -> usize {
    (2 * validator_count) / 3 + 1
}

async fn start_consensus() -> (MultiXfrTestState, Vec<MultiXfrValidator>) {
    let keys = gen_keys(3);
    let threshold = calc_signature_threshold(VALIDATOR_COUNT);
    let state = MultiXfrTestState::initialize(
        TEST_SEED,
        10,
        10,
        (
            MultiXfrRecordSpec {
                asset_def_ix: 0,
                owner_key_ix: 0,
                asset_amount: 0,
            },
            vec![MultiXfrRecordSpec {
                asset_def_ix: 0,
                owner_key_ix: 0,
                asset_amount: 0,
            }],
        ),
    )
    .unwrap();
    // Create the phaselocks and spawn their tasks
    let phaselocks: Vec<MultiXfrValidator> = join_all((0..VALIDATOR_COUNT).map(|x| {
        try_phaselock(
            &keys,
            VALIDATOR_COUNT,
            threshold,
            x,
            state.validator.clone(),
        )
    }))
    .await;
    // Boot up all the low level networking implementations
    for (_, _, _, network) in &phaselocks {
        let (x, sync) = oneshot::channel();
        match network.generate_task(x) {
            Some(task) => {
                for t in task {
                    spawn(t);
                }
                sync.await.expect("sync.await failed");
            }
            None => {
                error!("generate_task(x) returned None");
                panic!();
            }
        }
    }
    // Connect the phaselocks
    for (i, (_, key, port, _)) in phaselocks.iter().enumerate() {
        let socket = format!("localhost:{}", port);
        // Loop through all the other phaselocks and connect it to this one
        for (_, key_2, port_2, network_2) in &phaselocks[i..] {
            debug!("Connecting {} to {}", port_2, port);
            if key != key_2 {
                network_2
                    .connect_to(key.clone(), &socket)
                    .await
                    .expect("Unable to connect to node");
            }
        }
    }
    // Boot up all the high level implementations
    for (phaselock, _, _, _) in &phaselocks {
        phaselock.spawn_networking_tasks().await;
    }
    // Wait for all nodes to connect to each other
    debug!("Waiting for nodes to fully connect");
    for (_, _, _, w) in &phaselocks {
        while w.connection_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        while w.connection_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    info!("Consensus validators are connected");

    (state, phaselocks)
}

async fn propose_transaction(
    id: usize,
    phaselock: &PhaseLock<ElaboratedBlock, 64>,
    transaction: ElaboratedTransaction,
) {
    info!("Proposing transacton {}", id);
    phaselock
        .publish_transaction_async(transaction)
        .await
        .unwrap();
}

async fn consense(round: usize, phaselocks: &[MultiXfrValidator]) {
    info!("Consensing");

    // Issuing new views
    debug!("Issuing new view messages");
    join_all(
        phaselocks
            .iter()
            .map(|(h, _, _, _)| h.next_view(round as u64, None)),
    )
    .await;

    // Running a round of consensus
    debug!("Running round {}", round + 1);
    join_all(
        phaselocks
            .iter()
            .map(|(h, _, _, _)| h.run_round(round as u64 + 1, None)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap_or_else(|_| panic!("Round {} failed", round + 1));
}

async fn log_transaction(phaselocks: &[MultiXfrValidator]) {
    info!(
        "Current states:\n  {}",
        join_all(phaselocks.iter().map(|(h, _, _, _)| {
            h.get_state()
                .map(|x| TaggedBase64::new("LEDG", &x.commit()).unwrap().to_string())
        }))
        .await
        .join("\n  ")
    );
}

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt::init();
    load_ignition_keys();
    let (mut test_state, phaselocks) = start_consensus().await;

    for i in 0..TRANSACTION_COUNT {
        info!(
            "Current states:\n  {}",
            join_all(phaselocks.iter().map(|(h, _, _, _)| {
                h.get_state()
                    .map(|x| TaggedBase64::new("LEDG", &x.commit()).unwrap().to_string())
            }))
            .await
            .join("\n  ")
        );
        // Build a new transaction
        let mut transactions = test_state
            .generate_transactions(
                i as usize,
                vec![(true, 0, 0, 0, 0, -2)],
                TRANSACTION_COUNT as usize,
            )
            .unwrap();
        let transaction = transactions.remove(0);

        // Propose the transaction
        propose_transaction(i as usize, &phaselocks[0].0, transaction.2.clone()).await;

        consense(i as usize, &phaselocks).await;

        let (ix, keys_and_memos, txn) = transaction;
        let (owner_memos, kixs) = {
            let mut owner_memos = vec![];
            let mut kixs = vec![];

            for (kix, memo) in keys_and_memos {
                kixs.push(kix);
                owner_memos.push(memo);
            }
            (owner_memos, kixs)
        };

        let mut blk = ElaboratedBlock::default();
        test_state
            .try_add_transaction(
                &mut blk,
                txn,
                i as usize,
                ix,
                TRANSACTION_COUNT as usize,
                owner_memos,
                kixs,
            )
            .unwrap();
        test_state
            .validate_and_apply(blk, i as usize, TRANSACTION_COUNT as usize, 0.0)
            .unwrap();
    }
    log_transaction(&phaselocks).await;
}
