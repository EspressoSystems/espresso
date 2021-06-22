// Copyright © 2021 Translucence Research, Inc. All rights reserved.

//! This program demonstrates use of Hot Stuff in a trivial application.
//!
//! TODO - Add transaction validity checking.

use async_std::task::spawn;
use futures::channel::oneshot;
use futures::future::join_all;
use tracing::{debug, error, info};

use counter::block::{CounterBlock, CounterTransaction};
use counter::{gen_keys, try_hotstuff};
use hotstuff::demos::counter;
use hotstuff::message::Message;
use hotstuff::networking::w_network::WNetwork;
use hotstuff::{HotStuff, PubKey};

const VALIDATOR_COUNT: usize = 5;
const TRANSACTION_COUNT: u64 = 50;

type TransactionSpecification = u64;
type CounterValidator = (
    HotStuff<CounterBlock>,
    PubKey,
    u16,
    WNetwork<Message<CounterBlock, CounterTransaction>>,
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

async fn start_consensus() -> Vec<CounterValidator> {
    let keys = gen_keys(3);
    let threshold = calc_signature_threshold(VALIDATOR_COUNT);
    // Create the hotstuffs and spawn their tasks
    let hotstuffs: Vec<CounterValidator> =
        join_all((0..VALIDATOR_COUNT).map(|x| try_hotstuff(&keys, VALIDATOR_COUNT, threshold, x)))
            .await;
    // Boot up all the low level networking implementations
    for (_, _, _, network) in &hotstuffs {
        let (x, sync) = oneshot::channel();
        match network.generate_task(x) {
            Some(task) => {
                spawn(task);
                sync.await.expect("sync.await failed");
            }
            None => {
                error!("generate_task(x) returned None");
                panic!();
            }
        }
    }
    // Connect the hotstuffs
    for (i, (_, key, port, _)) in hotstuffs.iter().enumerate() {
        let socket = format!("localhost:{}", port);
        // Loop through all the other hotstuffs and connect it to this one
        for (_, key_2, port_2, network_2) in &hotstuffs[i..] {
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
    for (hotstuff, _, _, _) in &hotstuffs {
        hotstuff.spawn_networking_tasks().await;
    }
    // Wait for all nodes to connect to each other
    debug!("Waiting for nodes to fully connect");
    for (_, _, _, w) in &hotstuffs {
        while w.connection_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        while w.nodes_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    info!("Consensus validators are connected");

    hotstuffs
}

fn build_transaction(specification: TransactionSpecification) -> CounterTransaction {
    info!("Building transaction");
    CounterTransaction::Inc {
        previous: specification,
    }
}

async fn propose_transaction(
    id: usize,
    hotstuff: &HotStuff<CounterBlock>,
    transaction: CounterTransaction,
) {
    info!("Proposing to increment from {} -> {}", id, id + 1);
    hotstuff
        .publish_transaction_async(transaction)
        .await
        .unwrap();
}

async fn consense(id: usize, hotstuffs: &[CounterValidator]) {
    info!("Consensing");

    // Issuing new views
    debug!("Issuing new view messages");
    join_all(
        hotstuffs
            .iter()
            .map(|(h, _, _, _)| h.next_view(id as u64, None)),
    )
    .await;

    // Running a round of consensus
    debug!("Running round {}", id + 1);
    join_all(
        hotstuffs
            .iter()
            .map(|(h, _, _, _)| h.run_round(id as u64 + 1, None)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap_or_else(|_| panic!("Round {} failed", id + 1));
}

async fn log_transaction(hotstuffs: &[CounterValidator]) {
    info!(
        "Current states: {:?}",
        join_all(hotstuffs.iter().map(|(h, _, _, _)| h.get_state())).await
    );
}

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt::init();
    load_ignition_keys();
    let hotstuffs = start_consensus().await;

    for i in 0..TRANSACTION_COUNT {
        info!(
            "Current states: {:?}",
            join_all(hotstuffs.iter().map(|(h, _, _, _)| h.get_state())).await
        );
        // Build a new transaction
        let transaction = build_transaction(i);

        // Propose the transaction
        propose_transaction(i as usize, &hotstuffs[0].0, transaction).await;

        consense(i as usize, &hotstuffs).await;
    }
    log_transaction(&hotstuffs).await;
}
