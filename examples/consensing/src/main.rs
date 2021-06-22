// Copyright © 2021 Translucence Research, Inc. All rights reserved.

//! This program demonstrates use of Hot Stuff in a trivial application.
//!
//! TODO - Add transaction validity checking.

use async_std::task::spawn;
use futures::channel::oneshot;
use futures::future::join_all;

use counter::block::{CounterBlock, CounterTransaction};
use counter::{gen_keys, try_hotstuff};
use hotstuff::demos::counter;
use hotstuff::message::Message;
use hotstuff::networking::w_network::WNetwork;
use hotstuff::{HotStuff, PubKey};

const VALIDATOR_COUNT: usize = 5;
const TRANSACTION_COUNT: u64 = 2;

type TransactionSpecification = u64;

fn load_ignition_keys() {
    println!("Loading universal parameters and stuff");
}

async fn start_consensus() -> Vec<(
    HotStuff<CounterBlock>,
    PubKey,
    u16,
    WNetwork<Message<CounterBlock, CounterTransaction>>,
)> {
    let keys = gen_keys(3);
    // Create the hotstuffs and spawn their tasks
    let hotstuffs: Vec<(HotStuff<CounterBlock>, PubKey, u16, WNetwork<_>)> =
        join_all((0..VALIDATOR_COUNT).map(|x| try_hotstuff(&keys, VALIDATOR_COUNT, 4, x))).await;
    // Boot up all the low level networking implementations
    for (_, _, _, network) in &hotstuffs {
        let (x, sync) = oneshot::channel();
        match network.generate_task(x) {
            Some(task) => {
                spawn(task);
                sync.await.expect("sync.await failed");
            }
            None => {
                println!("generate_task(x) returned None");
                panic!();
            }
        }
    }
    // Connect the hotstuffs
    for (i, (_, key, port, _)) in hotstuffs.iter().enumerate() {
        let socket = format!("localhost:{}", port);
        // Loop through all the other hotstuffs and connect it to this one
        for (_, key_2, port_2, network_2) in &hotstuffs[i..] {
            println!("Connecting {} to {}", port_2, port);
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
    println!("Waiting for nodes to fully connect");
    for (_, _, _, w) in &hotstuffs {
        while w.connection_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        while w.nodes_table_size().await < VALIDATOR_COUNT - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    println!("Nodes should be connected");

    hotstuffs
}

fn build_transaction(specification: TransactionSpecification) -> CounterTransaction {
    println!("Building transaction");
    CounterTransaction::Inc {
        previous: specification,
    }
}

async fn propose_transaction(
    id: usize,
    hotstuff: &HotStuff<CounterBlock>,
    transaction: CounterTransaction,
) {
    println!("Proposing to increment from {} -> {}", id, id + 1);
    hotstuff
        .publish_transaction_async(transaction)
        .await
        .unwrap();
}

async fn consense(
    id: usize,
    hotstuffs: &Vec<(
        HotStuff<CounterBlock>,
        PubKey,
        u16,
        WNetwork<Message<CounterBlock, CounterTransaction>>,
    )>,
) -> bool {
    println!("Consensing");
    /*
        let mut unanimous = true;

        for _ in 0..VALIDATOR_COUNT {
            let next = rx.recv().unwrap();
            println!("  Validity is {}", &next);
            if !&next {
                unanimous = false;
            }
        }

        unanimous
    */
    // issuing new views
    println!("Issuing new view messages");
    join_all(
        hotstuffs
            .iter()
            .map(|(h, _, _, _)| h.next_view(id as u64, None)),
    )
    .await;

    // Running a round of consensus
    println!("Running round {}", id + 1);
    join_all(
        hotstuffs
            .iter()
            .map(|(h, _, _, _)| h.run_round(id as u64 + 1, None)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .expect(&format!("Round {} failed", id + 1));
    true
}

async fn log_transaction(
    hotstuffs: &Vec<(
        HotStuff<CounterBlock>,
        PubKey,
        u16,
        WNetwork<Message<CounterBlock, CounterTransaction>>,
    )>,
) {
    println!(
        "Current states: {:?}",
        join_all(hotstuffs.iter().map(|(h, _, _, _)| h.get_state())).await
    );
}

#[async_std::main]
async fn main() {
    load_ignition_keys();
    let hotstuffs = start_consensus().await;

    for i in 0..TRANSACTION_COUNT {
        println!(
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
