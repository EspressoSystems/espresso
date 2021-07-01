use async_std::task::spawn;
use futures::channel::oneshot;
use futures::future::join_all;

use counter::block::{CounterBlock, CounterTransaction};
use counter::{gen_keys, try_hotstuff};
use hotstuff::demos::counter;
use hotstuff::networking::w_network::WNetwork;
use hotstuff::{HotStuff, PubKey};

#[async_std::main]
async fn main() {
    let keys = gen_keys(3);
    // Create the hotstuffs and spawn their tasks
    let hotstuffs: Vec<(HotStuff<CounterBlock, 32>, PubKey, u16, WNetwork<_>)> =
        join_all((0..5).map(|x| try_hotstuff(&keys, 5, 4, x))).await;
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
        while w.connection_table_size().await < 4 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        while w.nodes_table_size().await < 4 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    println!("Nodes should be connected");
    for i in 0..50 {
        println!(
            "Current states: {:?}",
            join_all(hotstuffs.iter().map(|(h, _, _, _)| h.get_state())).await
        );
        // Propose a new transaction
        println!("Proposing to increment from {} -> {}", i, i + 1);
        hotstuffs[0]
            .0
            .publish_transaction_async(CounterTransaction::Inc { previous: i })
            .await
            .unwrap();
        // issuing new views
        println!("Issuing new view messages");
        join_all(hotstuffs.iter().map(|(h, _, _, _)| h.next_view(i, None))).await;
        // Running a round of consensus
        println!("Running round {}", i + 1);
        join_all(
            hotstuffs
                .iter()
                .map(|(h, _, _, _)| h.run_round(i + 1, None)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| panic!("Round {} failed", i + 1));
    }
    println!(
        "Current states: {:?}",
        join_all(hotstuffs.iter().map(|(h, _, _, _)| h.get_state())).await
    );
}
