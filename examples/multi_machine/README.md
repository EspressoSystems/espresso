# Multi-Machine Consensus Demo

## Build code
* Run `cargo run --release --bin multi_machine`.
* Check that `multi_machine` is generated under `target/release/`.

## Create a node config file
* To demonstrate consensus among 7 nodes, use the default config file, `system/examples/multi_machine/src/node-config.toml`.
* Otherwise, create a `.toml` file similar to the default file but with information of the desired number of nodes.
    * Note: number of nodes must be at least 5.

## Run demo
The instructions below assume that the number of nodes is 7. Otherwise, replace numbers accordingly.
* Open 7 terminal windows (or split a window into 7 sessions). Let them be `window 0, 1, ..., 6`, each representing a node.
* In each window:
    * Cd to `target/release/`.
    * Run `multi_machine --config {config} --id {id}`.
        * `config` is the path to the node config file.
            * Skip this option if using the default file, `system/examples/multi_machine/src/node-config.toml`.
        * `id` is the ID of the current node, starting from `0` to `6`.
            * `Node 0` is going to propose all transactions, but not necessarily the leader in each round.
* For each round:
    * In `window 0`:
        * After `Proposing a transaction` and `Hit any key when ready to start the consensus...`, hit any key to start.
    * In each of the other windows:
        * After `window 0` has started consensus and `Hit any key when ready to start the consensus...` is prompted, hit any key to start.
        * Note: it's important to not start consensus for any node until `node 0` has proposed a new transaction.
    * Check that the `Current commitment`s in all windows are the same.
* Nodes that have completed all (i.e., 3) rounds will terminate their processes, which may lead to connection errors displayed in other windows. It is okay to ignore these errors as long as the commitments of each round are consistent in all windows.