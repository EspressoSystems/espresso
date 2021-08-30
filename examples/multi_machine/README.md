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

### Generate public key files
* If there are public key files under `examples/multi_machine/src`, skip this section.
* Otherwise, in a terminal window:
    * Cd to `target/release/`.
    * Run `multi_machine --config {config} --generate_keys`.
    * Check that public key files are stored under `examples/multi_machine/src`, file names starting `pk_`.

### Simulate consensus
* Open 7 terminal windows (or split a window into 7 sessions using tmux). Let them be `window 0, 1, ..., 6`, each representing a node.
* In each window:
    * Cd to `target/release/`.
    * Run `multi_machine --config {config} --id {id}`.
        * `config` is the path to the node config file.
            * Skip this option if using the default file, `examples/multi_machine/src/node-config.toml`.
        * `id` is the ID of the current node, starting from `0` to `6`.
            * The last node, `node 6`, is going to propose all transactions, but not necessarily the leader in each round.
            * Note: Make sure to start `node 6` last, so that it will complete network connections faster than other nodes and starts to propose the first transaction. 
        * Add `--auto` to automatically start each round of the consensus.
            * Note: This is useful for automated testing, but the recommended and default way is to start the consensus by user input.
* For each round:
    * Wait until all windows display `Hit the enter key when ready to start the consensus...`, then hit the enter key in every window.
        * Skip this step if running with `--auto`.
    * Check that the `Current commitment`s in all windows are the same.
* Nodes that have completed all (i.e., 3) rounds will terminate their processes, which may lead to connection errors displayed in other windows. It is okay to ignore these errors as long as the commitments of each round are consistent in all windows.