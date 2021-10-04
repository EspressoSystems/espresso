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
* Open 7 terminal windows (or split a window into 7 sessions using tmux). Let them be `window 0, 1, ..., 6`, each representing a node.
* In each window:
    * Cd to `target/release/`.
    * Run `multi_machine --config {config} --id {id}`.
        * `config` is the path to the node config file.
            * Skip this option if using the default file, `system/examples/multi_machine/src/node-config.toml`.
        * `id` is the ID of the current node, starting from `0` to `6`.
            * `Node 0` is going to propose all transactions, but not necessarily the leader in each round.
* For each round:
    * Wait until all windows display `Hit the enter key when ready to start the consensus...`, then hit the enter key in every window.
        * Note: It may take a while until `window 0` displays the prompt message, since `node 0` needs to propose a transaction before starting the consensus. It is important to not hit the enter key if any node is not ready.
    * Check that the `Current commitment`s in all windows are the same.
* Nodes that have completed all (i.e., 3) rounds will terminate their processes, which may lead to connection errors displayed in other windows. It is okay to ignore these errors as long as the commitments of each round are consistent in all windows.

## Running with a wallet
By default, one of the validator nodes in the demo will automatically generate transactions to propose to the other nodes. But the demo can also be driven by a wallet,
running externally to all of the nodes.

To use a wallet with the demo, first generate a key pair for the wallet:
```
cd zerok/zerok_client
cargo run --key-gen $key_file
```
The private key will be stored in $key_file, and the public key in $key_file.pub. Next,
start the demo as you normally would, but pass the extra argument `--wallet $key_file.pub` to each node, and pass `--full` to at least one node. The lead node will initialize a ledger containing a single record of 2^32 native tokens, owned by the wallet.

In a separate terminal, you can now enter the interactive wallet REPL:
```
cd zerok/zerok_client
cargo run -- --key-path $key_file localhost:$port
```
where $port is the port number where the full node is serving (50000 + node id, by default). It will take a while to connect (actually, most of that time is deserializing the universal parameters and generating proving keys) and will prompt you when it is ready to process commands.

Open another wallet in yet another terminal using a different `--key-path`. (Or don't specify a key path, and one will be generated in-memory. We only needed the key in a file for the first wallet to give to the validators so they could bootstrap the system with some initial amount of native coins.)

Get the addresses of both of your wallets using the `address` command. View your available assets using the `assets` and `balance` commands. Transfer funds back and forth using `transfer <asset> <address> <amount> <fee>`. Remember to hit enter in all of the validator terminals to start consensus after you generate a transaction.
