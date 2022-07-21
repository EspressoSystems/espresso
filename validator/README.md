# Espresso Validator

`espresso-validator` is the executable which actually runs a validator and participates in the
Espresso protocol.

## Build code
* Run `cargo run --release --bin espresso-validator`.
* Check that `espresso-validator` is generated under `target/release/`.

### Statically linked binary

It is possible to build a statically linked version of this executable (with a musl libc) on `x86_64-linux` using nix (with flakes enabled).
This is useful because this executable may now be run on any recent linux distribution. Build commands:

```
nix develop .#staticShell -c cargo build --bin multi_machine_automation
```

The resulting binary is in `target/x86_64-unknown-linux-musl/release/multi_machine_automation`.


## Create a node config file
* To demonstrate consensus among 7 nodes, use the default config file, `validator/src/node-config.toml`.
* Otherwise, create a `.toml` file similar to the default file but with information of the desired number of nodes.
    * Note: number of nodes must be at least 5.

## Run demo
The instructions below assume that the number of nodes is 7. Otherwise, replace numbers accordingly.

### Simulate consensus
* To simulate the multi-process consensus:
    * Open 7 terminal windows (or split a window into 7 sessions using tmux). Let them be `window 0, 1, ..., 6`, each representing a node.
    * In each window:
        * Cd to `target/release/`.
        * Run `./espresso-validator --config {config} --id {id} --num-nodes {num_nodes} --num-txn {num_txn}`.
            * `config` is the path to the node config file.
                * Skip this option if using the default file, `validator/src/node-config.toml`.
            * `id` is the ID of the current node, starting from `0` to `6`.
                * `Node 0` is going to propose all transactions, but not necessarily the leader in each round.
            * `num_nodes` is the number of nodes, including the bootstrap nodes in the node config file, and non-bootstrap nodes.
            * `num_txn` is the number of transactions to generate.
                * If skipped, the consensus will keep running till the process is killed. For easier manual testing, do not skip it.
            * Add `--full` to run a full node.
    * After all processes are done:
        * Check that at least 5 windows display `Round {num_txn} completed` where `num_txn` is the number of transactions, and have the same commitment.
        * Note: Nodes that have completed all (i.e., 3) rounds or timed out will terminate their processes, which may lead to connection errors displayed in other windows. It is okay to ignore these errors as long as there are 5 identical commitments after the final round.
* To automate a single-command consensus:
    * In a terminal window:
        * Cd to `target/release/`.
        * Run `./multi_machine_automation --config {config} --num-nodes {num_nodes} --num-txn {num_txn}`.
            * `config` is the path to the node config file.
                * Skip this option if using the default file, `validator/src/node-config.toml`.
            * `num_nodes` is the number of nodes, including the bootstrap nodes in the node config file, and non-bootstrap nodes.
            * `num_txn` is the number of transactions to generate.
                * If skipped, the consensus will keep running till the process is killed. For easier manual testing, do not skip it.
    * Unlike the multi-process simulation, the single-command simulation will automatically check if the final commitments are the same and the number of succeeded nodes meets the threshold.

### Initialize web server
* Port
    * By default, the port the web server listens on is `id + 50000`. E.g., for `node 3`, the port is `50003`. Use the `PORT` environment variable to override the setting.
* Asset directory
    * By default, it is `validator/public`. Use `--assets` to provide the path to a different directory.
* API file
    * By default, API and messages are specified in `validator/api/api.toml`. Use `--api` to change the file.

## Running a query service

Since the validator has access to all of the information about the state of the ledger, it can be
configured to run an Espresso Query Service as well. This is a REST service which provides
information about the current and historical state of the ledger. It is used by clients to keep up
with on-chain events and build transactions. At least one validator must be running a query service
in order for an Espresso network to be useful.

Use the command line flag `--full` to run a query service. This turns the validator into a full
node, which means it stores the entire state of the ledger, including history, which gives it the
information it needs to provide in order to run the query service.

## Running with a keystore
By default, one of the validator nodes in the demo will automatically generate transactions to propose to the other nodes. But the demo can also be driven by a keystore,
running externally to all of the nodes.

To use a keystore with the demo, first generate a key pair for the keystore by logging into the CLI (`wallet-cli`) and generating a key (`gen_key sending`). Next,
start the demo as you normally would, but pass the extra argument `--faucet-pub-key $PUB_KEY` to each node, and pass `--full` to at least one node. The lead node will initialize a ledger containing a single record of 2^32 native tokens, owned by the keystore.

In a separate terminal, you can now enter the interactive keystore REPL:
```
cd zerok/zerok_client
cargo run -- localhost:$port
```
where $port is the port number where the full node is serving (50000 + node id, by default). It will take a while to connect (actually, most of that time is deserializing the universal parameters and generating proving keys) and will prompt you when it is ready to process commands.

