EspressoSystems > espresso is built on the Jellyfish cryptographic library.

# Running locally

The Espresso system is a combination of a number of interacting services, including:
* Validators (at least 5 are required, but you can have as many as you want)
* An Espresso Query Service (EsQS) (can run alongside a validator)
* A faucet service (testnet only)
* An address book

You can run all of the necessary services locally, directly from a copy of this repository's source
code, to test and experiment with a local Espresso testnet. First, download the source code, if you
haven't already:
```bash
git clone https://github.com/EspressoSystems/espresso.git
cd espresso
```

Build the system:
```bash
cargo build --release
```

We need to configure our validator network. See the [instructions](validator/README.md) for
generating a `node-config.toml` file, or use [the default](validator/src/node-config.toml). We also
need the public key of a genesis record which will be accessible by the faucet service. To get this,
first set the mnemonic seed phrase you will use for the faucet service, e.g. `export
ESPRESSO_FAUCET_MANAGER_MNEMONIC="test test test test test test test test test test test junk"`.
Then run `target/release/faucet-keystore-test-setup` and copy the output into your terminal to
export the necessary environment variables. It should look something like:
```bash
export ESPRESSO_FAUCET_MANAGER_MNEMONIC="test test test test test test test test test test test junk"
export ESPRESSO_FAUCET_PUB_KEYS="USERPUBKEY~oJtD62L-jgPwz2MtdSgBYhgkHXz30l8Qlh3_6Ggi6RsgAAAAAAAAAKbNFtKP1zaRURIPxpVelnYcsE26aDyP0wezQxLW8FNTxw"
```

Now, we need to configure all of the services to find each other when we run them on `localhost`.
Each service can be configured using command line arguments, but it is easier if we set some
environment variables which can be shared by all of the services. Set the following environment
variables in each terminal where you intend to start a service:
```bash
export ESPRESSO_VALIDATOR_CONFIG_PATH="/path/to/node-config.toml"
export ESPRESSO_VALIDATOR_PORT="50077"
export ESPRESSO_ADDRESS_BOOK_PORT="50078"
export ESPRESSO_ADDRESS_BOOK_URL="http://localhost:$ESPRESSO_ADDRESS_BOOK_PORT"
export ESPRESSO_ESQS_URL="http://localhost:$ESPRESSO_VALIDATOR_PORT"
export ESPRESSO_SUBMIT_URL="http://localhost:$ESPRESSO_VALIDATOR_PORT"
export ESPRESSO_FAUCET_WALLET_MNEMONIC="$ESPRESSO_FAUCET_MANAGER_MNEMONIC"
export ESPRESSO_FAUCET_PORT="50079"
export ESPRESSO_FAUCET_URL="http://localhost:$ESPRESSO_FAUCET_PORT"
```
These are the minimum environment variables required to allow all the services to discover each
other. There are other variables which allow you to tune various aspects of the system. They are
listed in the table below.

Now we are ready to start the services. First, the validators. The validator executable is in
`target/release/espresso-validator`. You must use `--full` for _exactly_ one of the validators.
(Since earlier we configured all validators to run their web servers on the same port with
`ESPRESSO_VALIDATOR_PORT=50077`, it will cause problems if more than one validator is running a web
server. You can also set `ESPRESSO_VALIDATOR_PORT` to something unique for each validator and use
`--full` for all of them, if you want.) You may also want to use `--reset-store-state` for all of
the validators, if you have run a local testnet before and your intention is to overwrite that
ledger with a fresh one.

Each validator must be started with a unique ID. The IDs should be sequential integers starting from
0. So, if we assume validator 0 will be the full node, you might run the following commands to start
5 validators:
```bash
target/release/espresso-validator -i 0 --full --reset-store-state
target/release/espresso-validator -i 1 --reset-store-state
target/release/espresso-validator -i 2 --reset-store-state
target/release/espresso-validator -i 3 --reset-store-state
target/release/espresso-validator -i 4 --reset-store-state
```

Next, the address book:
```bash
target/release/address-book
```

And finally the faucet:
```bash
target/release/faucet
```

| Environment Variable       | Type | Affected Services    | Meaning
|----------------------------|------|----------------------|---------
| ESPRESSO_VALIDATOR_CONFIG_PATH | Path | espresso-validator | Path to `node-config.toml` for validator network configuration
| ESPRESSO_VALIDATOR_STORE_PATH | Path | espresso-validator | Path to persistence files for validator service
| ESPRESSO_VALIDATOR_WEB_PATH | Path | espresso-validator | Path to validator assets including web server files.
| ESPRESSO_VALIDATOR_API_PATH | Path | espresso-validator | Path to validator API specification
| ESPRESSO_VALIDATOR_PUB_KEY_PATH | Path | espresso-validator | Path to validator public keys
| ESPRESSO_VALIDATOR_PORT    | u16  | espresso-validator   | Port on which to serve the query service and submit API
| ESPRESSO_VALIDATOR_SECRET_KEY_SEED | TaggedBase64 (tag="SEED") | espresso-validator | Seed to use for generating threshold signature secret key (overrides the value from `node-config.toml`)
| ESPRESSO_VALIDATOR_NODES | Vec<Url> | espresso-validator | Comma-separated list of URLs for validators in the network (overrides the value from `node-config.toml`)
| ESPRESSO_ADDRESS_BOOK_STORE_PATH | Path | address-book   | Path to persistence files for address book service (default `$LOCAL/.espresso/espresso/address-book/store`)
| ESPRESSO_ADDRESS_BOOK_PORT | u16  | address-book         | Port on which to serve the address book
| ESPRESSO_ADDRESS_BOOK_URL  | Url  | zerok-client, faucet | URL of the address book service
| ESPRESSO_ESQS_URL          | Url  | zerok-client, faucet | URL of the EsQS
| ESPRESSO_SUBMIT_URL        | Url  | zerok-client, faucet | URL of the validator to submit transactions to
| ESPRESSO_FAUCET_MANAGER_MNEMONIC | String | faucet-keystore-test-setup | Mnemonic phrase to generate the master faucet public key
| ESPRESSO_FAUCET_PUB_KEYS | Vec<UserPubKey> | espresso-validator | Comma-separated list of public keys owning records in the genesis block
| ESPRESSO_FAUCET_WALLET_MNEMONIC | String | faucet        | Mnemonic phrase to generate the faucet public key
| ESPRESSO_FAUCET_WALLET_STORE_PATH | Path | faucet              | Path to persistence files for faucet wallet (default `$LOCAL/.espresso/espresso/faucet/keystore`)
| ESPRESSO_FAUCET_WALLET_PASSWORD | String | faucet        | Password to use for persisted faucet files (random by default)
| ESPRESSO_FAUCET_GRANT_SIZE | u64  | faucet               | The amount of tokens to dispense with each faucet request
| ESPRESSO_FAUCET_FEE_SIZE   | u64  | faucet               | The fee to include with each transfer from the faucet
| ESPRESSO_FAUCET_PORT       | u16  | faucet               | Port on which to serve the faucet service
| ESPRESSO_FAUCET_URL        | Url  |                      | URL of the faucet service

# Docker

To run the system locally run

    docker compose up

This will also download the docker images from the github container registry if
necessary.

To update the local images run

    docker compose pull

To build the static executables and docker images locally run

    docker/build-images

This will tag the local images with the tags used in docker compose and
subsequently running `docker compose up` will use the locally built images.

To go back to using the images from the registry run `docker compose pull`.

The static dev shell is currently not supported on `aarch64` (for example M1
Macs).

# License headers
To insert or check license headers run

    addlicense -f .license-header.txt -ignore "target/**" .
    addlicense -check -f .license-header.txt -ignore "target/**" .
