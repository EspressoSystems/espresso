<!--
 ~ Copyright (c) 2022 Espresso Systems (espressosys.com)
 ~ This file is part of the Espresso library.
 ~
 ~ This program is free software: you can redistribute it and/or modify it under the terms of the GNU
 ~ General Public License as published by the Free Software Foundation, either version 3 of the
 ~ License, or (at your option) any later version.
 ~ This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 ~ even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 ~ General Public License for more details.
 ~ You should have received a copy of the GNU General Public License along with this program. If not,
 ~ see <https://www.gnu.org/licenses/>.
 -->

# Espresso
Espresso is the layer 1 protocol developed by Espresso Systems. It is built on the
[Jellyfish](EspressoSystems/jellyfish) cryptographic library and the [CAP](EspressoSystems/cap)
protocol.

**DISCLAIMER:** This software is provided "as is" and its security has not been externally audited.
Use at your own risk.

---

<!-- run `md-toc` inside the nix-shell to generate the table of contents -->

**Table of Contents**

- [Espresso](#espresso)
  - [Obtaining the source code](#obtaining-the-source-code)
  - [Project structure](#project-structure)
- [Documentation](#documentation)
  - [CAP protocol specification](#cap-protocol-specification)
  - [Rust docs](#rust-docs)
- [Environment](#environment)
  - [Nix](#nix)
    - [1. Install nix](#1-install-nix)
    - [2. Activate the nix environment](#2-activate-the-nix-environment)
    - [3. Verify installation](#3-verify-installation)
    - [4. direnv (Optional, but recommended for development)](#4-direnv-optional-but-recommended-for-development)
  - [Python tools](#python-tools)
- [Build](#build)
  - [Static build](#static-build)
  - [Docker images](#docker-images)
- [Test](#test)
  - [Unit tests](#unit-tests)
  - [Random wallet test](#random-wallet-test)
- [Running locally](#running-locally)
  - [Running with docker-compose](#running-with-docker-compose)
  - [Running the services manually](#running-the-services-manually)
- [License headers](#license-headers)

## Obtaining the source code

    git clone git@github.com:EspressoSystems/espresso.git

## Project structure

This is a Rust project consisting of a number of crates:
- [espresso-core](core/README.md): the definition of the Espresso ledger, including data types and transaction validation
- [espresso-validator](validator/README.md): integration of the Espresso ledger with [HotShot](hotshot.docs.espressosys.com) consensus, and the `espresso-validator` executable
- [espresso-client](client/README.md): integration of the Espresso ledger with the [Seahorse](https://seahorse.docs.espressosys.com/) keystore library, and the `wallet-cli` executable
- [espresso-esqs](apis/esqs): the Espresso Query Service
- [espresso-availability-api](apis/availability): the availability module of the EsQS
- [espresso-catchup-api](apis/catchup): the catchup module of the EsQS
- [espresso-metastate-api](apis/metastate): the metastate module of the EsQS
- [espresso-status-api](apis/status): the status module of the EsQS
- [espresso-validator-api](apis/validator): the validator API for transaction submission
- [faucet](faucet/README.md): the Espresso testnet faucet executable
- [faucet-types](faucet/types): types used in the REST interface to the faucet
- [address-book](address-book/README.md): server for posting and exchanging CAP addresses

# Documentation

## CAP protocol specification

A formal specification of the Configurable Asset Policy protocol can be found at [our CAP github repo](https://github.com/EspressoSystems/cap/blob/main/cap-specification.pdf)

## Rust docs

Documentation of Rust interfaces is available for all of the Rust crates:
- [espresso-core](https://espresso.docs.espressosys.com/espresso_core)
- [espresso-validator](https://espresso.docs.espressosys.com/espresso_validator)
- [espresso-client](https://espresso.docs.espressosys.com/espresso_client)
- [espresso-esqs](https://espresso.docs.espressosys.com/espresso_esqs)
- [espresso-availability-api](https://espresso.docs.espressosys.com/espresso_availability_api)
- [espresso-catchup-api](https://espresso.docs.espressosys.com/espresso_catchup_api)
- [espresso-metastate-api](https://espresso.docs.espressosys.com/espresso_metastate_api)
- [espresso-status-api](https://espresso.docs.espressosys.com/espresso_status_api)
- [espresso-validator-api](https://espresso.docs.espressosys.com/espresso_validator_api)
- [faucet](https://espresso.docs.espressosys.com/faucet)
- [faucet-types](https://espresso.docs.espressosys.com/faucet_types)
- [address-book](https://espresso.docs.espressosys.com/address_book)

# Environment

## Nix

This project can be built using only `cargo`, but we recommend using the
[nix](https://nixos.org) package manager to manage dependencies.

### 1. Install nix

Installation instructions can be found [here](https://nixos.org/download.html).
If in a rush, running the following command and following the on-screen
instructions should work in most cases

    curl -L https://nixos.org/nix/install | sh

If the install script fails, it may be because the usage of `curl` in
the script has incorrect arguments. You may need to change

    fetch() { curl -L "$1" > "$2"; }

to

    fetch() { curl -L "$1" -o "$2"; }

Once the install script has failed, it may be necessary to manually
remove nix before trying again. See [Uninstallation](#uninstallation) below.

Some linux distros (ubuntu, arch, ...) have packaged `nix`. See the section
[Alternative nix installation methods](#alternative-nix-installation-methods)
for more information.

### 2. Activate the nix environment

To activate a shell with the development environment run

    nix-shell

from within the top-level directory of the repo.

Note: for the remainder of this README it is necessary that this environment is
active.

Once the `nix-shell` is activated the dependencies as well as the scripts in the
`./bin` directory will be in the `PATH`.

### 3. Verify installation

Try running some tests to verify the installation

    cargo test --release

If this fails with errors that don't point to obvious problems please open an
issue on github. M1 Macs need to have node@16 installed to avoid memory allocation errors.

### 4. direnv (Optional, but recommended for development)

To avoid manually activating the nix shell each time the
[direnv](https://direnv.net/) shell extension can be used to activate the
environment when entering the local directory of this repo. Note that direnv
needs to be [hooked](https://direnv.net/docs/hook.html) into the shell to
function.

To enable `direnv` run

    direnv allow

from the root directory of this repo.

When developing `nix` related code it can sometimes be handy to take direnv out
of the equation: to temporarily disable `direnv` and manually enter a nix shell
run

    direnv deny
    nix-shell

## Python tools

We are using `poetry` for python dependencies and `poetry2nix` to integrate them
in the nix-shell development environment.

Use any poetry command e. g. `poetry add --dev ipython` to add packages.

# Build

To build the project run

    cargo build --release

The `--release` flag is recommended because without it many cryptographic
computations the project relies one become unbearably slow.

## Static build

To build a statically linked version of the project with musl64 as a libc on a `x86_64-linux-unknown-gnu` host:

```bash
nix develop .#staticShell -c cargo build --release
```

The resulting build artifacts end up in `target/x86_64-unknown-linux-musl`, and may be run on any linux computer as they will not depend on glibc or any shared libs (`*.so`).

## Docker images

To build the wallet or services Docker images locally run

    docker/build-images

inside a nix shell from the root directory of the repo.

For the CI build see the `docker-*` jobs in
[.github/workflows/build.yml](.github/workflows/build.yml).

# Test

## Unit tests

As mentioned above, you can run the unit tests for the rust codebase using

    cargo test --release

Some tests are slow and are not run by default. To enable them, use

    cargo test --release --features=slow-tests

## Random wallet test

The random wallet test is a scripted wallet that generates randomized transactions as fast as it
can. This makes for a good stress test of the overall system. To run it, make sure the system is
built as described in [Build](#build). You will then need to connect to a deployment of the Espresso
network, including the address book, EsQS, faucet, and validator services. See [Running locally](#running-locally)
for instructions on setting up a local deployment. In this case, the URLs in the command below will
all look like `http://localhost:$SERVICE_PORT`.

Once you have built the system and found the URLs of the services you are connecting to, run:

    target/release/random-wallet --address-book-url $ADDRESS_BOOK_URL --esqs-url $ESQS_URL -f $FAUCET_URL -v $VALIDATOR_URL

This will start the random wallet test, which will run for as long as you want and output logging
information to the console. When you want to stop the test, just hit Ctrl+C in the terminal.

# Running locally

There is no public deployment of Espresso yet, but you can build and run a testnet locally. The
Espresso system is a combination of a number of interacting services, including:
* Validators (at least 5 are required, but you can have as many as you want)
* An Espresso Query Service (EsQS) (can run alongside a validator)
* A faucet service (testnet only)
* An address book
Running the system locally basically amounts to building and running each of these services. We also
provide a `docker-compose.yml` file which makes it easy to run the whole thing at once.

Once you have started the services locally, it is possible to create a wallet to build and submit
transactions to the local network. See [the wallet README](client/README.md) for
instructions on running the wallet CLI. As an example, after starting the services using `docker-compose`,
the following command should start the wallet CLI:

    cargo run --release --bin wallet-cli -- --esqs-url http://localhost:60000 --submit-url http://localhost:60000 --address-book-url http://localhost:50000

## Running with docker-compose

To start the local Docker network, run

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

Note: the Docker compose setup includes two instances of the [random wallet test](#random-wallet-test),
a service that attaches to the network and randomly generates transactions as a stress test.

## Running the services manually

Make sure the project is built as described in [Build](#build).

We need the public key of a genesis record which will be accessible by the faucet service. To get
this, first set the mnemonic seed phrase you will use for the faucet service, e.g. `export
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
export ESPRESSO_VALIDATOR_QUERY_PORT="50077"
export ESPRESSO_ADDRESS_BOOK_PORT="50078"
export ESPRESSO_ADDRESS_BOOK_URL="http://localhost:$ESPRESSO_ADDRESS_BOOK_PORT"
export ESPRESSO_ESQS_URL="http://localhost:$ESPRESSO_VALIDATOR_QUERY_PORT"
export ESPRESSO_SUBMIT_URL="http://localhost:$ESPRESSO_VALIDATOR_QUERY_PORT"
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
`ESPRESSO_VALIDATOR_QUERY_PORT=50077`, it will cause problems if more than one validator is running a web
server. You can also set `ESPRESSO_VALIDATOR_QUERY_PORT` to something unique for each validator and use
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
| ESPRESSO_VALIDATOR_STORE_PATH | Path | espresso-validator | Path to persistence files for validator service
| ESPRESSO_VALIDATOR_PUB_KEY_PATH | Path | espresso-validator | Path to validator public keys
| ESPRESSO_VALIDATOR_SECRET_KEY_SEED | TaggedBase64 (tag="SEED") | espresso-validator | Seed to use for generating threshold signature secret key
| ESPRESSO_VALIDATOR_REPLICATION_FACTOR | usize | espresso-validator | Replication factor for entries in the DHT
| ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_HIGH | usize | espresso-validator | `mesh_n_high` parameter for gossibpsub for bootstrap validators
| ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_LOW | usize | espresso-validator | `mesh_n_low` parameter for gossibpsub for bootstrap validators
| ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_OUTBOUND_MIN | usize | espresso-validator | `mesh_outbound_min` parameter for gossibpsub for bootstrap validators
| ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N | usize | espresso-validator | `mesh_n` parameter for gossibpsub for bootstrap validators
| ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_HIGH | usize | espresso-validator | `mesh_n_high` parameter for gossibpsub for non-bootstrap validators
| ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_LOW | usize | espresso-validator | `mesh_n_low` parameter for gossibpsub for non-bootstrap validators
| ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_OUTBOUND_MIN | usize | espresso-validator | `mesh_outbound_min` parameter for gossibpsub for non-bootstrap validators
| ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N | usize | espresso-validator | `mesh_n` parameter for gossibpsub for non-bootstrap validators
| ESPRESSO_VALIDATOR_BOOTSTRAP_NODES | Vec<Url> | espresso-validator | Comma-separated list of URLs for the hosts of bootstrap validators in the network
| ESPRESSO_VALIDATOR_NONBOOTSTRAP_PORT | u16 | espresso-validator | String for the port of the current validator if it's non-bootstrap
| ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME | u64 | espresso-validator | Minimum time (in seconds) to wait for submitted transactions before proposing a block
| ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME | u64 | espresso-validator | Maximum time (in seconds) to wait for submitted transactions before proposing a block
| ESPRESSO_ESQS_PORT | u16 | espresso-validator | Port for the EsQS, if running
| ESPRESSO_ADDRESS_BOOK_STORE_PATH | Path | address-book   | Path to persistence files for address book service (default `$LOCAL/.espresso/espresso/address-book/store`)
| ESPRESSO_ADDRESS_BOOK_PORT | u16  | address-book         | Port on which to serve the address book
| ESPRESSO_ADDRESS_BOOK_URL  | Url  | wallet-cli, faucet | URL of the address book service
| ESPRESSO_ESQS_URL          | Url  | wallet-cli, faucet | URL of the EsQS
| ESPRESSO_SUBMIT_URL        | Url  | wallet-cli, faucet | URL of the validator to submit transactions to
| ESPRESSO_FAUCET_MANAGER_MNEMONIC | String | faucet-keystore-test-setup | Mnemonic phrase to generate the master faucet public key
| ESPRESSO_FAUCET_PUB_KEYS | Vec<UserPubKey> | espresso-validator | Comma-separated list of public keys owning records in the genesis block
| ESPRESSO_FAUCET_WALLET_MNEMONIC | String | faucet        | Mnemonic phrase to generate the faucet public key
| ESPRESSO_FAUCET_WALLET_STORE_PATH | Path | faucet              | Path to persistence files for faucet wallet (default `$LOCAL/.espresso/espresso/faucet/keystore`)
| ESPRESSO_FAUCET_WALLET_PASSWORD | String | faucet        | Password to use for persisted faucet files (random by default)
| ESPRESSO_FAUCET_GRANT_SIZE | u64  | faucet               | The amount of tokens to dispense with each faucet request
| ESPRESSO_FAUCET_FEE_SIZE   | u64  | faucet               | The fee to include with each transfer from the faucet
| ESPRESSO_FAUCET_PORT       | u16  | faucet               | Port on which to serve the faucet service
| ESPRESSO_FAUCET_URL        | Url  |                      | URL of the faucet service
