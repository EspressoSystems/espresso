# Wallet

User entry point to the CAPE system. This is an instantiation of the
[Seahorse](https://github.com/EspressoSystems/seahorse) generic library framework.

## Using the CLI

### Setting up environment

Before starting the CLI, set the following environment variables.

- Espresso Query Service (EsQS)
  - The default URL for the EsQS is `http://localhost:50087`. To override it, use the environment variable `ESPRESSO_ESQS_URL`.
- Address Book
  - The default URL for the Address Book is `http://localhost:50088`. To override it, use the environment variable `ESPRESSO_ADDRESS_BOOK_URL`.
- Validator
  - This is the validator that the CLI will submit transactions to. The default URL is `http://localhost:50089`. To override it, use the environment variable `ESPRESSO_SUBMIT_URL`.

### Starting the CLI

The wallet provides a REPL-style CLI for interacting with Espresso wallets using the command line. To
start the CLI, run

```
target/release/wallet-cli [options]
```

You can use `--help` to see a list of the possible values for `[options]`. A particularly useful
option is `--storage PATH`, which sets the location the wallet will use to store keystore files.
This allows you to have multiple wallets in different directories.

### Opening a wallet

When you run the CLI, you will be prompted to open a wallet. To do so, you can either create a new wallet or recover one with a mnemonic phrase.

- Creating a wallet

  - Enter `1` to accept the given phrase or `2` to generate a new one.
  - After a mnemonic phrase is accepted, follow the prompt to create a password.

- Recover a wallet

  - Enter `3` and the mnemonic phrase associated with the wallet.
  - Follow the prompts to create a new password.

### Running commands

Once you have an open wallet, you will get the REPL prompt, `>`. Now you can type `help` to view a list of commands you can execute and the arguments you need to specify.

- Transaction operations

  - `transfer`: transfer some owned assets to another user
  - `transfer_from`: transfer some assets from an owned address to another user
    - Note: Unlike the `transfer` command which allocates from all addresses owned by this wallet, `transfer_from` uses only the specified address, so make sure the address has sufficient balance.
  - `create_asset`: create a new asset
  - `mint`: mint an asset
    - Note: The `asset` argument must be an already-created asset. To create an asset, use the `create` command.
  - `freeze`: freeze assets owned by another user.
    - Note: The `asset` argument must be a freezable asset.
  - `unfreeze`: unfreeze previously frozen assets owned by another user
  - `wait`: wait for a transaction to complete
  - `sync`: wait until the wallet has processed up to a given event index

- Information listing

  - `address`: print all public addresses of this wallet
  - `pub_key`: print all public keys of this wallet
  - `assets`: list assets known to the wallet
  - `asset`: print information about an asset
  - `balance`: print owned balances of asset
    - Note: It is not the balance owned by one address, but the total balance of all addresses of this wallet.
  - `transactions`: list past transactions sent and received by this wallet
  - `transaction`: print the status of a transaction
  - `keys`: list keys tracked by this wallet
  - `info`: print general information about this wallet
  - `view`: list unspent records of viewable asset types
  - `now`: print the index of the latest event processed by the wallet

- Key and record operations

  - `gen_key`: generate new keys
  - `load_key`: load a key from a file
  - `import_memo`: import an owner memo belonging to this wallet
  - `import_asset`: import an asset type
