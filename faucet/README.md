<!--
 ~ Copyright (c) 2022 Espresso Systems (espressosys.com)
 -->

# Faucet

A faucet service to issue Espresso native assets.

The faucet is a REST service that takes public keys as requests and distributes Espresso tokens to
each of those public keys. The amount of Espresso to send per request is configurable, as is the
number of records per request. Distributing more records makes each request take longer, but it is
ultimately more convenient for the receiver, as they can then use their multiple records to make
multiple simultaneous transfers.

For the faucet to work, it must be funded. The faucet just needs an Espresso wallet seed phrase to
work, so passing it any seed phrase that corresponds to a funded wallet will do. An easy way to set
it up is to use the same seed phrase both to generate the genesis block of the Espresso ledger and
to configure the faucet.

To run the faucet, after building the Espresso repo, run `target/release/faucet`. You can use
`target/release/faucet --help` to see usage information and configuration options.

When a faucet is running, you can send a POST request to `faucet.url/request_fee_assets` with a CAP
public key as the request body, and the faucet will transfer some Espresso to that key.
