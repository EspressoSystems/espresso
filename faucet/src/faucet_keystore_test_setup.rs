// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

//! A script to export environment variables for test deployments of the Esresso testnet.

use clap::Parser;
use espresso_client::hd::{KeyTree, Mnemonic};
use num_bigint::BigUint;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

pub fn field_to_hex(f: impl Into<BigUint>) -> String {
    let bytes = f
        .into()
        .iter_u64_digits()
        .flat_map(|d| d.to_le_bytes())
        .rev()
        .collect::<Vec<_>>();
    hex::encode(&bytes)
}

#[derive(Debug, Parser)]
#[command(
    name = "Espresso Faucet utility",
    about = "Create address and encryption key from mnemonic"
)]
pub struct Options {
    /// mnemonic for the faucet keystore (if not provided, a random mnemonic will be generated)
    #[arg(long, env = "ESPRESSO_FAUCET_MANAGER_MNEMONIC")]
    pub mnemonic: Option<String>,
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let opt = Options::parse();
    let mnemonic = match opt.mnemonic {
        Some(phrase) => Mnemonic::from_phrase(phrase.replace('-', " ")).unwrap(),
        None => KeyTree::random(&mut ChaChaRng::from_entropy()).1,
    };

    // We don't actually want to create a keystore, just generate a key, so we will directly generate
    // the key stream that the faucet keystore will use.
    let pub_key = KeyTree::from_mnemonic(&mnemonic)
        .sending_key_stream()
        .sending_key(0)
        .pub_key();

    eprintln!("Faucet manager mnemonic: {}", mnemonic);
    eprintln!("Faucet manager encryption key: {}", pub_key);
    eprintln!("Faucet manager address: {}", pub_key.address());

    println!("export ESPRESSO_FAUCET_MANAGER_MNEMONIC=\"{}\"", mnemonic);
    println!("export ESPRESSO_FAUCET_PUB_KEY=\"{}\"", pub_key);
    Ok(())
}
