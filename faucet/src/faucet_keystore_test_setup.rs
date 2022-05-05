// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A script to export environment variables for test deployments of the Esresso testnet.

use num_bigint::BigUint;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use structopt::StructOpt;
use zerok_lib::keystore::hd::{KeyTree, Mnemonic};

pub fn field_to_hex(f: impl Into<BigUint>) -> String {
    let bytes = f
        .into()
        .iter_u64_digits()
        .flat_map(|d| d.to_le_bytes())
        .rev()
        .collect::<Vec<_>>();
    hex::encode(&bytes)
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Espresso Faucet utility",
    about = "Create address and encryption key from mnemonic"
)]
pub struct Options {
    /// mnemonic for the faucet keystore (if not provided, a random mnemonic will be generated)
    #[structopt(long, env = "ESPRESSO_FAUCET_MANAGER_MNEMONIC")]
    pub mnemonic: Option<String>,
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let opt = Options::from_args();
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

    eprintln!("Faucet manager encryption key: {}", pub_key);
    eprintln!(
        "Faucet manager address: {}",
        net::UserAddress(pub_key.address())
    );

    let enc_key_bytes: [u8; 32] = pub_key.enc_key().into();
    let address = pub_key.address();
    println!("export CAPE_FAUCET_MANAGER_MNEMONIC=\"{}\"", mnemonic);
    println!(
        "export CAPE_FAUCET_MANAGER_ENC_KEY=0x{}",
        hex::encode(enc_key_bytes)
    );
    println!(
        "export CAPE_FAUCET_MANAGER_ADDRESS_X=0x{}",
        field_to_hex(address.internal().x)
    );
    println!(
        "export CAPE_FAUCET_MANAGER_ADDRESS_Y=0x{}",
        field_to_hex(address.internal().y)
    );
    Ok(())
}
