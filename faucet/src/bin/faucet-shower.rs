// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Turns a trickle into a shower.
//!
//! Give faucet-shower a master mnemonic for a funded keystore and a number N and it will generate N
//! new keystores, transfer some tokens from the master keystore to each new keystore, and print the
//! mnemonics and public keys of the newly funded keystores.
use futures::stream::{iter, StreamExt};
use jf_cap::structs::AssetCode;
use primitive_types::U256;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;
use structopt::StructOpt;
use surf::Url;
use tempdir::TempDir;
use zerok_lib::{
    keystore::{
        hd::KeyTree,
        loader::{Loader, LoaderMetadata},
        network::NetworkBackend,
        txn_builder::TransactionStatus,
        EspressoKeystore, EspressoKeystoreError,
    },
    universal_params::UNIVERSAL_PARAM,
};

#[derive(Debug, StructOpt)]
pub struct Options {
    /// mnemonic for the master faucet keystore
    #[structopt(short, long, env = "ESPRESSO_FAUCET_WALLET_MNEMONIC")]
    pub master_mnemonic: String,

    /// number of new keystores to generate
    #[structopt(short, long, default_value = "10")]
    pub num_keystores: usize,

    /// number of records to create in each new keystore
    #[structopt(short, long, default_value = "1")]
    pub num_records: u64,

    /// size of each record to create in the new keystores
    #[structopt(short, long, default_value = "1000000")]
    pub record_size: u64,

    /// URL for the Ethereum Query Service.
    #[structopt(
        long,
        env = "ESPRESSO_ESQS_URL",
        default_value = "http://localhost:50087"
    )]
    pub esqs_url: Url,
}

async fn create_keystore(
    opt: &Options,
    rng: &mut ChaChaRng,
    mnemonic: String,
    dir: PathBuf,
) -> Result<EspressoKeystore<'static, NetworkBackend<'static, LoaderMetadata>>, EspressoKeystoreError>
{
    // We are never going to re-open this keystore once it's created, so we don't really need a
    // password. Just make it random bytes.
    let mut password = [0; 32];
    rng.fill_bytes(&mut password);
    let mut loader = Loader::from_literal(Some(mnemonic), hex::encode(password), dir);
    let backend = NetworkBackend::new(
        &*UNIVERSAL_PARAM,
        opt.esqs_url.clone(),
        opt.esqs_url.clone(),
        opt.esqs_url.clone(),
        &mut loader,
    )?;
    EspressoKeystore::new(backend).await
}

#[async_std::main]
async fn main() {
    let opt = Options::from_args();
    let mut rng = ChaChaRng::from_entropy();
    let dir = TempDir::new("faucet-shower").unwrap();

    // Create the parent keystore.
    let parent_dir = [dir.path(), Path::new("parent")].iter().collect();
    let mut parent = create_keystore(&opt, &mut rng, opt.master_mnemonic.clone(), parent_dir)
        .await
        .unwrap();

    // Generate the key which will be used to transfer to the children. Tell it to start a scan
    // from the default index (the first event) so it can find records created by the faucet event.
    let parent_key = parent
        .generate_user_key("parent key".into(), Some(Default::default()))
        .await
        .unwrap();

    // While the ledger scan is going, create the child keystores.
    let children = iter(0..opt.num_keystores)
        .then(|i| {
            let mut rng = ChaChaRng::from_rng(&mut rng).unwrap();
            let dir = &dir;
            let opt = &opt;
            async move {
                let (_, mnemonic) = KeyTree::random(&mut rng);
                let dir = [dir.path(), Path::new(&format!("child_keystore_{}", i))]
                    .iter()
                    .collect();
                let mut keystore = create_keystore(opt, &mut rng, mnemonic.to_string(), dir)
                    .await
                    .unwrap();
                let key = keystore
                    .generate_user_key(format!("child key {}", i), None)
                    .await
                    .unwrap();
                (keystore, mnemonic, key)
            }
        })
        .collect::<Vec<_>>()
        .await;

    // Once we have all the keystores, we need to wait for the ledger scan so that the parent keystore
    // can discover a record to transfer from.
    parent.await_key_scan(&parent_key.address()).await.unwrap();
    let balance = parent.balance(&AssetCode::native()).await;
    let total_per_keystore = U256::from(opt.record_size) * opt.num_records;
    if balance < total_per_keystore * opt.num_keystores {
        eprintln!(
            "Insufficient balance for transferring {} units to {} keystores: {}",
            total_per_keystore, opt.num_keystores, balance
        );
        exit(1);
    }

    // Print out the generated child mnemonics and keys _before_ we start doing any transfers. If we
    // panic or get killed for any reason after we have transferred, it is crucial that we have
    // already reported all of the mnemonics needed to recover the funds.
    println!(
        "Transferring {} units each to the following keystores:",
        total_per_keystore
    );
    for (_, mnemonic, key) in &children {
        println!("{} {}", mnemonic, key);
    }

    // Do the transfers.
    for (_, _, key) in &children {
        for _ in 0..opt.num_records {
            match parent
                .transfer(
                    None,
                    &AssetCode::native(),
                    &[(key.clone(), opt.record_size)],
                    0,
                )
                .await
            {
                Ok(receipt) => match parent.await_transaction(&receipt).await {
                    Ok(TransactionStatus::Retired) => {
                        println!("Transferred {} units to {}", opt.record_size, key)
                    }
                    Ok(status) => eprintln!(
                        "Transfer to {} did not complete successfully: {}",
                        key, status
                    ),
                    Err(err) => eprintln!("Error while waiting for transfer to {}: {}", key, err),
                },
                Err(err) => eprintln!("Failed to transfer to {}: {}", key, err),
            }
        }
    }

    // Wait for the children to report the new balances.
    for (keystore, _, key) in &children {
        while keystore.balance(&AssetCode::native()).await < total_per_keystore {
            eprintln!(
                "Waiting for {} to receive {} tokens",
                key, total_per_keystore
            );
            async_std::task::sleep(Duration::from_secs(1)).await;
        }
    }
}
