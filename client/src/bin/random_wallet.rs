// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

// A keystore that generates random transactions, for testing purposes.
//
// Spin up a random keystore and point it at a query service like so:
//  random_keystore storage/random_keystore_N localhost:50000
//
// The keystore will discover its peers (all of the other keystores connected to the same query service)
// and begin making random transactions as follows:
//  * define a new custom asset type and mint 2^32 tokens for ourselves
//  * repeatedly:
//      - randomly select an asset type for which we have a nonzero balance
//      - transfer a fraction of that asset type to a randomly selected peer
//
// There can be multiple groups of keystores connected to different query servers. Keystores will only
// interact with other keystores in the same group.
//
// Note that the ledger must be initialized with a balance of native assets for each random keystore
// by passing the public key of each keystore that should receive funds to each validator with
// `--keystore`. This requires having the public key before starting `random_keystore`. You can generate
// a key pair using `wallet-cli -g KEY_FILE`, and then pass the public key to the validators with
// `-w KEY_FILE.pub` and pass the key pair to `random_keystore` with `-k KEY_FILE`.

use async_std::task::sleep;
use espresso_core::{ledger::EspressoLedger, universal_params::UNIVERSAL_PARAM};
use jf_cap::keys::{FreezerPubKey, UserKeyPair, UserPubKey};
use jf_cap::structs::{AssetCode, AssetPolicy, FreezeFlag};
use rand::distributions::weighted::WeightedError;
use rand::seq::SliceRandom;
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use seahorse::txn_builder::RecordInfo;
use seahorse::{events::EventIndex, hd::KeyTree, loader::KeystoreLoader, KeystoreError};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use surf::StatusCode;
use tempdir::TempDir;
use tracing::{event, Level};
use validator_node::{
    api::client::response_body,
    keystore::network::{NetworkBackend, Url},
};

#[derive(Debug)]
pub enum OperationType {
    Transfer,
    Freeze,
    Unfreeze,
    Mint,
}

impl Distribution<OperationType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OperationType {
        match rng.gen_range(0..=12) {
            0 => OperationType::Mint,
            1 => OperationType::Freeze,
            2 => OperationType::Unfreeze,
            // Bias toward transfer
            _ => OperationType::Transfer,
        }
    }
}

type Keystore = seahorse::Keystore<'static, NetworkBackend<'static>, EspressoLedger, ()>;

/// Return records the freezer has access to freeze or unfreeze but does not own.
/// Will only return records with freeze_flag the same as the frozen arg.
pub async fn find_freezable_records<'a>(freezer: &Keystore, frozen: FreezeFlag) -> Vec<RecordInfo> {
    let pks: HashSet<UserPubKey> = freezer.pub_keys().await.into_iter().collect();
    let freeze_keys: HashSet<FreezerPubKey> =
        freezer.freezer_pub_keys().await.into_iter().collect();
    let records = freezer.records().await;
    records
        .filter(|r| {
            let ro = &r.ro;
            // Ignore records we own
            if pks.contains(&ro.pub_key) {
                return false;
            }
            // Check we can freeeze
            if !(freeze_keys.contains(ro.asset_def.policy_ref().freezer_pub_key())) {
                return false;
            }
            ro.freeze_flag == frozen
        })
        .collect()
}

#[derive(StructOpt, Debug)]
struct Args {
    /// Path to a private key file to use for the keystore.
    ///
    /// If not given, new keys are generated randomly.
    #[structopt(short, long)]
    key_path: Option<PathBuf>,

    /// Seed for random number generation.
    #[structopt(long)]
    seed: Option<u64>,

    /// Path to a saved keystore, or a new directory where this keystore will be saved.
    /// Will use a TempDir if not provided
    #[structopt(long, env = "ESPRESSO_RANDOM_WALLET_PATH")]
    storage: Option<PathBuf>,

    /// URL of a server for querying with the ledger
    #[structopt(short, long, env = "ESPRESSO_ESQS_URL")]
    esqs_url: Url,

    /// URL of a server for interacting with the ledger
    #[structopt(short, long, env = "ESPRESSO_SUBMIT_URL")]
    validator_url: Url,

    /// URL of a server for address book
    #[structopt(short, long, env = "ESPRESSO_ADDRESS_BOOK_URL")]
    address_book_url: Url,

    #[structopt(short, long, env = "ESPRESSO_FAUCET_URL")]
    faucet_url: Url,

    /// Whether to color log output with ANSI color codes.
    #[structopt(long, env = "ESPRESSO_COLORED_LOGS")]
    colored_logs: bool,
}

struct TrivialKeystoreLoader {
    pub dir: PathBuf,
    pub key_tree: KeyTree,
}

impl KeystoreLoader<EspressoLedger> for TrivialKeystoreLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<((), KeyTree), KeystoreError<EspressoLedger>> {
        Ok(((), self.key_tree.clone()))
    }

    fn load(&mut self, _meta: &mut ()) -> Result<KeyTree, KeystoreError<EspressoLedger>> {
        Ok(self.key_tree.clone())
    }
}

async fn retry_delay() {
    sleep(Duration::from_secs(1)).await
}

async fn get_peers(url: &Url) -> Result<Vec<UserPubKey>, surf::Error> {
    let mut response = surf::get(format!("{}request_peers", url))
        .content_type(surf::http::mime::JSON)
        .await?;
    let pub_keys: Vec<UserPubKey> = response_body(&mut response).await?;
    event!(Level::INFO, "peers {} ", pub_keys.len());
    Ok(pub_keys)
}

#[async_std::main]
async fn main() {
    let args = Args::from_args();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(args.colored_logs)
        .init();
    event!(Level::INFO, "args = {:?}", args);
    let seed = args
        .seed
        .unwrap_or_else(|| ChaChaRng::from_entropy().next_u64());
    event!(Level::INFO, "Using Seed {}", seed);
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let tempdir = TempDir::new("keystore").unwrap();
    let storage = args
        .storage
        .unwrap_or_else(|| PathBuf::from(tempdir.path()));

    let mut loader = TrivialKeystoreLoader {
        dir: storage,
        key_tree: KeyTree::random(&mut rng).0,
    };
    let backend = NetworkBackend::new(
        &UNIVERSAL_PARAM,
        args.esqs_url.clone(),
        args.address_book_url.clone(),
        args.validator_url.clone(),
    )
    .await
    .expect("failed to connect to backend");
    let mut keystore = Keystore::new(backend, &mut loader)
        .await
        .expect("error loading keystore");
    let pub_key = match args.key_path {
        Some(path) => {
            let mut file = File::open(path).unwrap_or_else(|err| {
                panic!("cannot open private key file: {}", err);
            });
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap_or_else(|err| {
                panic!("error reading private key file: {}", err);
            });
            let key_pair: UserKeyPair = bincode::deserialize(&bytes).unwrap_or_else(|err| {
                panic!("invalid private key file: {}", err);
            });
            keystore
                .add_user_key(
                    key_pair.clone(),
                    "Random keystore key".to_string(),
                    EventIndex::default(),
                )
                .await
                .unwrap_or_else(|err| {
                    panic!("error loading key: {}", err);
                });
            key_pair.pub_key()
        }
        None => {
            keystore
                .generate_viewing_key("view key".to_string())
                .await
                .unwrap();
            keystore
                .generate_freeze_key("freeze key".to_string())
                .await
                .unwrap();
            keystore
                .generate_user_key("Random Key".to_string(), Some(EventIndex::default()))
                .await
                .unwrap()
        }
    };
    let address = pub_key.address();
    event!(Level::INFO, "address = {:?}", address);

    // Wait for the scan of the ledger to catch up.
    keystore.await_key_scan(&address).await.unwrap();

    if keystore.balance(&AssetCode::native()).await == 0u64.into() {
        // Request native asset for the keystore.
        let receiver_key_bytes = bincode::serialize(&pub_key).unwrap();
        loop {
            match surf::post(format!("{}request_fee_assets", args.faucet_url))
                .content_type(surf::http::mime::BYTE_STREAM)
                .body_bytes(&receiver_key_bytes)
                .await
            {
                Ok(res) if res.status() == StatusCode::Ok => {
                    break;
                }
                Ok(res) => {
                    tracing::error!("retrying faucet because of {} response", res.status());
                    retry_delay().await;
                }
                Err(err) => {
                    tracing::error!("Retrying faucet because of {:?}", err);
                    retry_delay().await;
                }
            }
        }

        // Wait for initial balance.
        while keystore.balance(&AssetCode::native()).await == 0u64.into() {
            event!(Level::INFO, "waiting for initial balance");
            retry_delay().await;
        }
    }
    tracing::info!(
        "initial balance: {}",
        keystore.balance(&AssetCode::native()).await
    );

    // Check if we already have a mintable asset (if we are loading from a saved keystore).
    let my_asset = match keystore
        .assets()
        .await
        .into_iter()
        .find(|info| info.mint_info().is_some())
    {
        Some(info) => {
            event!(
                Level::INFO,
                "found saved keystore with custom asset type {}",
                info.code()
            );
            info.definition().clone()
        }
        None => {
            let my_asset = keystore
                .define_asset(
                    "Random keystore asset".to_string(),
                    &[],
                    AssetPolicy::default()
                        .set_viewer_pub_key(keystore.viewer_pub_keys().await[0].clone())
                        .set_freezer_pub_key(keystore.freezer_pub_keys().await[0].clone())
                        .reveal_record_opening()
                        .unwrap(),
                )
                .await
                .expect("failed to define asset");
            event!(Level::INFO, "defined a new asset type: {}", my_asset.code);
            my_asset
        }
    };
    // If we don't yet have a balance of our asset type, mint some.
    if keystore.balance(&my_asset.code).await == 0u64.into() {
        event!(Level::INFO, "minting my asset type {}", my_asset.code);
        loop {
            let txn = keystore
                .mint(
                    Some(&address),
                    1,
                    &my_asset.code,
                    1u64 << 32,
                    pub_key.clone(),
                )
                .await
                .expect("failed to generate mint transaction");
            let status = keystore
                .await_transaction(&txn)
                .await
                .expect("error waiting for mint to complete");
            if status.succeeded() {
                break;
            }
            // The mint transaction is allowed to fail due to contention from other clients.
            event!(Level::WARN, "mint transaction failed, retrying...");
            retry_delay().await;
        }
        event!(Level::INFO, "minted custom asset");
    }

    let mut peers = vec![];

    loop {
        // Get a list of all users in our group (this will include our own public key).
        // Filter out our own public key and randomly choose one of the other ones to transfer to.
        peers = match get_peers(&args.address_book_url).await {
            Ok(results) => results,
            Err(_) => {
                event!(Level::ERROR, "Failed to refresh peers from address book");
                peers
            }
        };
        let recipient =
            match peers.choose_weighted(&mut rng, |pk| if *pk == pub_key { 0u64 } else { 1u64 }) {
                Ok(recipient) => recipient,
                Err(WeightedError::NoItem | WeightedError::AllWeightsZero) => {
                    event!(Level::INFO, "no peers yet, retrying...");
                    retry_delay().await;
                    continue;
                }
                Err(err) => {
                    panic!("error in weighted choice of peer: {}", err);
                }
            };

        // Get a list of assets for which we have a non-zero balance.
        let mut asset_balances = vec![];
        for info in keystore.assets().await {
            if keystore.balance(&info.code()).await > 0u64.into() {
                asset_balances.push(info.code());
            }
        }
        // Randomly choose an asset type for the transfer.
        let asset = asset_balances.choose(&mut rng).unwrap();

        let operation: OperationType = rand::random();
        // All transfers are the same, small size. This should prevent fragmentation errors and
        // allow us to make as many transactions as possible with the assets we have.
        let amount = 10;
        let fee = 1;

        match operation {
            OperationType::Transfer => {
                event!(
                    Level::INFO,
                    "transferring {} units of {} to user {}",
                    amount,
                    if *asset == AssetCode::native() {
                        String::from("the native asset")
                    } else if *asset == my_asset.code {
                        String::from("my asset")
                    } else {
                        asset.to_string()
                    },
                    recipient,
                );
                let txn = match keystore
                    .transfer(Some(&address), asset, &[(recipient.clone(), amount)], fee)
                    .await
                {
                    Ok(txn) => txn,
                    Err(err) => {
                        event!(Level::ERROR, "Error generating transfer: {}", err);
                        continue;
                    }
                };
                match keystore.await_transaction(&txn).await {
                    Ok(status) => {
                        if !status.succeeded() {
                            // Transfers are allowed to fail. It can happen, for instance, if we get starved
                            // out until our transfer becomes too old for the validators. Thus we make this
                            // a warning, not an error.
                            event!(Level::WARN, "transfer failed!");
                        }
                    }
                    Err(err) => {
                        event!(Level::ERROR, "error while waiting for transaction: {}", err);
                    }
                }
            }
            OperationType::Mint => {
                let new_asset = match keystore
                    .define_asset(
                        "Random keystore asset".to_string(),
                        &[],
                        AssetPolicy::default()
                            .set_viewer_pub_key(keystore.viewer_pub_keys().await[0].clone())
                            .set_freezer_pub_key(keystore.freezer_pub_keys().await[0].clone())
                            .reveal_record_opening()
                            .unwrap(),
                    )
                    .await
                {
                    Ok(txn) => txn,
                    Err(err) => {
                        event!(Level::ERROR, "Error defining asset: {}", err);
                        continue;
                    }
                };

                event!(Level::INFO, "defined a new asset type: {}", new_asset.code);

                event!(Level::INFO, "minting my asset type {}", new_asset.code);
                let txn = match keystore
                    .mint(
                        Some(&address),
                        1,
                        &new_asset.code,
                        1u64 << 32,
                        pub_key.clone(),
                    )
                    .await
                {
                    Ok(txn) => txn,
                    Err(err) => {
                        event!(Level::ERROR, "Error minting asset: {}", err);
                        continue;
                    }
                };
                match keystore.await_transaction(&txn).await {
                    Ok(status) => {
                        if !status.succeeded() {
                            event!(Level::WARN, "mint failed!");
                        }
                    }
                    Err(err) => {
                        event!(Level::ERROR, "error while waiting for mint: {}", err);
                    }
                }
                // The mint transaction is allowed to fail due to contention from other clients.
                retry_delay().await;
                event!(Level::INFO, "minted custom asset");
            }
            OperationType::Freeze => {
                let freezable_records: Vec<RecordInfo> =
                    find_freezable_records(&keystore, FreezeFlag::Unfrozen).await;
                if freezable_records.is_empty() {
                    event!(Level::INFO, "No freezable records");
                    continue;
                }
                let record = freezable_records.choose(&mut rng).unwrap();
                let owner_address = record.ro.pub_key.address().clone();
                let asset_def = &record.ro.asset_def;
                event!(
                    Level::INFO,
                    "Freezing Asset: {}, Amount: {}, Owner: {}",
                    asset_def.code,
                    record.ro.amount,
                    owner_address
                );
                let freeze_address = keystore.pub_keys().await[0].address();

                keystore
                    .freeze(
                        Some(&freeze_address),
                        fee,
                        &asset_def.code,
                        record.amount(),
                        owner_address,
                    )
                    .await
                    .ok();
            }
            OperationType::Unfreeze => {
                event!(Level::INFO, "Unfreezing");
                let freezable_records: Vec<RecordInfo> =
                    find_freezable_records(&keystore, FreezeFlag::Frozen).await;
                if freezable_records.is_empty() {
                    event!(Level::INFO, "No frozen records");
                    continue;
                }
                let record = freezable_records.choose(&mut rng).unwrap();
                let owner_address = record.ro.pub_key.address();
                let asset_def = &record.ro.asset_def;
                event!(
                    Level::INFO,
                    "Unfreezing Asset: {}, Amount: {}, Owner: {}",
                    asset_def.code,
                    record.ro.amount,
                    owner_address
                );
                let freeze_address = keystore.pub_keys().await[0].address();
                keystore
                    .unfreeze(
                        Some(&freeze_address),
                        fee,
                        &asset_def.code,
                        record.amount(),
                        owner_address,
                    )
                    .await
                    .ok();
            }
        }

        event!(
            Level::INFO,
            "Wallet Native balance {}",
            keystore.balance(&AssetCode::native()).await
        );
        event!(
            Level::INFO,
            "Wallet Custom Asset balance {}",
            keystore.balance(&my_asset.code).await
        );
        retry_delay().await;
    }
}
