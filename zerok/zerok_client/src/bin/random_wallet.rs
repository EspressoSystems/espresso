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
// a key pair using `zerok_client -g KEY_FILE`, and then pass the public key to the validators with
// `-w KEY_FILE.pub` and pass the key pair to `random_keystore` with `-k KEY_FILE`.

use async_std::task::sleep;
use jf_cap::keys::UserPubKey;
use jf_cap::structs::{AssetCode, AssetPolicy};
use rand::distributions::weighted::WeightedError;
use rand::seq::SliceRandom;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use seahorse::{events::EventIndex, hd::KeyTree, loader::KeystoreLoader, KeySnafu, KeystoreError};
use snafu::ResultExt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use tempdir::TempDir;
use tracing::{event, Level};
use zerok_lib::{
    keystore::network::{NetworkBackend, Url},
    ledger::EspressoLedger,
    universal_params::UNIVERSAL_PARAM,
};

type Keystore = seahorse::Keystore<'static, NetworkBackend<'static>, EspressoLedger, ()>;

#[derive(StructOpt)]
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
}

struct TrivialKeystoreLoader {
    dir: PathBuf,
}

impl KeystoreLoader<EspressoLedger> for TrivialKeystoreLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<EspressoLedger>> {
        let key = KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)?;
        Ok(((), key))
    }

    fn load(&mut self, _meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<EspressoLedger>> {
        KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)
    }
}

async fn retry_delay() {
    sleep(Duration::from_secs(1)).await
}

async fn get_peers(url: &Url) -> Result<Vec<UserPubKey>, surf::Error> {
    let mut response = surf::get(format!("{}/request_fee_assets", url))
        .content_type(surf::http::mime::JSON)
        .await?;
    let bytes = response.body_bytes().await.unwrap();
    let pub_keys: Vec<UserPubKey> = bincode::deserialize(&bytes)?;
    Ok(pub_keys)
}

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(Level::INFO.into()),
        )
        .init();

    let args = Args::from_args();

    let mut rng = ChaChaRng::seed_from_u64(args.seed.unwrap_or(0));
    let tempdir = TempDir::new("keystore").unwrap();
    let storage = args
        .storage
        .unwrap_or_else(|| PathBuf::from(tempdir.path()));

    let mut loader = TrivialKeystoreLoader { dir: storage };
    let backend = NetworkBackend::new(
        &*UNIVERSAL_PARAM,
        args.esqs_url.clone(),
        args.address_book_url.clone(),
        args.validator_url.clone(),
        // &mut loader,
    )
    .await
    .expect("failed to connect to backend");
    let mut keystore = Keystore::new(backend, &mut loader)
        .await
        .expect("error loading keystore");
    match args.key_path {
        Some(path) => {
            let mut file = File::open(path).unwrap_or_else(|err| {
                panic!("cannot open private key file: {}", err);
            });
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap_or_else(|err| {
                panic!("error reading private key file: {}", err);
            });
            keystore
                .add_user_key(
                    bincode::deserialize(&bytes).unwrap_or_else(|err| {
                        panic!("invalid private key file: {}", err);
                    }),
                    "Random keystore key".to_string(),
                    EventIndex::default(),
                )
                .await
                .unwrap_or_else(|err| {
                    panic!("error loading key: {}", err);
                });
        }
        None => {
            keystore
                .generate_user_key("Random Key".to_string(), None)
                .await
                .unwrap();
        }
    }

    let pub_key = keystore.pub_keys().await.remove(0);
    let address = pub_key.address();
    let receiver_key_bytes = bincode::serialize(&pub_key).unwrap();

    // Request native asset for the keystore.
    surf::post(format!("{}/request_fee_assets", args.faucet_url))
        .content_type(surf::http::mime::BYTE_STREAM)
        .body_bytes(&receiver_key_bytes)
        .await
        .unwrap();

    // Wait for initial balance.
    while keystore.balance(&AssetCode::native()).await == 0u64.into() {
        event!(Level::INFO, "waiting for initial balance");
        retry_delay().await;
    }

    // Check if we already have a mintable asset (if we are loading from a saved keystore).
    let my_asset = match keystore
        .assets()
        .await
        .into_iter()
        .find(|info| info.mint_info.is_some())
    {
        Some(info) => {
            event!(
                Level::INFO,
                "found saved keystore with custom asset type {}",
                info.definition.code
            );
            info.definition
        }
        None => {
            let my_asset = keystore
                .define_asset(
                    "Random keystore asset".to_string(),
                    &[],
                    AssetPolicy::default(),
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
            match peers.choose_weighted(
                &mut rng,
                |pk| {
                    if *pk == pub_key.clone() {
                        0u64
                    } else {
                        1u64
                    }
                },
            ) {
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
            if keystore.balance(&info.definition.code).await > 0u64.into() {
                asset_balances.push(info.definition.code);
            }
        }
        // Randomly choose an asset type for the transfer.
        let asset = asset_balances.choose(&mut rng).unwrap();

        // All transfers are the same, small size. This should prevent fragmentation errors and
        // allow us to make as many transactions as possible with the assets we have.
        let amount = 1;
        let fee = 1;

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
