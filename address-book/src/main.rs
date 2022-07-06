// COPYRIGHT100 (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.

use address_book::{error::AddressBookError, init_web_server};
use clap::Parser;
use std::{fs, path::PathBuf};
use strum_macros::AsRefStr;
use tide::StatusCode;
use tide_disco::{get_settings, DiscoArgs, DiscoKey};
use tracing::{info, trace};
use url::Url;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(flatten)]
    disco_args: DiscoArgs,
    #[clap(long)]
    /// Storage path
    store_path: Option<PathBuf>,
}

/// Lookup keys for application-specific configuration settings
#[derive(AsRefStr, Debug)]
#[allow(non_camel_case_types)]
pub enum AppKey {
    store_path,
}

// impl Interrupt for InterruptHandle {
//     fn signal_action(signal: i32) {
//         // TOOD modify web_state based on the signal.
//         println!("\nReceived signal {}", signal);
//         process::exit(1);
//     }
// }

// TODO move to tide-disco
fn init_logging(want_color: bool) {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(want_color)
        .init();
}

use address_book::{
    store::{address_book_store_path, address_book_temp_dir, FileStore, Store, TransientFileStore},
    wait_for_server, InsertPubKey,
};
use async_std::task::spawn;
use jf_cap::keys::{UserKeyPair, UserPubKey};
use portpicker::pick_unused_port;
use rand_chacha::rand_core::SeedableRng;
use std::collections::HashSet;

const ROUND_TRIP_COUNT: u64 = 10; //100;
const NOT_FOUND_COUNT: u64 = 10; //100;

// Test
//    lookup(insert(x)) = x
// and
//    lookup(y) = Err, if y has not been previously inserted.
//
async fn round_trip<T: Store + 'static>(store: T) {
    let port = pick_unused_port().unwrap();
    let base_url: String = format!("http://127.0.0.1:{port}");
    let settings = get_settings::<Args>().unwrap();
    let api_toml = &settings.get_string(DiscoKey::api_toml.as_ref()).unwrap();
    let app = init_web_server(api_toml.to_string(), store).unwrap();

    let handle = spawn(app.serve(base_url.clone()));
    wait_for_server(&base_url).await;

    let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
    let mut rng2 = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
    let mut inserted = HashSet::new();

    // Insert and lookup a bunch of address/key pairs.
    for _ in 0..ROUND_TRIP_COUNT {
        let user_key = UserKeyPair::generate(&mut rng);
        let pub_key = user_key.pub_key();
        inserted.insert(pub_key.clone());
        let pub_key_bytes = bincode::serialize(&pub_key).unwrap();
        let sig = user_key.sign(&pub_key_bytes);
        let json_request = InsertPubKey { pub_key_bytes, sig };
        let response = surf::post(format!("{base_url}/insert_pubkey"))
            .content_type(surf::http::mime::JSON)
            .body_json(&json_request)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::Ok);
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let mut response = surf::post(format!("{base_url}/request_pubkey"))
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::Ok);
        let gotten_pub_key: UserPubKey = response.body_json().await.unwrap();
        assert_eq!(gotten_pub_key, pub_key);
        let mut response = surf::get(format!("{base_url}/request_peers"))
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        let gotten_pub_keys: Vec<UserPubKey> = serde_json::from_slice(&bytes).unwrap();
        let gotten_set: HashSet<UserPubKey> = gotten_pub_keys.into_iter().collect();
        assert_eq!(gotten_set, inserted);
    }
    // Lookup the addresses just inserted to demonstrate that all the keys
    // are still present after the lookups.
    for _ in 0..ROUND_TRIP_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let mut response = surf::post(format!("{base_url}/request_pubkey"))
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes)
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        let gotten_pub_key: UserPubKey = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(gotten_pub_key, pub_key);
    }

    // Lookup addresses we didn't insert.
    trace!(
        "The following {} 'No such' errors are expected.",
        NOT_FOUND_COUNT
    );
    for _ in 0..NOT_FOUND_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let mut response = surf::post(format!("{base_url}/request_pubkey"))
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes)
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        assert!(bincode::deserialize::<UserPubKey>(&bytes).is_err());
    }
    assert!(handle.cancel().await.is_none());
}

async fn test_address_book() {
    // Can change to using two separate tests once the webserver port is
    // configurable.
    let temp_dir = address_book_temp_dir();
    let store = FileStore::new(temp_dir.path().to_path_buf());
    round_trip(store).await;

    let store = TransientFileStore::default();
    round_trip(store).await
}

#[async_std::main]
async fn main() -> Result<(), AddressBookError> {
    // let cleanup_signals = register_interrupt_signals();

    // Combine settings from multiple sources.
    let settings = get_settings::<Args>()?;

    info!(
        "Store path: {:?}",
        &settings.get_string(AppKey::store_path.as_ref())?
    );

    // Colorful logs upon request.
    let want_color = settings.get_bool("ansi_color").unwrap_or(false);

    init_logging(want_color);

    // Fetch the configuration values before any slow operations.
    let api_toml = &settings.get_string(DiscoKey::api_toml.as_ref())?;
    let base_url = &settings.get_string(DiscoKey::base_url.as_ref())?;

    let store_path = address_book_store_path();
    info!("Using store path {:?}", store_path);
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(store_path);

    let app = init_web_server(api_toml.to_string(), store)?;

    test_address_book().await;
    Ok(())
    /*
        app.serve(base_url)
            .await
            .map_err(|err| AddressBookError::Config {
                msg: err.to_string(),
            })
    */
    // cleanup_signals.await;
    //    Ok(())
}

#[cfg(windows)]
async fn register_interrupt_signals() {
    // Signals aren't properly supported on windows so we'll just exit
    process::exit(1);
}

#[cfg(not(windows))]
fn register_interrupt_signals() -> impl std::future::Future<Output = ()> {
    use address_book::signal::handle_signals;
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook_async_std::Signals;

    let signals = Signals::new(&[SIGINT, SIGTERM]).expect("Failed to create signals.");
    let handle = signals.handle();
    let signals_task = async_std::task::spawn(handle_signals(signals));

    async move {
        handle.close();
        signals_task.await;
    }
}
