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

use address_book::{
    address_book_port, address_book_store_path, insert_pubkey, request_peers, request_pubkey,
    FileStore, ServerState,
};
use async_std::sync::{Arc, RwLock};
use clap::Parser;
use config::ConfigError;
use futures::FutureExt;
use jf_cap::keys::UserAddress;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::{fs, io::Error, path::PathBuf, process};
use tagged_base64::*;
use tide_disco::{
    configure_router, get_api_path, get_settings, http::StatusCode, init_web_server, load_api, Api,
    App, AppServerState, ConfigKey, HealthStatus::*,
};
use toml::{from_slice, value::Value};
use tracing::info;
use url::Url;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    /// Server address
    base_url: Option<Url>,
    #[clap(long)]
    /// HTTP routes
    api_toml: Option<PathBuf>,
    /// If true, log in color. Otherwise, no color.
    #[clap(long)]
    ansi_color: Option<bool>,
}

// impl Interrupt for InterruptHandle {
//     fn signal_action(signal: i32) {
//         // TOOD modify web_state based on the signal.
//         println!("\nReceived signal {}", signal);
//         process::exit(1);
//     }
// }

#[derive(Clone, Debug, Deserialize, Serialize, Snafu)]
enum AddressBookError {
    Config { msg: String },
}

impl From<ConfigError> for AddressBookError {
    fn from(error: ConfigError) -> Self {
        Self::Config {
            msg: error.to_string(),
        }
    }
}

impl From<std::io::Error> for AddressBookError {
    fn from(error: std::io::Error) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
        }
    }
}

impl From<toml::de::Error> for AddressBookError {
    fn from(error: toml::de::Error) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
        }
    }
}

impl tide_disco::Error for AddressBookError {
    fn catch_all(status: StatusCode, msg: String) -> Self {
        unimplemented!();
    }
    fn status(&self) -> StatusCode {
        StatusCode::InternalServerError
    }
}

#[async_std::main]
async fn main() -> Result<(), AddressBookError> {
    // let cleanup_signals = register_interrupt_signals();

    // Combine settings from multiple sources.
    let settings = get_settings::<Args>()?;

    // Colorful logs upon request.
    let want_color = settings.get_bool("ansi_color").unwrap_or(false);

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(want_color)
        .init();

    // Fetch the configuration values before any slow operations.
    let api_toml = &settings.get_string(ConfigKey::api_toml.as_ref())?;
    let base_url = &settings.get_string(ConfigKey::base_url.as_ref())?;

    let store_path = address_book_store_path();
    info!("Using store path {:?}", store_path);
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(store_path);
    let mut server_state = ServerState {
        store: Arc::new(store),
    };
    let mut app = App::<_, AddressBookError>::with_state(RwLock::new(server_state));
    info!("Using API path {:?}", api_toml);
    let mut api = Api::<RwLock<ServerState<FileStore>>, AddressBookError>::new(toml::from_slice(
        &fs::read(api_toml)?,
    )?)
    .unwrap();

    // Define the handlers for the routes
    api.post("insert_pubkey", |req_params, server_state| {
        async move {
            info!("insert pubkey");
            Ok(format!(
                "insert pubkey req_params.body_bytes(): {:?}",
                req_params.body_bytes()
            ))
            // insert_pubkey(req_params, server_state)
        }
        .boxed()
    })
    .unwrap();
    api.post("request_pubkey", |req_params, server_state| {
        async move {
            info!("request pubkey");
            info!("dummy UserAddress: {}", UserAddress::default());
            info!(
                "serialized: {:?}",
                bincode::serialize(&UserAddress::default()).unwrap()
            );
            let bytes = req_params.body_bytes();
            info!("bytes: {:?}", bytes);
            let s = String::from_utf8_lossy(&bytes);
            info!("string: {}", s);
            let tb64: TaggedBase64 = TaggedBase64::parse(&s).unwrap();
            info!("tb64 value: {:?}", tb64.value());
            // let address: UserAddress = bincode::deserialize(&bytes).unwrap();
            // let address: UserAddress = bincode::deserialize(&tb64.value()).unwrap();
            // let address: UserAddress = bincode::deserialize(&s.as_bytes()).unwrap();
            // info!("address from tb64 value: {:?}", address);
            Ok(format!("request pubkey for address: {:?}", address))
        }
        .boxed()
    })
    .unwrap();

    app.register_module("", api).unwrap();
    app.serve(base_url)
        .await
        .map_err(|err| AddressBookError::Config {
            msg: err.to_string(),
        })

    // cleanup_signals.await;
    //    Ok(())
}

#[cfg(windows)]
async fn register_interrupt_signals() {
    // Signals aren't properly supported on windows so we'll just exit
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
