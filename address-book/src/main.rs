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

use address_book::{address_book_store_path, init_web_server, AddressBookError, FileStore};
use clap::Parser;
use std::{fs, path::PathBuf};
use tide_disco::{get_settings, ConfigKey};
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

// TODO move to tide-disco
fn init_logging(want_color: bool) {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(want_color)
        .init();
}

#[async_std::main]
async fn main() -> Result<(), AddressBookError> {
    // let cleanup_signals = register_interrupt_signals();

    // Combine settings from multiple sources.
    let settings = get_settings::<Args>()?;

    // Colorful logs upon request.
    let want_color = settings.get_bool("ansi_color").unwrap_or(false);

    init_logging(want_color);

    // Fetch the configuration values before any slow operations.
    let api_toml = &settings.get_string(ConfigKey::api_toml.as_ref())?;
    let base_url = &settings.get_string(ConfigKey::base_url.as_ref())?;

    let store_path = address_book_store_path();
    info!("Using store path {:?}", store_path);
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(store_path);

    let app = init_web_server(api_toml.to_string(), store)?;

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
