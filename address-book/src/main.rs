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
    error::AddressBookError, init_web_server, store::address_book_store_path, store::FileStore,
    AppKey, Args, APP_NAME,
};
use espresso_systems_common::brand::ORG_DIR_NAME;
use std::fs;
use std::path::PathBuf;
use tide_disco::{compose_settings, init_logging, DiscoKey};

#[cfg(windows)]
async fn register_interrupt_signals() {
    // Signals aren't properly supported on Windows so we'll just complain.
    trace!("Custom signal handlers are not supported on Windows.");
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

#[async_std::main]
async fn main() -> Result<(), AddressBookError> {
    let cleanup_signals = register_interrupt_signals();

    // Combine settings from multiple sources.
    let api_path = std::env::current_dir()
        .unwrap()
        .join("api")
        .join("api.toml");
    let settings = compose_settings::<Args>(
        &ORG_DIR_NAME,
        &APP_NAME,
        &[
            (
                DiscoKey::api_toml.as_ref(),
                &api_path.to_str().unwrap().to_string(),
            ),
            (DiscoKey::base_url.as_ref(), "http://127.0.0.1:50078"),
            (
                AppKey::store_path.as_ref(),
                &address_book_store_path().to_str().unwrap(),
            ),
        ],
    )?;

    // Colorful logs upon request.
    let want_color = settings.get_bool("ansi_color").unwrap_or(false);

    init_logging(want_color);

    let api_toml = settings.get_string(DiscoKey::api_toml.as_ref())?;
    let base_url = &settings.get_string(DiscoKey::base_url.as_ref())?;

    let store_path = &settings.get_string(AppKey::store_path.as_ref())?;
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(PathBuf::from(store_path));

    let app = init_web_server(api_toml, store)?;
    app.serve(base_url)
        .await
        .map_err(|err| AddressBookError::Config {
            msg: err.to_string(),
        })
        .unwrap();

    #[cfg(not(windows))]
    cleanup_signals.await;
    Ok(())
}
