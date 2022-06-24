// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use address_book::{address_book_port, address_book_store_path, init_web_server, FileStore};
use std::fs;

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let cleanup_signals = register_interrupt_signals();

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let store_path = address_book_store_path();
    tracing::info!("Using store path {:?}", store_path);
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(store_path);

    init_web_server(address_book_port(), store)
        .await
        .unwrap_or_else(|err| {
            panic!("Web server exited with an error: {}", err);
        })
        .await?;

    cleanup_signals.await;

    Ok(())
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
