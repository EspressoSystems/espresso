// Copyright (c) 2022 Espresso Systems (espressosys.com)

use async_std::prelude::*;
use signal_hook_async_std::Signals;
use std::process;

/// Spawn a thread that waits for SIGTERM. If SIGTERM is received,
/// the application exits with exit status 1.
pub async fn handle_signals(mut signals: Signals) {
    while let Some(signal) = signals.next().await {
        println!("Received signal {:?}", signal);
        process::exit(1);
    }
}
