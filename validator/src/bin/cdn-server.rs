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

use clap::Parser;
use espresso_core::state::PubKey;
use hotshot_centralized_server::Server;

#[derive(Parser)]
struct Args {
    #[clap(short, long, env = "ESPRESSO_CDN_SERVER_PORT")]
    port: u16,

    #[clap(long, env = "ESPRESSO_COLORED_LOGS")]
    colored_logs: bool,
}

#[async_std::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(args.colored_logs)
        .init();
    tracing::info!("starting CDN server on port {}", args.port);
    Server::<PubKey>::new("0.0.0.0".parse().unwrap(), args.port)
        .await
        .run()
        .await;
    tracing::info!("CDN server exiting");
}
