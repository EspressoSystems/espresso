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

#![deny(warnings)]

use crate::*;
use clap::Parser;
use espresso_core::StakingKey;
use espresso_esqs::full_node::{self, EsQS};
use std::process::exit;

/// Command line arguments for a validator.
#[derive(Parser)]
pub struct ValidatorOpt {
    #[command(flatten)]
    pub node_opt: NodeOpt,

    #[command(flatten)]
    pub consensus_opt: ConsensusOpt,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_ID", requires("num-nodes"))]
    pub id: usize,

    /// Location of the current node.
    ///
    /// If not provided, the IP address will be used for dashboard display.
    #[clap(long, env = "ESPRESSO_VALIDATOR_LOCATION")]
    pub location: Option<String>,

    /// Whether to color log output with ANSI color codes.
    #[arg(long, env = "ESPRESSO_COLORED_LOGS")]
    pub colored_logs: bool,

    #[command(subcommand)]
    pub esqs: Option<full_node::Command>,
}

/// Initiate the hotshot
pub async fn init<R: CryptoRng + RngCore + Send + 'static>(
    rng: R,
    genesis: GenesisNote,
    options: ValidatorOpt,
) -> Result<Consensus, std::io::Error> {
    if let Err(msg) = options.node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }
    if options.node_opt.num_nodes < MINIMUM_NODES {
        eprintln!("Not enough nodes (need at least {})", MINIMUM_NODES);
        exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(options.colored_logs)
        .init();

    let own_id = options.id;

    // Initialize the hotshot
    let keys = gen_keys(&options.consensus_opt, options.node_opt.num_nodes);
    let priv_key = keys[own_id].clone();
    let known_nodes = keys
        .into_iter()
        .map(|sk| StakingKey::from_private(&sk))
        .collect();
    let hotshot = init_validator(
        rng,
        &options.node_opt,
        &options.consensus_opt,
        priv_key,
        known_nodes,
        genesis,
        own_id,
    )
    .await;
    let data_source =
        open_data_source(&options.node_opt, own_id, options.location, hotshot.clone());

    // Start an EsQS server if requested.
    if let Some(esqs) = &options.esqs {
        Some(EsQS::new(esqs, data_source, hotshot.clone())?)
    } else {
        None
    };

    Ok(hotshot)
}
