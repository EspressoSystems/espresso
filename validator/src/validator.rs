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
use espresso_core::state::ElaboratedBlock;
use espresso_esqs::full_node::{self, EsQS};
use std::process::exit;

/// Command line arguments for a validator.
#[derive(Parser)]
pub struct ValidatorOpt {
    #[command(flatten)]
    node_opt: NodeOpt,

    #[command(flatten)]
    consensus_opt: ConsensusOpt,

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

    /// Number of nodes, including a fixed number of bootstrap nodes and a dynamic number of non-
    /// bootstrap nodes.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_NUM_NODES")]
    pub num_nodes: usize,

    /// Whether to color log output with ANSI color codes.
    #[arg(long, env = "ESPRESSO_COLORED_LOGS")]
    pub colored_logs: bool,

    /// Unique identifier for this instance of Espresso.
    #[arg(long, env = "ESPRESSO_VALIDATOR_CHAIN_ID", default_value = "0")]
    pub chain_id: u16,

    #[command(subcommand)]
    pub esqs: Option<full_node::Command>,
}

/// Initiate the hotshot
pub async fn init(
    genesis: GenesisNote,
    options: ValidatorOpt,
) -> Result<Consensus, std::io::Error> {
    if let Err(msg) = options.node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(options.colored_logs)
        .init();

    let own_id = options.id;

    // Initialize the hotshot
    let keys = gen_keys(&options.consensus_opt, options.num_nodes);
    let priv_key = keys[own_id].private.clone();
    let known_nodes = keys.into_iter().map(|pair| pair.public).collect();
    let hotshot = init_validator(
        &options.node_opt,
        &options.consensus_opt,
        priv_key,
        known_nodes,
        genesis.clone(),
        own_id,
    )
    .await;
    let data_source =
        open_data_source(&options.node_opt, own_id, options.location, hotshot.clone());

    // Start an EsQS server if requested.
    if let Some(esqs) = &options.esqs {
        Some(EsQS::new(
            esqs,
            data_source,
            hotshot.clone(),
            ElaboratedBlock::genesis(genesis),
        )?)
    } else {
        None
    };

    Ok(hotshot)
}
