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
use espresso_core::StakingKey;
use espresso_esqs::full_node::EsQS;
use std::process::exit;

/// Initiate the hotshot
pub async fn init(genesis: GenesisNote, node_opt: NodeOpt) -> Result<Consensus, std::io::Error> {
    if let Err(msg) = node_opt.check() {
        eprintln!("{}", msg);
        exit(1);
    }
    if node_opt.num_nodes < MINIMUM_NODES {
        eprintln!("Not enough nodes (need at least {})", MINIMUM_NODES);
        exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(node_opt.colored_logs)
        .init();

    // Initialize the hotshot
    let keys = gen_keys(node_opt.secret_key_seed, node_opt.num_nodes);
    let priv_key = keys[node_opt.id].clone();
    let known_nodes = keys
        .into_iter()
        .map(|sk| StakingKey::from_private(&sk))
        .collect();
    let hotshot = init_validator(&node_opt, priv_key, known_nodes, genesis).await;
    let data_source = open_data_source(&node_opt, hotshot.clone());

    // Start an EsQS server if requested.
    if let Some(esqs) = &node_opt.esqs {
        Some(EsQS::new(esqs, data_source, hotshot.clone())?)
    } else {
        None
    };

    Ok(hotshot)
}
