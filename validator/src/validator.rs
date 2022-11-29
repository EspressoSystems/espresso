// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

#![deny(warnings)]

use crate::*;
use espresso_core::StakingKey;
use espresso_esqs::full_node::EsQS;
use std::process::exit;

/// Initiate the hotshot
pub async fn init<R: CryptoRng + RngCore + Send + 'static>(
    rng: R,
    genesis: GenesisNote,
    node_opt: NodeOpt,
) -> Result<Consensus, std::io::Error> {
    if let Err(msg) = node_opt.check() {
        eprintln!("{}", msg);
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
    let hotshot = init_validator(rng, &node_opt, priv_key, known_nodes, genesis).await;
    let data_source = open_data_source(&node_opt, hotshot.clone());

    // Start an EsQS server if requested.
    if let Some(esqs) = &node_opt.esqs {
        Some(EsQS::new(esqs, data_source, hotshot.clone())?)
    } else {
        None
    };

    Ok(hotshot)
}
