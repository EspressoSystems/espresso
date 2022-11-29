// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

#![deny(warnings)]

use clap::Parser;
use espresso_validator::{validator::*, *};
use futures::future::pending;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let node_opt = NodeOpt::parse();
    let genesis = genesis(&node_opt);
    let hotshot = init(ChaChaRng::from_entropy(), genesis, node_opt).await?;
    run_consensus(hotshot, pending::<()>()).await;
    Ok(())
}
