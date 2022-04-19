// Copyright © 2021 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]

use espresso_validator::{get_node_config, run_validator, NodeOpt};
use structopt::StructOpt;

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Get configuration
    let options = NodeOpt::from_args();
    let node_config = get_node_config(&options);

    // Override the path to the universal parameter file if it's specified
    if let Some(dir) = options.universal_param_path.as_ref() {
        std::env::set_var("UNIVERSAL_PARAM_PATH", dir);
    }

    run_validator(&options, &node_config).await
}
