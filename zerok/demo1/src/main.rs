// Copyright © 2021 Translucence Research, Inc. All rights reserved.

// Demo 1 - Anonymous transaction processing
//
// This code builds and validates transactions with two inputs and two outputs.

#![feature(proc_macro_hygiene, decl_macro)]


use jf_txn::parameters::CacheableProverSrs;
use jf_txn::structs::RecordCommitment;
use jf_txn::proof::transfer::{TransferProvingKey, TransferVerifyingKey};
use jf_primitives::merkle_tree::MerkleTree;
use jf_txn::keys::UserKeyPair;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use std::path::Path;
use structopt::StructOpt;
use tracing::info;
use zerok_lib::state_comm;
use zerok_lib::*;

#[macro_use]
extern crate rocket;

mod ip;

mod config;
use crate::config::Args;

mod disco;
use crate::disco::messages_path;

pub const CRS_FILE_NAME: &str = "setup_params_2x2";

// todo !corbett configuration file items
//    location of common reference string file
//    number of users
//    number of asset definitions
//

fn intro() {
    info!(
        "Demo 1 - Anonymous transaction processing\n\
         This code builds and validates transactions with two inputs and two outputs."
    );
    info!("Message path is {:?}.", messages_path());
}

// TODO: update this to perform single-initialization of a shared instance, rather than reloading it each time
// fn fetch_common_reference_string() -> TransferProvingKey<'static> {
//     info!("Obtaining the common reference string.");
//     if !Path::exists(Path::new(CRS_FILE_NAME)) {
//         info!("Generating common reference string. Expect a 10-30m delay.");
//     } else {
//         info!("Loading cached common reference string.");
//     }
//     let (n_inputs, m_outputs, tree_depth, src_path) = (
//         2,
//         2,
//         Some((MERKLE_HEIGHT) as usize),
//         Some(CRS_FILE_NAME.to_string()),
//     );

//     TransferProvingKey::from_file(n_inputs, m_outputs, tree_depth, src_path)
//         .expect("Unable to read or generate the common reference string.")
// }

#[rocket::main]
async fn main() {
    tracing_subscriber::fmt::init();

    intro();

    let args = Args::from_args();
    info!("Arguments: {:?}", args);

    // let user_params = fetch_common_reference_string();

    // Fixed seed for deterministic results to make documentation simpler.
    let mut prng = ChaChaRng::from_seed([0x8au8; 32]);

    // Make two sets of keys
    let keys: Vec<_> = (0..2).map(|_| UserKeyPair::generate(&mut prng)).collect();
    info!("Generated {} user key pairs", keys.len());

    // def0 and key0 are indices; amt0 is an arbitrary amount of asset units.
    let (def0, key0, amt0) = (0u8, 0u8, 1000u64);
    let (def1, key1, amt1) = (1u8, 1u8, 2000u64);

    let time_delta = 0;
    let (input00, input01, key00, key01, amt_diff0) = (0, 1, 0, 1, -200);
    let (input10, input11, key10, key11, amt_diff1) = (1, 0, 1, 0, 5000);
    let txs = vec![
        (time_delta, input00, input01, key00, key01, amt_diff0),
        (time_delta, input10, input11, key10, key11, amt_diff1),
    ];

}
