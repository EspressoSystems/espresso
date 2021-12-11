#![deny(warnings)]
use crate::state::MERKLE_HEIGHT;
use crate::util::canonical;
use jf_txn::{structs::NoteType, utils::compute_universal_param_size};
use lazy_static::lazy_static;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;

/// Generates universal parameter and store it to file.
pub fn set_universal_param(prng: &mut ChaChaRng) {
    let universal_param = jf_txn::proof::universal_setup(
        *[
            compute_universal_param_size(NoteType::Transfer, 3, 3, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Transfer: {}",
                        err
                    )
                },
            ),
            compute_universal_param_size(NoteType::Mint, 0, 0, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Mint: {}",
                        err
                    )
                },
            ),
            compute_universal_param_size(NoteType::Freeze, 2, 2, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Freeze: {}",
                        err
                    )
                },
            ),
        ]
        .iter()
        .max()
        .unwrap(),
        prng,
    )
    .unwrap_or_else(|err| panic!("Error while setting up the universal parameter: {}", err));
    let param_bytes = canonical::serialize_unchecked(&universal_param)
        .unwrap_or_else(|err| panic!("Error while serializing the universal parameter: {}", err));
    let path = UNIVERSAL_PARAM_PATH
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error while converting universal parameter path to a string");
    println!("path {}", path);
    let mut file = File::create(path)
        .unwrap_or_else(|err| panic!("Error while creating a universal parameter file: {}", err));
    file.write_all(&param_bytes).unwrap_or_else(|err| {
        panic!(
            "Error while writing to the universal parameter file: {}",
            err
        )
    });
}

/// Reads universal parameter from file if it exists. If not, generates the universal parameter, stores
/// it to file, and returns it.
pub fn get_universal_param(prng: &mut ChaChaRng) -> jf_txn::proof::UniversalParam {
    // create a new seeded PRNG from the master PRNG when getting the UniversalParam. This ensures a
    // deterministic RNG result after the call, either the UniversalParam is newly generated or loaded
    // from a file.
    let mut new_prng = ChaChaRng::from_rng(prng)
        .unwrap_or_else(|err| panic!("Error while creating a new PRNG: {}", err));
    let mut file = match File::open(&*UNIVERSAL_PARAM_PATH) {
        Ok(f) => f,
        Err(_) => {
            set_universal_param(&mut new_prng);
            File::open(&*UNIVERSAL_PARAM_PATH).unwrap_or_else(|_| {
                panic!(
                    "Cannot find the universal parameter file after generation: {}",
                    UNIVERSAL_PARAM_PATH.display()
                )
            })
        }
    };
    let mut param_bytes = Vec::new();
    file.read_to_end(&mut param_bytes)
        .unwrap_or_else(|err| panic!("Error while reading the universal parameter file: {}", err));
    canonical::deserialize_unchecked(&param_bytes[..])
        .unwrap_or_else(|err| panic!("Error while deserializing the universal parameter: {}", err))
}

lazy_static! {
    // By default, set the path to the universal parameter file as `src/universal_param` under `CARGO_MANIFEST_DIR`.
    // Override it with the environment variable, `UNIVERSAL_PARAM_PATH`.
    static ref UNIVERSAL_PARAM_PATH: PathBuf = match std::env::var("UNIVERSAL_PARAM_PATH") {
        Ok(path) => PathBuf::from(path),
        _ => [
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            Path::new("src/universal_param")
        ]
        .iter()
        .collect(),
    };
    pub static ref UNIVERSAL_PARAM: jf_txn::proof::UniversalParam =
        get_universal_param(&mut ChaChaRng::from_seed([0x8au8; 32]));
}
