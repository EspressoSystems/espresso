#![deny(warnings)]
use crate::state::MERKLE_HEIGHT;
use jf_cap::structs::NoteType;
use jf_cap::utils::compute_universal_param_size;
use lazy_static::lazy_static;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;

lazy_static! {
    pub static ref UNIVERSAL_PARAM: UniversalParam = {
        let max_degree = compute_universal_param_size(NoteType::Transfer, 3, 3, MERKLE_HEIGHT)
            .unwrap_or_else(|err| {
                panic!(
                    "Error while computing the universal parameter size for Transfer: {}",
                    err
                )
            });
        jf_cap::proof::universal_setup(max_degree, &mut ChaChaRng::from_seed([0u8; 32]))
            .unwrap_or_else(|err| panic!("Error while generating universal param: {}", err))
    };
}
