#![deny(warnings)]
use lazy_static::lazy_static;

lazy_static! {
    pub static ref UNIVERSAL_PARAM: jf_cap::proof::UniversalParam =
        (&*seahorse::testing::UNIVERSAL_PARAM).clone();
}
