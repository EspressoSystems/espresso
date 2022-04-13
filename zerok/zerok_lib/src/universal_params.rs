#![deny(warnings)]
use lazy_static::lazy_static;
use reef::Ledger;

lazy_static! {
    pub static ref UNIVERSAL_PARAM: jf_cap::proof::UniversalParam =
        reef::cap::Ledger::srs().clone();
}
