pub mod network;
#[cfg(any(test, feature = "mocks"))]
pub mod testing;

use crate::ledger::EspressoLedger;

pub use seahorse::*;

pub type EspressoKeystore<'a, Backend> = Keystore<'a, Backend, EspressoLedger>;
pub type EspressoKeystoreError = KeystoreError<EspressoLedger>;
