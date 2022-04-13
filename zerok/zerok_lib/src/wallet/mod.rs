pub mod network;
#[cfg(any(test, feature = "mocks"))]
pub mod testing;

use crate::ledger::EspressoLedger;

pub use seahorse::*;

pub type EspressoWallet<'a, Backend> = Wallet<'a, Backend, EspressoLedger>;
pub type EspressoWalletError = WalletError<EspressoLedger>;
