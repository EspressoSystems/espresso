// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

pub mod cli_client;
pub mod network;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use cli_client::CliClient;
pub use seahorse::*;

use espresso_core::ledger::EspressoLedger;

pub type EspressoKeystore<'a, Backend, Meta> = Keystore<'a, Backend, EspressoLedger, Meta>;
pub type EspressoKeystoreError = KeystoreError<EspressoLedger>;
