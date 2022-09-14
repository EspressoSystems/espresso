// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

////////////////////////////////////////////////////////////////////////////////
// The Espresso Keystore Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a keystore interactively.
//

mod cli_client;

use async_trait::async_trait;
use espresso_client::network::{NetworkBackend, Url};
use espresso_core::ledger::EspressoLedger;
use jf_cap::proof::UniversalParam;
use seahorse::{
    cli::*,
    io::SharedIO,
    loader::{InteractiveLoader, MnemonicPasswordLogin},
    reader::Reader,
    KeystoreError,
};
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Args {
    /// Generate keys for a keystore, do not run the REPL.
    ///
    /// The keys are stored in FILE and FILE.pub.
    #[structopt(short = "g", long)]
    pub key_gen: Option<PathBuf>,

    /// Path to a saved keystore, or a new directory where this keystore will be saved.
    ///
    /// If not given, the keystore will be stored in ~/.translucence/keystore. If a keystore already
    /// exists there, it will be loaded. Otherwise, a new keystore will be created.
    #[structopt(short, long)]
    pub storage: Option<PathBuf>,

    /// Create a new keystore and store it an a temporary location which will be deleted on exit.
    ///
    /// This option is mutually exclusive with --storage.
    #[structopt(long)]
    #[structopt(conflicts_with("storage"))]
    #[structopt(hidden(true))]
    pub tmp_storage: bool,

    #[structopt(long)]
    /// Run in a mode which is friendlier to automated scripting.
    ///
    /// Instead of prompting the user for input with a line editor, the prompt will be printed,
    /// followed by a newline, and the input will be read without an editor.
    pub non_interactive: bool,

    /// URL for the Espresso Query Service.
    #[structopt(
        long,
        env = "ESPRESSO_ESQS_URL",
        default_value = "http://localhost:50087"
    )]
    pub esqs_url: Url,

    /// URL for the Espresso address book.
    #[structopt(
        long,
        env = "ESPRESSO_ADDRESS_BOOK_URL",
        default_value = "http://localhost:50088"
    )]
    pub address_book_url: Url,

    /// URL for a validator to submit transactions to.
    #[structopt(
        long,
        env = "ESPRESSO_SUBMIT_URL",
        default_value = "http://localhost:50089"
    )]
    pub submit_url: Url,
}

impl CLIArgs for Args {
    fn key_gen_path(&self) -> Option<PathBuf> {
        self.key_gen.clone()
    }

    fn storage_path(&self) -> Option<PathBuf> {
        self.storage.clone()
    }

    fn io(&self) -> Option<SharedIO> {
        if self.non_interactive {
            Some(SharedIO::std())
        } else {
            None
        }
    }

    fn use_tmp_storage(&self) -> bool {
        self.tmp_storage
    }
}

struct EspressoCli;

#[async_trait]
impl<'a> CLI<'a> for EspressoCli {
    type Ledger = EspressoLedger;
    type Backend = NetworkBackend<'a>;
    type Args = Args;
    type Loader = InteractiveLoader;
    type Meta = MnemonicPasswordLogin;

    async fn init_backend(
        univ_param: &'a UniversalParam,
        args: Self::Args,
    ) -> Result<Self::Backend, KeystoreError<EspressoLedger>> {
        NetworkBackend::new(
            univ_param,
            args.esqs_url,
            args.address_book_url,
            args.submit_url,
        )
        .await
    }

    async fn init_loader(
        storage: PathBuf,
        input: Reader,
    ) -> Result<Self::Loader, KeystoreError<Self::Ledger>> {
        Ok(InteractiveLoader::new(storage, input))
    }
}

#[async_std::main]
async fn main() {
    if let Err(err) = cli_main::<EspressoLedger, EspressoCli>(Args::from_args()).await {
        println!("{}", err);
        exit(1);
    }
}
