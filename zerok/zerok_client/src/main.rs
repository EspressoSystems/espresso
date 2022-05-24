////////////////////////////////////////////////////////////////////////////////
// The Espresso Keystore Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a keystore interactively.
//

mod cli_client;

use async_std::task::block_on;
use jf_cap::proof::UniversalParam;
use seahorse::{
    cli::*,
    io::SharedIO,
    loader::{KeystoreLoader, LoaderMetadata},
    KeystoreError,
};
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;
use zerok_lib::{
    keystore::network::{NetworkBackend, Url},
    ledger::EspressoLedger,
};

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
        default_value = "http://localhost:50078"
    )]
    pub address_book_url: Url,

    /// URL for a validator to submit transactions to.
    #[structopt(
        long,
        env = "ESPRESSO_SUBMIT_URL",
        default_value = "http://localhost:50087"
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

impl<'a> CLI<'a> for EspressoCli {
    type Ledger = EspressoLedger;
    type Backend = NetworkBackend<'a, LoaderMetadata>;
    type Args = Args;

    fn init_backend(
        univ_param: &'a UniversalParam,
        args: Self::Args,
        loader: &mut impl KeystoreLoader<EspressoLedger, Meta = LoaderMetadata>,
    ) -> Result<Self::Backend, KeystoreError<EspressoLedger>> {
        block_on(NetworkBackend::new(
            univ_param,
            args.esqs_url,
            args.address_book_url,
            args.submit_url,
            loader,
        ))
    }
}

#[async_std::main]
async fn main() {
    if let Err(err) = cli_main::<EspressoLedger, EspressoCli>(Args::from_args()).await {
        println!("{}", err);
        exit(1);
    }
}
