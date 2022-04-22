////////////////////////////////////////////////////////////////////////////////
// The Espresso Keystore Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a keystore interactively.
//

mod cli_client;

use jf_cap::proof::UniversalParam;
use seahorse::{
    cli::*,
    io::SharedIO,
    loader::{LoaderMetadata, KeystoreLoader},
    KeystoreError,
};
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;
use zerok_lib::{
    ledger::EspressoLedger,
    keystore::network::{NetworkBackend, Url},
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

    /// URL of a server for interacting with the ledger
    pub server: Option<Url>,
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
        let server = args.server.ok_or(KeystoreError::Failed {
            msg: String::from("server is required"),
        })?;
        NetworkBackend::new(univ_param, server.clone(), server.clone(), server, loader)
    }
}

#[async_std::main]
async fn main() {
    if let Err(err) = cli_main::<EspressoLedger, EspressoCli>(Args::from_args()).await {
        println!("{}", err);
        exit(1);
    }
}
