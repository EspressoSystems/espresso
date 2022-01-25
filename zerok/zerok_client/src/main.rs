////////////////////////////////////////////////////////////////////////////////
// The Spectrum Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

mod cli_client;

use jf_aap::proof::UniversalParam;
use seahorse::{
    cli::*,
    loader::{LoadMethod, LoaderMetadata, WalletLoader},
    WalletError,
};
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;
use zerok_lib::wallet::{
    network::{NetworkBackend, Url},
    spectrum::SpectrumLedger,
};

#[derive(StructOpt)]
pub struct Args {
    /// Generate keys for a wallet, do not run the REPL.
    ///
    /// The keys are stored in FILE and FILE.pub.
    #[structopt(short = "g", long)]
    pub key_gen: Option<PathBuf>,

    /// Path to a saved wallet, or a new directory where this wallet will be saved.
    ///
    /// If not given, the wallet will be stored in ~/.translucence/wallet. If a wallet already
    /// exists there, it will be loaded. Otherwise, a new wallet will be created.
    #[structopt(short, long)]
    pub storage: Option<PathBuf>,

    /// Store the contents of the wallet in plaintext.
    ///
    /// You will not require a password to access your wallet, and your wallet will not be protected
    /// from malicious software that gains access to a device where you loaded your wallet.
    ///
    /// This option is only available when creating a new wallet. When loading an existing wallet, a
    /// password will always be required if the wallet was created without the --unencrypted flag.
    #[structopt(long)]
    pub unencrypted: bool,

    /// Load the wallet using a password and salt, rather than a mnemonic phrase.
    #[structopt(long)]
    pub password: bool,

    /// Create a new wallet and store it an a temporary location which will be deleted on exit.
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

    fn interactive(&self) -> bool {
        !self.non_interactive
    }

    fn encrypted(&self) -> bool {
        !self.unencrypted
    }

    fn load_method(&self) -> LoadMethod {
        if self.password {
            LoadMethod::Password
        } else {
            LoadMethod::Mnemonic
        }
    }

    fn use_tmp_storage(&self) -> bool {
        self.tmp_storage
    }
}

struct SpectrumCli;

impl<'a> CLI<'a> for SpectrumCli {
    type Ledger = SpectrumLedger;
    type Backend = NetworkBackend<'a, LoaderMetadata>;
    type Args = Args;

    fn init_backend(
        univ_param: &'a UniversalParam,
        args: &'a Self::Args,
        loader: &mut impl WalletLoader<SpectrumLedger, Meta = LoaderMetadata>,
    ) -> Result<Self::Backend, WalletError<SpectrumLedger>> {
        let server = args.server.clone().ok_or(WalletError::Failed {
            msg: String::from("server is required"),
        })?;
        NetworkBackend::new(univ_param, server.clone(), server.clone(), server, loader)
    }
}

#[async_std::main]
async fn main() {
    if let Err(err) = cli_main::<SpectrumLedger, SpectrumCli>(&Args::from_args()).await {
        println!("{}", err);
        exit(1);
    }
}
