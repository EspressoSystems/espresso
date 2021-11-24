////////////////////////////////////////////////////////////////////////////////
// The AAP Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

mod cli_client;

use jf_txn::proof::UniversalParam;
use std::process::exit;
use structopt::StructOpt;
use zerok_lib::{
    ledger::AAPLedger,
    wallet::{cli::*, network::NetworkBackend, persistence::WalletLoader, WalletError},
};

struct AapCli;

impl<'a> CLI<'a> for AapCli {
    type Ledger = AAPLedger;
    type Backend = NetworkBackend<'a, WalletMetadata>;

    fn init_backend(
        univ_param: &'a UniversalParam,
        args: &'a Args,
        loader: &mut impl WalletLoader<Meta = WalletMetadata>,
    ) -> Result<Self::Backend, WalletError> {
        let server = args.server.clone().ok_or(WalletError::Failed {
            msg: String::from("server is required"),
        })?;
        NetworkBackend::new(
            univ_param,
            server.clone(),
            server.clone(),
            server,
            loader,
        )
    }
}

#[async_std::main]
async fn main() {
    if let Err(err) = cli_main::<AapCli>(&Args::from_args()).await {
        println!("{}", err);
        exit(1);
    }
}
