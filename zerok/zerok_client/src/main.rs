////////////////////////////////////////////////////////////////////////////////
// The AAP Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

use api::UserAddress;
use async_std::sync::{Arc, Mutex};
use async_std::task::block_on;
use async_trait::async_trait;
use fmt::{Display, Formatter};
use futures::future::BoxFuture;
use jf_txn::structs::AssetCode;
use lazy_static::lazy_static;
use shutdown_hooks::add_shutdown_hook;
use std::any::type_name;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::iter::once;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use structopt::StructOpt;
use tempdir::TempDir;
use wallet::network::*;
use zerok_lib::{api, wallet, UNIVERSAL_PARAM};

type Wallet = wallet::Wallet<'static, NetworkBackend<'static>>;

#[derive(StructOpt)]
struct Args {
    #[structopt(short = "g", long)]
    /// Generate keys for a wallet, do not run the REPL.
    ///
    /// The keys are stored in FILE and FILE.pub.
    key_gen: Option<PathBuf>,

    #[structopt(short, long)]
    /// Path to a private key file to use for the wallet.
    ///
    /// If not given, new keys are generated randomly.
    key_path: Option<PathBuf>,

    #[structopt(short, long)]
    /// Path to a saved wallet, or a new directory where this wallet will be saved.
    ///
    /// If not given, a temporary directory is created and will be deleted when the program is
    /// closed.
    storage: Option<PathBuf>,

    /// URL of a server for interacting with the ledger
    server: Option<Url>,
}

// A REPL command.
struct Command {
    // The name of the command, for display and lookup.
    name: String,
    // The parameters of the command and their types, as strings, for display purposes in the 'help'
    // command.
    params: Vec<(String, String)>,
    // A brief description of what the command does.
    help: String,
    // Run the command with a list of arguments.
    run: CommandFunc,
}

type CommandFunc = Box<dyn Sync + for<'a> Fn(Vec<String>) -> BoxFuture<'static, ()>>;

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        for (param, ty) in &self.params {
            write!(f, " [{}: {}]", param, ty)?;
        }
        write!(f, "\n    {}", self.help)?;
        Ok(())
    }
}

macro_rules! command {
    ($name:ident, $help:expr, |$wallet:pat, $($arg:ident : $argty:ty),*| $run:expr) => {
        Command {
            name: String::from(stringify!($name)),
            params: vec![$((
                String::from(stringify!($arg)),
                String::from(type_name::<$argty>()),
            )),*],
            help: String::from($help),
            run: Box::new(|args| Box::pin(async {
                if args.len() != count!($($arg)*) {
                    println!("incorrect number of arguments (expected {})", count!($($arg)*));
                    return;
                }

                // For each (arg, ty) pair in the signature of the handler function, create a local
                // variable `arg: ty` by converting from the corresponding string in the `args`
                // vector. `args` will be unused if $($arg)* is empty, hence the following allows.
                #[allow(unused_mut)]
                #[allow(unused_variables)]
                let mut args = args.into_iter();
                $(
                    let $arg = match <$argty>::from_str(args.next().unwrap().as_str()) {
                        Ok(arg) => arg,
                        Err(_) => {
                            println!(
                                "invalid value for argument {} (expected {})",
                                stringify!($arg),
                                type_name::<$argty>());
                            return;
                        }
                    };
                )*

                let $wallet = &mut *WALLET.lock().await;
                $run
            }))
        }
    };

    // Don't require a comma after $wallet if there are no additional args.
    ($name:ident, $help:expr, |$wallet:pat| $run:expr) => {
        command!($name, $help, |$wallet,| $run)
    };

    // Don't require wallet at all.
    ($name:ident, $help:expr, || $run:expr) => {
        command!($name, $help, |_| $run)
    };
}

macro_rules! count {
    () => (0);
    ($x:tt $($xs:tt)*) => (1 + count!($($xs)*));
}

// Types which can be listed in terminal output and parsed from a list index.
#[async_trait]
trait Listable: Sized {
    async fn list(wallet: &mut Wallet) -> Vec<ListItem<Self>>;

    fn list_sync(wallet: &mut Wallet) -> Vec<ListItem<Self>> {
        block_on(Self::list(wallet))
    }
}

struct ListItem<T> {
    index: usize,
    item: T,
    annotation: Option<String>,
}

impl<T: Display> Display for ListItem<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}. {}", self.index, self.item)?;
        if let Some(annotation) = &self.annotation {
            write!(f, " ({})", annotation)?;
        }
        Ok(())
    }
}

impl<T: Listable + FromStr> FromStr for ListItem<T> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(index) = usize::from_str(s) {
            // If the input looks like a list index, build the list for type T and get an element of
            // type T by indexing.
            let mut items = T::list_sync(&mut *block_on(WALLET.lock()));
            if index < items.len() {
                Ok(items.remove(index))
            } else {
                Err(())
            }
        } else {
            // Otherwise, just parse a T directly.
            match T::from_str(s) {
                Ok(item) => Ok(ListItem {
                    item,
                    index: 0,
                    annotation: None,
                }),
                Err(_) => Err(()),
            }
        }
    }
}

#[async_trait]
impl Listable for AssetCode {
    async fn list(wallet: &mut Wallet) -> Vec<ListItem<Self>> {
        // Get all assets known to the wallet, except the native asset, which we will add to the
        // results manually to make sure that it is always present and always first.
        let mut assets = wallet
            .assets()
            .await
            .into_iter()
            .filter(|asset| *asset != AssetCode::native())
            .collect::<Vec<_>>();
        // Sort alphabetically for consistent ordering as long as the set of known assets remains
        // stable.
        assets.sort_by_key(|asset| asset.to_string());

        // Convert to ListItems and prepend the native asset code.
        once(AssetCode::native())
            .chain(assets)
            .into_iter()
            .enumerate()
            .map(|(index, asset)| ListItem {
                index,
                annotation: if asset == AssetCode::native() {
                    Some(String::from("native"))
                } else {
                    None
                },
                item: asset,
            })
            .collect()
    }
}

lazy_static! {
    static ref COMMANDS: Vec<Command> = vec![
        command!(address, "print the address of this wallet", |wallet| {
            println!("{}", api::UserAddress(wallet.address()));
        }),
        command!(pub_key, "print the public key of this wallet", |wallet| {
            println!("{:?}", wallet.pub_key());
        }),
        command!(assets, "list assets known to the wallet", |wallet| {
            for item in AssetCode::list(wallet).await {
                println!("{}", item)
            }
        }),
        command!(
            balance,
            "print owned balance of asset",
            |wallet, asset: ListItem<AssetCode>| {
                println!("{}", wallet.balance(&asset.item).await);
            }
        ),
        command!(
            transfer,
            "transfer some owned assets to another user",
            |wallet, asset: ListItem<AssetCode>, address: UserAddress, amount: u64, fee: u64| {
                if let Err(err) = wallet
                    .transfer(&asset.item, &[(address.0, amount)], fee)
                    .await
                {
                    println!("{}\nAssets were not transferred.", err);
                }
            }
        ),
        command!(help, "display list of available commands", || {
            for command in COMMANDS.iter() {
                println!("{}", command);
            }
        }),
    ];
}

lazy_static! {
    static ref STORAGE: (PathBuf, Arc<Mutex<Option<TempDir>>>) = {
        match Args::from_args().storage {
            Some(storage) => (storage, Arc::new(Mutex::new(None))),
            None => {
                let tmp_dir = TempDir::new("wallet").unwrap_or_else(|err| {
                    println!("error creating temporary directory: {}", err);
                    exit(1);
                });
                add_shutdown_hook(close_storage);
                (
                    PathBuf::from(tmp_dir.path()),
                    Arc::new(Mutex::new(Some(tmp_dir))),
                )
            }
        }
    };
    static ref STORAGE_PATH: &'static Path = &STORAGE.0;
    static ref WALLET: Arc<Mutex<Wallet>> = Arc::new(Mutex::new(block_on(init_repl())));
}

extern "C" fn close_storage() {
    block_on(STORAGE.1.lock()).take();
}

async fn init_repl() -> Wallet {
    let args = Args::from_args();
    let server = args.server.unwrap_or_else(|| {
        println!("server is required");
        exit(1);
    });

    println!(
        "Welcome to the AAP wallet, version {}",
        env!("CARGO_PKG_VERSION")
    );
    println!("(c) 2021 Translucence Research, Inc.");
    println!("connecting...");

    let key_pair = if let Some(path) = args.key_path {
        let mut file = File::open(path).unwrap_or_else(|err| {
            println!("cannot open private key file: {}", err);
            exit(1);
        });
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap_or_else(|err| {
            println!("error reading private key file: {}", err);
            exit(1);
        });
        bincode::deserialize(&bytes).unwrap_or_else(|err| {
            println!("invalid private key file: {}", err);
            exit(1);
        })
    } else {
        wallet::new_key_pair()
    };

    let backend = NetworkBackend::new(
        &*UNIVERSAL_PARAM,
        server.clone(),
        server.clone(),
        server.clone(),
        *STORAGE_PATH,
    )
    .unwrap_or_else(|err| {
        println!("Failed to connect to backend: {}", err);
        exit(1);
    });
    let wallet = Wallet::new(key_pair, backend).await.unwrap_or_else(|err| {
        println!("Error loading wallet: {}", err);
        exit(1);
    });

    println!("Type 'help' for a list of commands.");
    wallet
}

#[async_std::main]
async fn main() {
    let args = Args::from_args();

    if let Some(mut path) = args.key_gen {
        let key_pair = wallet::new_key_pair();

        let mut file = File::create(path.clone()).unwrap_or_else(|err| {
            println!("error creating private key file: {}", err);
            exit(1);
        });
        let bytes = bincode::serialize(&key_pair).unwrap_or_else(|err| {
            println!("error generating private key: {}", err);
            exit(1)
        });
        file.write_all(&bytes).unwrap_or_else(|err| {
            println!("error writing private key file: {}", err);
            exit(1);
        });

        path.set_extension("pub");
        let mut file = File::create(path).unwrap_or_else(|err| {
            println!("error creating public key file: {}", err);
            exit(1);
        });
        let bytes = bincode::serialize(&key_pair.pub_key()).unwrap_or_else(|err| {
            println!("error generating public key: {}", err);
            exit(1);
        });
        file.write_all(&bytes).unwrap_or_else(|err| {
            println!("error writing public key file: {}", err);
            exit(1);
        });

        return;
    }

    // Force static initialization to happen eagerly, so we don't get a long delay some time later
    // after the user has started using the wallet.
    let _ = &*WALLET;

    let mut input = rustyline::Editor::<()>::new();
    'repl: while let Ok(line) = input.readline("> ") {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }
        for Command { name, run, .. } in COMMANDS.iter() {
            if name == tokens[0] {
                run(tokens.into_iter().skip(1).map(String::from).collect()).await;
                continue 'repl;
            }
        }
        println!("Unknown command. Type 'help' for a list of valid commands.");
    }
}
