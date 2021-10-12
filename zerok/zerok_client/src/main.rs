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
use jf_txn::keys::{AuditorPubKey, FreezerPubKey};
use jf_txn::structs::{AssetCode, AssetDefinition, AssetPolicy};
use lazy_static::lazy_static;
use std::any::type_name;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::iter::once;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use wallet::{network::*, AssetInfo, MintInfo};
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
    // The keyword parameters of the command and their types, as strings, for display purposes in
    // the 'help' command.
    kwargs: Vec<(String, String)>,
    // A brief description of what the command does.
    help: String,
    // Run the command with a list of arguments.
    run: CommandFunc,
}

type CommandFunc =
    Box<dyn Sync + for<'a> Fn(Vec<String>, HashMap<String, String>) -> BoxFuture<'static, ()>>;

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        for (param, ty) in &self.params {
            write!(f, " {}: {}", param, ty)?;
        }
        for (param, ty) in &self.kwargs {
            write!(f, " [{}: {}]", param, ty)?;
        }
        write!(f, "\n    {}", self.help)?;
        Ok(())
    }
}

macro_rules! command {
    ($name:ident,
     $help:expr,
     |$wallet:pat, $($arg:ident : $argty:ty),*
      $(; $($kwarg:ident : Option<$kwargty:ty>),*)?| $run:expr) => {
        Command {
            name: String::from(stringify!($name)),
            params: vec![$((
                String::from(stringify!($arg)),
                String::from(type_name::<$argty>()),
            )),*],
            kwargs: vec![$($((
                String::from(stringify!($kwarg)),
                String::from(type_name::<$kwargty>()),
            )),*)?],
            help: String::from($help),
            run: Box::new(|args, kwargs| Box::pin(async move {
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

                // For each (kwarg, ty) pair in the signature of the handler function, create a
                // local variable `kwarg: Option<ty>` by converting the value associated with
                // `kwarg` in `kwargs` to tye type `ty`.
                $($(
                    let $kwarg = match kwargs.get(stringify!($kwarg)) {
                        Some(val) => match <$kwargty>::from_str(val) {
                            Ok(arg) => Some(arg),
                            Err(_) => {
                                println!(
                                    "invalid value for argument {} (expected {})",
                                    stringify!($kwarg),
                                    type_name::<$kwargty>());
                                return;
                            }
                        }
                        None => None,
                    };
                )*)?
                // `kwargs` will be unused if there are no keyword params.
                let _ = kwargs;

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
            .filter_map(|(code, asset)| {
                if code == AssetCode::native() {
                    None
                } else {
                    Some(asset)
                }
            })
            .collect::<Vec<_>>();
        // Sort alphabetically for consistent ordering as long as the set of known assets remains
        // stable.
        assets.sort_by_key(|info| info.asset.code.to_string());

        // Convert to ListItems and prepend the native asset code.
        once(AssetInfo::from(AssetDefinition::native()))
            .chain(assets)
            .into_iter()
            .enumerate()
            .map(|(index, info)| ListItem {
                index,
                annotation: if info.asset.code == AssetCode::native() {
                    Some(String::from("native"))
                } else {
                    // Annotate the listing with attributes indicating whether the asset is
                    // auditable, freezable, and mintable by us.
                    let mut attributes = String::new();
                    let policy = info.asset.policy_ref();
                    let auditor_pub_key = wallet.auditor_pub_key();
                    let freezer_pub_key = wallet.freezer_pub_key();
                    if *policy.auditor_pub_key() == auditor_pub_key {
                        attributes.push('a');
                    }
                    if *policy.freezer_pub_key() == freezer_pub_key {
                        attributes.push('f');
                    }
                    if info.mint_info.is_some() {
                        attributes.push('m');
                    }
                    if attributes.is_empty() {
                        None
                    } else {
                        Some(attributes)
                    }
                },
                item: info.asset.code,
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
                println!("{}", item);
            }
            println!("(a=auditable, f=freezeable, m=mintable)");
        }),
        command!(
            asset,
            "print information about an asset",
            |wallet, asset: ListItem<AssetCode>| {
                let assets = wallet.assets().await;
                let info = match assets.get(&asset.item) {
                    Some(info) => info,
                    None => {
                        println!("No such asset {}", asset.item);
                        return;
                    }
                };

                // Try to format the asset description as human-readable as possible.
                let desc = if let Some(MintInfo { desc, .. }) = &info.mint_info {
                    // If it looks like it came from a string, interpret as a string. Otherwise,
                    // encode the binary blob as tagged base64.
                    match std::str::from_utf8(desc) {
                        Ok(s) => String::from(s),
                        Err(_) => TaggedBase64::new("DESC", desc).unwrap().to_string(),
                    }
                } else if info.asset.code == AssetCode::native() {
                    String::from("Native")
                } else {
                    String::from("Asset")
                };
                println!("{} {}", desc, info.asset.code);

                // Print the auditor, noting if it is us.
                let policy = info.asset.policy_ref();
                if policy.is_auditor_pub_key_set() {
                    let auditor_key = policy.auditor_pub_key();
                    if *auditor_key == wallet.auditor_pub_key() {
                        println!("Auditor: me");
                    } else {
                        println!("Auditor: {}", *auditor_key);
                    }
                } else {
                    println!("Not auditable");
                }

                // Print the freezer, noting if it is us.
                if policy.is_freezer_pub_key_set() {
                    let freezer_key = policy.freezer_pub_key();
                    if *freezer_key == wallet.freezer_pub_key() {
                        println!("Freezer: me");
                    } else {
                        println!("Freezer: {}", *freezer_key);
                    }
                } else {
                    println!("Not freezeable");
                }

                // Print the minter, noting if it is us.
                if info.mint_info.is_some() {
                    println!("Minter: me");
                } else if info.asset.code == AssetCode::native() {
                    println!("Not mintable");
                } else {
                    println!("Minter: unknown");
                }
            }
        ),
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
        command!(
            issue,
            "create a new asset",
            |wallet, desc: String; auditor: Option<AuditorPubKey>, freezer: Option<FreezerPubKey>| {
                let mut policy = AssetPolicy::default();
                if let Some(auditor) = auditor {
                    policy = policy.set_auditor_pub_key(auditor);
                }
                if let Some(freezer) = freezer {
                    policy = policy.set_freezer_pub_key(freezer);
                }
                match wallet.define_asset(desc.as_bytes(), policy).await {
                    Ok(def) => {
                        println!("{}", def.code);
                    }
                    Err(err) => {
                        println!("{}\nAsset was not created.", err);
                    }
                }
            }
        ),
        command!(
            mint,
            "mint an asset",
            |wallet, asset: ListItem<AssetCode>, address: UserAddress, amount: u64, fee: u64| {
                if let Err(err) = wallet.mint(fee, &asset.item, amount, address.0).await {
                    println!("{}\nAssets were not minted.", err);
                }
            }
        ),
        command!(
            info,
            "print general information about this wallet",
            |wallet| {
                println!("Address: {}", wallet.address());
                println!("Public key: {}", wallet.pub_key());
                println!("Audit key: {}", wallet.auditor_pub_key());
                println!("Freeze key: {}", wallet.freezer_pub_key());
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
    static ref WALLET: Arc<Mutex<Wallet>> = Arc::new(Mutex::new(block_on(init_repl())));
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
                let mut args = Vec::new();
                let mut kwargs = HashMap::new();
                for tok in tokens.into_iter().skip(1) {
                    if let Some((key, value)) = tok.split_once("=") {
                        kwargs.insert(String::from(key), String::from(value));
                    } else {
                        args.push(String::from(tok));
                    }
                }
                run(args, kwargs).await;
                continue 'repl;
            }
        }
        println!("Unknown command. Type 'help' for a list of valid commands.");
    }
}
