////////////////////////////////////////////////////////////////////////////////
// The AAP Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

use crate::{api, wallet, UNIVERSAL_PARAM};
use api::{MerklePath, UserAddress};
use async_std::task::block_on;
use async_trait::async_trait;
use encryption::{Cipher, CipherText};
use fmt::{Display, Formatter};
use futures::future::BoxFuture;
use jf_txn::{
    keys::{AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserKeyPair},
    proof::UniversalParam,
    structs::{AssetCode, AssetDefinition, AssetPolicy, ReceiverMemo, RecordCommitment},
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use rpassword::prompt_password_stdout;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::any::type_name;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::iter::once;
use std::path::PathBuf;
use std::str::FromStr;
use tagged_base64::TaggedBase64;
use tempdir::TempDir;
use wallet::{
    encryption, hd::KeyTree, ledger::Ledger, persistence::WalletLoader, AssetInfo, BincodeError,
    EncryptionError, IoError, KeyError, MintInfo, TransactionReceipt, TransactionStatus,
    WalletBackend, WalletError,
};

pub trait CLI<'a> {
    type Ledger: 'static + Ledger;
    type Backend: 'a + WalletBackend<'a, Self::Ledger> + Send + Sync;
    type Args: CLIArgs;

    fn init_backend(
        universal_param: &'a UniversalParam,
        args: &'a Self::Args,
        loader: &mut impl WalletLoader<Meta = WalletMetadata>,
    ) -> Result<Self::Backend, WalletError>;
}

pub trait CLIArgs {
    fn key_gen_path(&self) -> Option<PathBuf>;
    fn storage_path(&self) -> Option<PathBuf>;
    fn interactive(&self) -> bool;
    fn encrypted(&self) -> bool;
    fn use_tmp_storage(&self) -> bool;
}

type Wallet<'a, C> = wallet::Wallet<'a, <C as CLI<'a>>::Backend, <C as CLI<'a>>::Ledger>;

// A REPL command.
struct Command<'a, C: CLI<'a>> {
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
    run: CommandFunc<'a, C>,
}

type CommandFunc<'a, C> = Box<
    dyn Sync
        + for<'l> Fn(&'l mut Wallet<'a, C>, Vec<String>, HashMap<String, String>) -> BoxFuture<'l, ()>,
>;

impl<'a, C: CLI<'a>> Display for Command<'a, C> {
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

pub trait CLIInput<'a, C: CLI<'a>>: Sized {
    fn parse_for_wallet(wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self>;
}

macro_rules! cli_input_from_str {
    ($($t:ty),*) => {
        $(
            impl<'a, C: CLI<'a>> CLIInput<'a, C> for $t {
                fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
                    Self::from_str(s).ok()
                }
            }
        )*
    }
}

cli_input_from_str! {
    bool, u64, String, AssetCode, AuditorPubKey, FreezerPubKey, UserAddress, PathBuf, ReceiverMemo,
    RecordCommitment, MerklePath
}

impl<'a, C: CLI<'a>, L: Ledger> CLIInput<'a, C> for TransactionReceipt<L> {
    fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        Self::from_str(s).ok()
    }
}

macro_rules! command {
    ($name:ident,
     $help:expr,
     $cli:ident,
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
            run: Box::new(|wallet, args, kwargs| Box::pin(async move {
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
                    let $arg = match <$argty as CLIInput<$cli>>::parse_for_wallet(wallet, args.next().unwrap().as_str()) {
                        Some(arg) => arg,
                        None => {
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
                        Some(val) => match <$kwargty as CLIInput<$cli>>::parse_for_wallet(wallet, val) {
                            Some(arg) => Some(arg),
                            None => {
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

                let $wallet = wallet;
                $run
            }))
        }
    };

    // Don't require a comma after $wallet if there are no additional args.
    ($name:ident, $help:expr, $cli:ident, |$wallet:pat| $run:expr) => {
        command!($name, $help, $cli, |$wallet,| $run)
    };

    // Don't require wallet at all.
    ($name:ident, $help:expr, $cli:ident, || $run:expr) => {
        command!($name, $help, $cli, |_| $run)
    };
}

macro_rules! count {
    () => (0);
    ($x:tt $($xs:tt)*) => (1 + count!($($xs)*));
}

// Types which can be listed in terminal output and parsed from a list index.
#[async_trait]
trait Listable<'a, C: CLI<'a>>: Sized {
    async fn list(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>>;

    fn list_sync(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>> {
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

impl<'a, C: CLI<'a>, T: Listable<'a, C> + CLIInput<'a, C>> CLIInput<'a, C> for ListItem<T> {
    fn parse_for_wallet(wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        if let Ok(index) = usize::from_str(s) {
            // If the input looks like a list index, build the list for type T and get an element of
            // type T by indexing.
            let mut items = T::list_sync(wallet);
            if index < items.len() {
                Some(items.remove(index))
            } else {
                None
            }
        } else {
            // Otherwise, just parse a T directly.
            T::parse_for_wallet(wallet, s).map(|item| ListItem {
                item,
                index: 0,
                annotation: None,
            })
        }
    }
}

#[async_trait]
impl<'a, C: CLI<'a>> Listable<'a, C> for AssetCode {
    async fn list(wallet: &mut Wallet<'a, C>) -> Vec<ListItem<Self>> {
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

        // Get our auditor and freezer keys so we can check if the asset types are
        // auditable/freezable.
        let audit_keys = wallet.auditor_pub_keys().await;
        let freeze_keys = wallet.freezer_pub_keys().await;

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
                    if audit_keys.contains(policy.auditor_pub_key()) {
                        attributes.push('a');
                    }
                    if freeze_keys.contains(policy.freezer_pub_key()) {
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

fn init_commands<'a, C: CLI<'a>>() -> Vec<Command<'a, C>> {
    vec![
        command!(
            address,
            "print all public addresses of this wallet",
            C,
            |wallet| {
                for pub_key in wallet.pub_keys().await {
                    println!("{}", api::UserAddress(pub_key.address()));
                }
            }
        ),
        command!(
            pub_key,
            "print all of the public keys of this wallet",
            C,
            |wallet| {
                for pub_key in wallet.pub_keys().await {
                    println!("{:?}", pub_key);
                }
            }
        ),
        command!(assets, "list assets known to the wallet", C, |wallet| {
            for item in <AssetCode as Listable<C>>::list(wallet).await {
                println!("{}", item);
            }
            println!("(a=auditable, f=freezeable, m=mintable)");
        }),
        command!(
            asset,
            "print information about an asset",
            C,
            |wallet, asset: ListItem<AssetCode>| {
                let assets = wallet.assets().await;
                let info = if asset.item == AssetCode::native() {
                    // We always recognize the native asset type in the CLI, even if it's not
                    // included in the wallet's assets yet.
                    AssetInfo::from(AssetDefinition::native())
                } else {
                    match assets.get(&asset.item) {
                        Some(info) => info.clone(),
                        None => {
                            println!("No such asset {}", asset.item);
                            return;
                        }
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
                    if wallet.auditor_pub_keys().await.contains(auditor_key) {
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
                    if wallet.freezer_pub_keys().await.contains(freezer_key) {
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
            "print owned balances of asset",
            C,
            |wallet, asset: ListItem<AssetCode>| {
                println!("Address Balance");
                for pub_key in wallet.pub_keys().await {
                    println!(
                        "{} {}",
                        UserAddress(pub_key.address()),
                        wallet.balance(&pub_key.address(), &asset.item).await
                    );
                }
            }
        ),
        command!(
            transfer,
            "transfer some owned assets to another user",
            C,
            |wallet, asset: ListItem<AssetCode>, from: UserAddress, to: UserAddress, amount: u64, fee: u64; wait: Option<bool>| {
                match wallet
                    .transfer(&from.0, &asset.item, &[(to.0, amount)], fee)
                    .await
                {
                    Ok(receipt) => {
                        if wait == Some(true) {
                            match wallet.await_transaction(&receipt).await {
                                Err(err) => {
                                    println!("Error waiting for transaction to complete: {}", err);
                                }
                                Ok(TransactionStatus::Retired) => {},
                                _ => {
                                    println!("Transaction failed");
                                }
                            }
                        } else {
                            println!("Transaction {}", receipt);
                        }
                    }
                    Err(err) => {
                        println!("{}\nAssets were not transferred.", err);
                    }
                }
            }
        ),
        command!(
            issue,
            "create a new asset",
            C,
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
            C,
            |wallet, asset: ListItem<AssetCode>, from: UserAddress, to: UserAddress, amount: u64, fee: u64; wait: Option<bool>| {
                match wallet
                    .mint(&from.0, fee, &asset.item, amount, to.0)
                    .await
                {
                    Ok(receipt) => {
                        if wait == Some(true) {
                            match wallet.await_transaction(&receipt).await {
                                Err(err) => {
                                    println!("Error waiting for transaction to complete: {}", err);
                                }
                                Ok(TransactionStatus::Retired) => {},
                                _ => {
                                    println!("Transaction failed");
                                }
                            }
                        } else {
                            println!("Transaction {}", receipt);
                        }
                    }
                    Err(err) => {
                        println!("{}\nAssets were not minted.", err);
                    }
                }
            }
        ),
        command!(
            transactions,
            "list past transactions sent and received by this wallet",
            C,
            |wallet| {
                match wallet.transaction_history().await {
                    Ok(txns) => {
                        println!("Submitted Status Asset Type Sender Receiver Amount ...");
                        for txn in txns {
                            let status = match &txn.receipt {
                                Some(receipt) => wallet
                                    .transaction_status(receipt)
                                    .await
                                    .unwrap_or(TransactionStatus::Unknown),
                                None => {
                                    // Transaction history entries lack a receipt only if they are
                                    // received transactions from someone else. We only receive
                                    // transactions once they have been retired.
                                    TransactionStatus::Retired
                                }
                            };
                            // Try to get a readable name for the asset.
                            let asset = if txn.asset == AssetCode::native() {
                                String::from("Native")
                            } else if let Some(AssetInfo {
                                mint_info: Some(mint_info),
                                ..
                            }) = wallet.assets().await.get(&txn.asset)
                            {
                                // If the description looks like it came from a string, interpret as
                                // a string. Otherwise, encode the binary blob as tagged base64.
                                match std::str::from_utf8(&mint_info.desc) {
                                    Ok(s) => String::from(s),
                                    Err(_) => TaggedBase64::new("DESC", &mint_info.desc)
                                        .unwrap()
                                        .to_string(),
                                }
                            } else {
                                txn.asset.to_string()
                            };
                            let sender = match txn.sender {
                                Some(sender) => UserAddress(sender).to_string(),
                                None => String::from("unknown"),
                            };
                            print!("{} {} {} {} {} ", txn.time, status, asset, txn.kind, sender);
                            for (receiver, amount) in txn.receivers {
                                print!("{} {} ", UserAddress(receiver), amount);
                            }
                            if let Some(receipt) = txn.receipt {
                                print!("{}", receipt);
                            }
                            println!();
                        }
                    }
                    Err(err) => println!("Error reading transaction history: {}", err),
                }
            }
        ),
        command!(
            transaction,
            "print the status of a transaction",
            C,
            |wallet, receipt: TransactionReceipt<C::Ledger>| {
                match wallet.transaction_status(&receipt).await {
                    Ok(status) => println!("{}", status),
                    Err(err) => println!("Error getting transaction status: {}", err),
                }
            }
        ),
        command!(
            wait,
            "wait for a transaction to complete",
            C,
            |wallet, receipt: TransactionReceipt<C::Ledger>| {
                match wallet.await_transaction(&receipt).await {
                    Ok(status) => println!("{}", status),
                    Err(err) => println!("Error waiting for transaction: {}", err),
                }
            }
        ),
        command!(keys, "list keys tracked by this wallet", C, |wallet| {
            print_keys::<C>(wallet).await;
        }),
        command!(
            gen_key,
            "generate new keys",
            C,
            |wallet, key_type: KeyType| {
                match key_type {
                    KeyType::Audit => match wallet.generate_audit_key().await {
                        Ok(pub_key) => println!("{}", pub_key),
                        Err(err) => println!("Error generating audit key: {}", err),
                    },
                    KeyType::Freeze => match wallet.generate_freeze_key().await {
                        Ok(pub_key) => println!("{}", pub_key),
                        Err(err) => println!("Error generating freeze key: {}", err),
                    },
                    KeyType::Spend => match wallet.generate_user_key().await {
                        Ok(pub_key) => println!("{}", UserAddress(pub_key.address())),
                        Err(err) => println!("Error generating spending key: {}", err),
                    },
                }
            }
        ),
        command!(
            load_key,
            "load a key from a file",
            C,
            |wallet, key_type: KeyType, path: PathBuf; scan_from: Option<u64>| {
                let mut file = match File::open(path.clone()).context(IoError) {
                    Ok(file) => file,
                    Err(err) => {
                        println!("Error opening file {:?}: {}", path, err);
                        return;
                    }
                };
                let mut bytes = Vec::new();
                if let Err(err) = file.read_to_end(&mut bytes).context(IoError) {
                    println!("Error reading file: {}", err);
                    return;
                }

                match key_type {
                    KeyType::Audit => match bincode::deserialize::<AuditorKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_audit_key(key.clone()).await {
                            Ok(()) => println!("{}", key.pub_key()),
                            Err(err) => println!("Error saving audit key: {}", err),
                        },
                        Err(err) => {
                            println!("Error loading audit key: {}", err);
                        }
                    },
                    KeyType::Freeze => match bincode::deserialize::<FreezerKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_freeze_key(key.clone()).await {
                            Ok(()) => println!("{}", key.pub_key()),
                            Err(err) => println!("Error saving freeze key: {}", err),
                        },
                        Err(err) => {
                            println!("Error loading freeze key: {}", err);
                        }
                    },
                    KeyType::Spend => match bincode::deserialize::<UserKeyPair>(&bytes) {
                        Ok(key) => match wallet.add_user_key(key.clone(), scan_from.unwrap_or(0)).await {
                            Ok(()) => {
                                println!(
                                    "Note: assets belonging to this key will become available after\
                                     a scan of the ledger. This may take a long time. If you have\
                                     the owner memo for a record you want to use immediately, use\
                                     import_memo.");
                                println!("{}", UserAddress(key.address()));
                            }
                            Err(err) => println!("Error saving spending key: {}", err),
                        },
                        Err(err) => {
                            println!("Error loading spending key: {}", err);
                        }
                    },
                };
            }
        ),
        command!(
            import_memo,
            "import an owner memo belonging to this wallet",
            C,
            |wallet, memo: ReceiverMemo, comm: RecordCommitment, uid: u64, proof: MerklePath| {
                if let Err(err) = wallet.import_memo(memo, comm, uid, proof.0).await {
                    println!("{}", err);
                }
            }
        ),
        command!(
            info,
            "print general information about this wallet",
            C,
            |wallet| {
                println!("Addresses:");
                for pub_key in wallet.pub_keys().await {
                    println!("  {}", UserAddress(pub_key.address()));
                }
                print_keys::<C>(wallet).await;
            }
        ),
    ]
}

async fn print_keys<'a, C: CLI<'a>>(wallet: &Wallet<'a, C>) {
    println!("Public keys:");
    for key in wallet.pub_keys().await {
        println!("  {}", key);
    }
    println!("Audit keys:");
    for key in wallet.auditor_pub_keys().await {
        println!("  {}", key);
    }
    println!("Freeze keys:");
    for key in wallet.freezer_pub_keys().await {
        println!("  {}", key);
    }
}

enum KeyType {
    Audit,
    Freeze,
    Spend,
}

impl<'a, C: CLI<'a>> CLIInput<'a, C> for KeyType {
    fn parse_for_wallet(_wallet: &mut Wallet<'a, C>, s: &str) -> Option<Self> {
        match s {
            "audit" => Some(Self::Audit),
            "freeze" => Some(Self::Freeze),
            "spend" => Some(Self::Spend),
            _ => None,
        }
    }
}

enum Reader {
    Interactive(rustyline::Editor<()>),
    Automated,
}

impl Reader {
    fn new(args: &impl CLIArgs) -> Self {
        if args.interactive() {
            Self::Interactive(rustyline::Editor::<()>::new())
        } else {
            Self::Automated
        }
    }

    fn read_password(&self, prompt: &str) -> Result<String, WalletError> {
        match self {
            Self::Interactive(_) => {
                prompt_password_stdout(prompt).map_err(|err| WalletError::Failed {
                    msg: err.to_string(),
                })
            }
            Self::Automated => {
                println!("{}", prompt);
                let mut password = String::new();
                match std::io::stdin().read_line(&mut password) {
                    Ok(_) => Ok(password),
                    Err(err) => Err(WalletError::Failed {
                        msg: err.to_string(),
                    }),
                }
            }
        }
    }

    fn read_line(&mut self) -> Option<String> {
        let prompt = "> ";
        match self {
            Self::Interactive(editor) => editor.readline(prompt).ok(),
            Self::Automated => {
                println!("{}", prompt);
                let mut line = String::new();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) => {
                        // EOF
                        None
                    }
                    Err(_) => None,
                    Ok(_) => Some(line),
                }
            }
        }
    }
}

// Metadata about a wallet which is always stored unencrypted, so we can report some basic
// information about the wallet without decrypting. This also aids in the key derivation process.
//
// DO NOT put secrets in here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMetadata {
    encrypted: bool,
    salt: encryption::Salt,
    // Encrypted random bytes. This will only decrypt successfully if we have the correct password,
    // so we can use it as a quick check that the user entered the right password.
    password_check: CipherText,
}

struct PasswordLoader {
    encrypted: bool,
    dir: PathBuf,
    rng: ChaChaRng,
    reader: Reader,
}

impl WalletLoader for PasswordLoader {
    type Meta = WalletMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(WalletMetadata, KeyTree), WalletError> {
        let password = if self.encrypted {
            loop {
                let password = self.reader.read_password("Create password: ")?;
                let confirm = self.reader.read_password("Retype password: ")?;
                if password == confirm {
                    break password;
                } else {
                    println!("Passwords do not match.");
                }
            }
        } else {
            String::new()
        };

        let (key, salt) =
            KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeyError)?;

        // Encrypt some random data, which we can decrypt on load to check the user's password.
        let mut password_check = [0; 32];
        self.rng.fill_bytes(&mut password_check);
        let password_check = Cipher::new(key.clone(), ChaChaRng::from_rng(&mut self.rng).unwrap())
            .encrypt(&password_check)
            .context(EncryptionError)?;

        let meta = WalletMetadata {
            encrypted: self.encrypted,
            salt,
            password_check,
        };
        Ok((meta, key))
    }

    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError> {
        if !self.encrypted {
            return Err(WalletError::Failed {
                msg: String::from(
                    "option --unencrypted is not allowed when loading an existing wallet",
                ),
            });
        }

        let key = loop {
            let password = if meta.encrypted {
                self.reader.read_password("Enter password: ")?
            } else {
                String::new()
            };

            // Generate the key and check that we can use it to decrypt the `password_check` data.
            // If we can't, the password is wrong.
            let key = KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt)
                .context(KeyError)?;
            if Cipher::new(key.clone(), ChaChaRng::from_rng(&mut self.rng).unwrap())
                .decrypt(&meta.password_check)
                .is_ok()
            {
                break key;
            } else if !meta.encrypted {
                // If the default password doesn't work, then the password_check data must be
                // corrupted or encrypted with a non-default password. If the metadata claims it is
                // unencrypted, than the metadata is corrupt (either in the `encrypted` field, the
                // `password_check` field, or both).
                return Err(WalletError::Failed {
                    msg: String::from("wallet metadata is corrupt"),
                });
            } else {
                println!("Sorry, that's incorrect.");
            }
        };

        Ok(key)
    }
}

pub async fn cli_main<'a, C: CLI<'a>>(args: &'a C::Args) -> Result<(), WalletError> {
    if let Some(path) = args.key_gen_path() {
        key_gen(path)
    } else {
        repl::<C>(args).await
    }
}

fn key_gen(mut path: PathBuf) -> Result<(), WalletError> {
    let key_pair = wallet::new_key_pair();

    let mut file = File::create(path.clone()).context(IoError)?;
    let bytes = bincode::serialize(&key_pair).context(BincodeError)?;
    file.write_all(&bytes).context(IoError)?;

    path.set_extension("pub");
    let mut file = File::create(path).context(IoError)?;
    let bytes = bincode::serialize(&key_pair.pub_key()).context(BincodeError)?;
    file.write_all(&bytes).context(IoError)?;

    Ok(())
}

async fn repl<'a, C: CLI<'a>>(args: &'a C::Args) -> Result<(), WalletError> {
    let (storage, _tmp_dir) = match args.storage_path() {
        Some(storage) => (storage, None),
        None if !args.use_tmp_storage() => {
            let home = std::env::var("HOME").map_err(|_| WalletError::Failed {
                msg: String::from(
                    "HOME directory is not set. Please set your HOME directory, or specify \
                        a different storage location using --storage.",
                ),
            })?;
            let mut dir = PathBuf::from(home);
            dir.push(".translucence/wallet");
            (dir, None)
        }
        None => {
            let tmp_dir = TempDir::new("wallet").context(IoError)?;
            (PathBuf::from(tmp_dir.path()), Some(tmp_dir))
        }
    };

    println!(
        "Welcome to the AAP wallet, version {}",
        env!("CARGO_PKG_VERSION")
    );
    println!("(c) 2021 Translucence Research, Inc.");

    let reader = Reader::new(args);
    let mut loader = PasswordLoader {
        dir: storage,
        encrypted: args.encrypted(),
        rng: ChaChaRng::from_entropy(),
        reader,
    };
    let backend = C::init_backend(&*UNIVERSAL_PARAM, args, &mut loader)?;

    // Loading the wallet takes a while. Let the user know that's expected.
    //todo !jeb.bearer Make it faster
    println!("connecting...");
    let mut wallet = Wallet::<C>::new(backend).await?;
    println!("Type 'help' for a list of commands.");
    let commands = init_commands::<C>();

    let mut input = Reader::new(args);
    'repl: while let Some(line) = input.read_line() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0] == "help" {
            for command in commands.iter() {
                println!("{}", command);
            }
            continue;
        }
        for Command { name, run, .. } in commands.iter() {
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
                run(&mut wallet, args, kwargs).await;
                continue 'repl;
            }
        }
        println!("Unknown command. Type 'help' for a list of valid commands.");
    }

    Ok(())
}
