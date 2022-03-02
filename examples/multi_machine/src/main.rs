// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use crate::routes::{
    dispatch_url, dispatch_web_socket, server_error, RouteBinding, UrlSegmentType, UrlSegmentValue,
};
use async_std::sync::{Arc, RwLock};
use async_std::task;
use async_trait::async_trait;
use futures_util::StreamExt;
use jf_cap::structs::{AssetDefinition, FreezeFlag, ReceiverMemo, RecordCommitment, RecordOpening};
use jf_cap::TransactionVerifyingKey;
use jf_primitives::merkle_tree::FilledMTBuilder;
use key_set::{KeySet, VerifierKeySet};
use phaselock::{
    error::PhaseLockError, event::EventType, message::Message, networking::w_network::WNetwork,
    traits::storage::memory_storage::MemoryStorage, PhaseLock, PhaseLockConfig, PubKey, H_256,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{de::DeserializeOwned, Serialize};
use server::request_body;
use std::collections::hash_map::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;
use tide::StatusCode;
use tide_websockets::{WebSocket, WebSocketConnection};
use toml::Value;
use tracing::{debug, event, Level};
use zerok_lib::{
    api::SpectrumError,
    api::{server, BlockId, PostMemos, TransactionId, UserPubKey},
    node,
    node::{EventStream, PhaseLockEvent, QueryService, Validator},
    state::{
        ElaboratedBlock, ElaboratedTransaction, FullPersistence, LWPersistence, ValidatorState,
        MERKLE_HEIGHT,
    },
    testing::{MultiXfrRecordSpec, MultiXfrTestState, TxnPrintInfo},
    universal_params::UNIVERSAL_PARAM,
};

mod disco;
mod ip;
mod routes;

const STATE_SEED: [u8; 32] = [0x7au8; 32];

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Multi-machine concensus",
    about = "Simulates consensus among multiple machines"
)]
struct NodeOpt {
    /// Path to the node configuration file.
    #[structopt(
        long = "config",
        short = "c",
        default_value = ""      // See fn default_config_path().
    )]
    config: String,

    /// Path to the universal parameter file.
    #[structopt(long = "universal_param_path", short = "u")]
    universal_param_path: Option<String>,

    /// Whether to generate and store public keys for all nodes.
    ///
    /// Public keys will be stored under the directory specified by `pk_path`.
    ///
    /// Skip this option if public key files already exist.
    #[structopt(long = "gen_pk", short = "g")]
    gen_pk: bool,

    /// Whether to load from persisted state.
    ///
    #[structopt(long = "load_from_store", short = "l")]
    load_from_store: bool,

    /// Path to public keys.
    ///
    /// Public keys will be stored under the specified directory, file names starting
    /// with `pk_`.
    #[structopt(
        long = "pk_path", 
        short = "p", 
        default_value = ""      // See fn default_pk_path().
    )]
    pk_path: String,

    /// Path to persistence files.
    ///
    /// Persistence files will be nested under the specified directory
    #[structopt(
        long = "store_path", 
        short = "s", 
        default_value = ""      // See fn default_store_path().
    )]
    store_path: String,

    /// Id of the current node.
    ///
    /// If the node ID is 0, it will propose and try to add transactions.
    ///
    /// Skip this option if only want to generate public key files.
    #[structopt(long = "id", short = "i")]
    id: Option<u64>,

    /// Whether the current node should run a full node.
    #[structopt(long = "full", short = "f")]
    full: bool,

    /// Path to assets including web server files.
    #[structopt(
        long = "assets",
        default_value = ""      // See fn default_web_path().
    )]
    web_path: String,

    /// Path to API specification and messages.
    #[structopt(
        long = "api",
        default_value = ""      // See fn default_api_path().
    )]
    api_path: String,

    /// Use an external wallet to generate transactions.
    ///
    /// The argument is the path to the wallet's public key. If this option is given, the ledger
    /// will be initialized with a record of 2^32 native tokens, owned by the wallet's public key.
    /// The demo will then wait for the wallet to generate some transactions and submit them to the
    /// validators using the network API.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native token
    /// records for different wallets.
    #[structopt(short, long = "wallet")]
    wallet_pk_path: Option<Vec<PathBuf>>,

    /// Number of transactions to generate.
    ///
    /// Skip this option if want to keep generating transactions till the process is killed.
    #[structopt(long = "num_txn", short = "n")]
    num_txn: Option<u64>,

    /// Wait for web server to exit after transactions complete.
    #[structopt(long)]
    wait: bool,
}

/// Gets public key of a node from its public key file.
fn get_public_key(node_id: u64) -> PubKey {
    let path_str = format!("{}/pk_{}", get_pk_dir(), node_id);
    let path = Path::new(&path_str);
    let mut pk_file = File::open(&path)
        .unwrap_or_else(|_| panic!("Cannot find public key file: {}", path.display()));
    let mut pk_str = String::new();
    pk_file
        .read_to_string(&mut pk_str)
        .unwrap_or_else(|err| panic!("Error while reading public key file: {}", err));
    serde_json::from_str(&pk_str).expect("Error while reading public key")
}

/// Returns the project directory.
fn project_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("path {}", path.display());
    path
}

/// Returns "<repo>/public/" where <repo> is
/// derived from the executable path assuming the executable is in
/// two directory levels down and the project directory name
/// can be derived from the executable name.
///
/// For example, if the executable path is
/// ```
///    ~/tri/systems/system/examples/multi_machine/target/release/multi_machine
/// ```
/// then the asset path is
/// ```
///    ~/tri/systems/system/examples/multi_machine/public/
/// ```
fn default_web_path() -> PathBuf {
    const ASSET_DIR: &str = "public";
    let dir = project_path();
    [&dir, Path::new(ASSET_DIR)].iter().collect()
}

/// Returns the default path to the node configuration file.
fn default_config_path() -> PathBuf {
    const CONFIG_FILE: &str = "src/node-config.toml";
    let dir = project_path();
    [&dir, Path::new(CONFIG_FILE)].iter().collect()
}

/// Returns the default directory to store public key files.
fn default_pk_path() -> PathBuf {
    const PK_DIR: &str = "src";
    let dir = project_path();
    [&dir, Path::new(PK_DIR)].iter().collect()
}

/// Returns the default directory to store persistence files.
fn default_store_path(node_id: u64) -> PathBuf {
    const STORE_DIR: &str = "src/store";
    let dir = project_path();
    [
        &dir,
        Path::new(STORE_DIR),
        Path::new(&format!("node{}", node_id)),
    ]
    .iter()
    .collect()
}

/// Returns the default path to the API file.
fn default_api_path() -> PathBuf {
    const API_FILE: &str = "api/api.toml";
    let dir = project_path();
    [&dir, Path::new(API_FILE)].iter().collect()
}

/// Reads configuration file path and node id from options
fn get_node_config() -> Value {
    let config_path_str = NodeOpt::from_args().config;
    let path = if config_path_str.is_empty() {
        println!("default config path");
        default_config_path()
    } else {
        println!("command line config path");
        PathBuf::from(&config_path_str)
    };

    // Read node info from node configuration file
    let mut config_file = File::open(&path)
        .unwrap_or_else(|_| panic!("Cannot find node config file: {}", path.display()));
    let mut config_str = String::new();
    config_file
        .read_to_string(&mut config_str)
        .unwrap_or_else(|err| panic!("Error while reading node config file: {}", err));
    toml::from_str(&config_str).expect("Error while reading node config file")
}

/// Gets the directory to public key files.
fn get_pk_dir() -> String {
    let pk_path = NodeOpt::from_args().pk_path;
    if pk_path.is_empty() {
        default_pk_path()
            .into_os_string()
            .into_string()
            .expect("Error while converting public key path to a string")
    } else {
        pk_path
    }
}

/// Gets the directory to public key files.
fn get_store_dir(node_id: u64) -> String {
    let store_path = NodeOpt::from_args().store_path;
    if store_path.is_empty() {
        default_store_path(node_id)
            .into_os_string()
            .into_string()
            .expect("Error while converting store path to a string")
    } else {
        store_path
    }
}

/// Gets IP address and port number of a node from node configuration file.
fn get_host(node_config: Value, node_id: u64) -> (String, u16) {
    let node = &node_config["nodes"][node_id.to_string()];
    let ip = node["ip"].as_str().expect("Missing IP info").to_owned();
    let port = node["port"].as_integer().expect("Missing port info") as u16;
    (ip, port)
}

/// Trys to get a networking implementation with the given id and port number.
///
/// Also starts the background task.
async fn get_networking<
    T: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug + 'static,
>(
    node_id: u64,
    listen_addr: &str,
    port: u16,
) -> (WNetwork<T>, PubKey) {
    let pub_key = get_public_key(node_id);
    debug!(?pub_key);
    let network = WNetwork::new(pub_key.clone(), listen_addr, port, None).await;
    if let Ok(n) = network {
        let (c, sync) = futures::channel::oneshot::channel();
        match n.generate_task(c) {
            Some(task) => {
                task.into_iter().for_each(|n| {
                    async_std::task::spawn(n);
                });
                sync.await.expect("sync.await failed");
            }
            None => {
                panic!("Failed to launch networking task");
            }
        }
        return (n, pub_key);
    }
    panic!("Failed to open a port");
}

type PLNetwork = WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, ValidatorState, H_256>>;
type PLStorage = MemoryStorage<ElaboratedBlock, ValidatorState, H_256>;
type LWNode = node::LightWeightNode<PLNetwork, PLStorage>;
type FullNode<'a> = node::FullNode<'a, PLNetwork, PLStorage>;

enum Node {
    Light(LWNode),
    Full(Arc<RwLock<FullNode<'static>>>),
}

#[async_trait]
impl Validator for Node {
    type Event = PhaseLockEvent;

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError> {
        match self {
            Node::Light(n) => <LWNode as Validator>::submit_transaction(n, tx).await,
            Node::Full(n) => n.read().await.submit_transaction(tx).await,
        }
    }

    async fn start_consensus(&self) {
        match self {
            Node::Light(n) => n.start_consensus().await,
            Node::Full(n) => n.read().await.start_consensus().await,
        }
    }

    async fn current_state(&self) -> Arc<ValidatorState> {
        match self {
            Node::Light(n) => n.current_state().await,
            Node::Full(n) => n.read().await.current_state().await,
        }
    }

    fn subscribe(&self) -> EventStream<Self::Event> {
        match self {
            Node::Light(n) => n.subscribe(),
            Node::Full(n) => {
                let node = &*task::block_on(n.read());
                <FullNode as Validator>::subscribe(node)
            }
        }
    }
}

/// Creates the initial state and phaselock for simulation.
#[allow(clippy::too_many_arguments)]
async fn init_state_and_phaselock(
    public_keys: tc::PublicKeySet,
    secret_key_share: tc::SecretKeyShare,
    nodes: u64,
    threshold: u64,
    node_id: u64,
    networking: WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, ValidatorState, H_256>>,
    full_node: bool,
    load_from_store: bool,
) -> (Option<MultiXfrTestState>, Node) {
    // Create the initial state
    let (state, validator, records, nullifiers, memos) =
        if let Some(pk_paths) = NodeOpt::from_args().wallet_pk_path {
            let mut rng = zerok_lib::testing::crypto_rng_from_seed([0x42u8; 32]);

            let mut records = FilledMTBuilder::new(MERKLE_HEIGHT).unwrap();
            let mut memos = Vec::new();

            // Process the initial native token records for the wallets.
            for (i, pk_path) in pk_paths.into_iter().enumerate() {
                // Read in the public key of the wallet which will get an initial grant of native
                // coins.
                let mut file = File::open(pk_path).unwrap();
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                let pub_key: UserPubKey = bincode::deserialize(&bytes).unwrap();

                // Create the initial grant.
                event!(
                    Level::INFO,
                    "creating initial native token record for {}",
                    pub_key.address()
                );
                let ro = RecordOpening::new(
                    &mut rng,
                    1u64 << 32,
                    AssetDefinition::native(),
                    pub_key,
                    FreezeFlag::Unfrozen,
                );
                records.push(RecordCommitment::from(&ro).to_field_element());
                memos.push((ReceiverMemo::from_ro(&mut rng, &ro, &[]).unwrap(), i as u64));
            }
            let records = records.build();

            // Set up the validator.
            let univ_setup = &*UNIVERSAL_PARAM;
            let (_, xfr_verif_key_12, _) =
                jf_cap::proof::transfer::preprocess(univ_setup, 1, 2, MERKLE_HEIGHT).unwrap();
            let (_, xfr_verif_key_23, _) =
                jf_cap::proof::transfer::preprocess(univ_setup, 2, 3, MERKLE_HEIGHT).unwrap();
            let (_, mint_verif_key, _) =
                jf_cap::proof::mint::preprocess(univ_setup, MERKLE_HEIGHT).unwrap();
            let (_, freeze_verif_key, _) =
                jf_cap::proof::freeze::preprocess(univ_setup, 2, MERKLE_HEIGHT).unwrap();
            let verif_keys = VerifierKeySet {
                mint: TransactionVerifyingKey::Mint(mint_verif_key),
                xfr: KeySet::new(
                    vec![
                        TransactionVerifyingKey::Transfer(xfr_verif_key_12),
                        TransactionVerifyingKey::Transfer(xfr_verif_key_23),
                    ]
                    .into_iter(),
                )
                .unwrap(),
                freeze: KeySet::new(
                    vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
                )
                .unwrap(),
            };

            let nullifiers = Default::default();
            let validator = ValidatorState::new(verif_keys, records.clone());
            (None, validator, records, nullifiers, memos)
        } else {
            let state = async_std::task::spawn_blocking(|| {
                MultiXfrTestState::initialize(
                    STATE_SEED,
                    10,
                    10,
                    (
                        MultiXfrRecordSpec {
                            asset_def_ix: 0,
                            owner_key_ix: 0,
                            asset_amount: 100,
                        },
                        vec![
                            MultiXfrRecordSpec {
                                asset_def_ix: 1,
                                owner_key_ix: 0,
                                asset_amount: 50,
                            },
                            MultiXfrRecordSpec {
                                asset_def_ix: 0,
                                owner_key_ix: 0,
                                asset_amount: 70,
                            },
                        ],
                    ),
                )
                .unwrap()
            })
            .await;

            let validator = state.validator.clone();
            let record_merkle_tree = state.record_merkle_tree.clone();
            let nullifiers = state.nullifiers.clone();
            let unspent_memos = state.unspent_memos();
            (
                Some(state),
                validator,
                record_merkle_tree,
                nullifiers,
                unspent_memos,
            )
        };

    // Create the initial phaselock
    let known_nodes: Vec<_> = (0..nodes).map(get_public_key).collect();

    let config = PhaseLockConfig {
        total_nodes: nodes as u32,
        threshold: threshold as u32,
        max_transactions: 100,
        known_nodes,
        next_view_timeout: 10000,
        timeout_ratio: (11, 10),
        round_start_delay: 1,
        start_delay: 1,
    };
    debug!(?config);
    let genesis = ElaboratedBlock::default();

    let lw_persistence =
        LWPersistence::new(Path::new(&get_store_dir(node_id)), "multi_machine_demo").unwrap();
    let stored_state = if load_from_store {
        lw_persistence
            .load_latest_state()
            .unwrap_or_else(|_| validator.clone())
    } else {
        validator.clone()
    };
    let (_, phaselock) = PhaseLock::init(
        genesis,
        public_keys,
        secret_key_share,
        node_id,
        config,
        validator,
        networking,
        MemoryStorage::default(),
        lw_persistence,
    )
    .await;
    debug!("phaselock launched");

    let validator = if full_node {
        let full_persisted =
            FullPersistence::new(Path::new(&get_store_dir(node_id)), "multi_machine_demo").unwrap();

        let records = if load_from_store {
            let mut builder = FilledMTBuilder::new(MERKLE_HEIGHT).unwrap();
            for leaf in full_persisted.rmt_leaf_iter() {
                builder.push(leaf.unwrap().0);
            }
            builder.build()
        } else {
            records
        };
        let nullifiers = if load_from_store {
            full_persisted
                .get_latest_nullifier_set()
                .unwrap_or_else(|_| Default::default())
        } else {
            nullifiers
        };
        let node = FullNode::new(
            phaselock,
            &*UNIVERSAL_PARAM,
            stored_state,
            records,
            nullifiers,
            memos,
            full_persisted,
        );
        Node::Full(Arc::new(RwLock::new(node)))
    } else {
        Node::Light(phaselock)
    };

    (state, validator)
}

#[derive(Clone)]
struct Connection {
    id: String,
    wsc: WebSocketConnection,
}

#[derive(Clone)]
pub struct WebState {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    web_path: PathBuf,
    api: toml::Value,
    node: Arc<RwLock<FullNode<'static>>>,
}

async fn submit_endpoint(mut req: tide::Request<WebState>) -> Result<tide::Response, tide::Error> {
    let tx = request_body(&mut req).await?;
    let validator = req.state().node.read().await;
    validator
        .submit_transaction(tx)
        .await
        .map_err(server_error)?;
    Ok(tide::Response::new(StatusCode::Ok))
}

async fn memos_endpoint(mut req: tide::Request<WebState>) -> Result<tide::Response, tide::Error> {
    let PostMemos { memos, signature } = request_body(&mut req).await?;
    let mut bulletin = req.state().node.write().await;
    let TransactionId(BlockId(block), tx) =
        UrlSegmentValue::parse(req.param("txid").unwrap(), "TaggedBase64")
            .ok_or_else(|| {
                server_error(SpectrumError::Param {
                    param: String::from("txid"),
                    msg: String::from(
                        "Valid transaction ID required. Transaction IDs start with TX~.",
                    ),
                })
            })?
            .to()?;
    bulletin
        .post_memos(block as u64, tx as u64, memos, signature)
        .await
        .map_err(server_error)?;
    Ok(tide::Response::new(StatusCode::Ok))
}

async fn users_endpoint(mut req: tide::Request<WebState>) -> Result<tide::Response, tide::Error> {
    let pub_key: UserPubKey = request_body(&mut req).await?;
    let mut bulletin = req.state().node.write().await;
    bulletin.introduce(&pub_key).await.map_err(server_error)?;
    Ok(tide::Response::new(StatusCode::Ok))
}

async fn form_demonstration(req: tide::Request<WebState>) -> Result<tide::Body, tide::Error> {
    let mut index_html: PathBuf = req.state().web_path.clone();
    index_html.push("index.html");
    Ok(tide::Body::from_file(index_html).await?)
}

// Get the route pattern that matches the URL of a request, and the bindings for parameters in the
// pattern. If no route matches, the error is a documentation string explaining what went wrong.
fn parse_route(
    req: &tide::Request<WebState>,
) -> Result<(String, HashMap<String, RouteBinding>), String> {
    let first_segment = &req
        .url()
        .path_segments()
        .ok_or_else(|| String::from("No path segments"))?
        .next()
        .ok_or_else(|| String::from("Empty path"))?;
    let api = &req.state().api["route"][first_segment];
    let route_patterns = api["PATH"]
        .as_array()
        .expect("Invalid PATH type. Expecting array.");
    let mut arg_doc: String = api["DOC"].as_str().expect("Missing DOC").to_string();
    let mut matching_route_count = 0u64;
    let mut matching_route = String::new();
    let mut bindings: HashMap<String, HashMap<String, RouteBinding>> = HashMap::new();
    for route_pattern in route_patterns.iter() {
        let mut found_literal_mismatch = false;
        let mut argument_parse_failed = false;
        arg_doc.push_str(&format!(
            "\n\nRoute: {}\n--------------------\n",
            &route_pattern.as_str().unwrap()
        ));
        // The `path_segments()` succeeded above, so `unwrap()` is safe.
        let mut req_segments = req.url().path_segments().unwrap();
        for pat_segment in route_pattern
            .as_str()
            .expect("PATH must be an array of strings")
            .split('/')
        {
            // Each route parameter has an associated type. The lookup
            // will only succeed if the current segment is a parameter
            // placeholder, such as :id. Otherwise, it is assumed to
            // be a literal.
            if let Some(segment_type_value) = &api.get(pat_segment) {
                let segment_type = segment_type_value
                    .as_str()
                    .expect("The path pattern must be a string.");
                let req_segment = req_segments.next().unwrap_or("");
                arg_doc.push_str(&format!(
                    "  Argument: {} as type {} and value: {} ",
                    pat_segment, segment_type, req_segment
                ));
                if let Some(value) = UrlSegmentValue::parse(req_segment, segment_type) {
                    let rb = RouteBinding {
                        parameter: pat_segment.to_string(),
                        ptype: UrlSegmentType::from_str(segment_type).unwrap(),
                        value,
                    };
                    bindings
                        .entry(String::from(route_pattern.as_str().unwrap()))
                        .or_default()
                        .insert(pat_segment.to_string(), rb);
                    arg_doc.push_str("(Parse succeeded)\n");
                } else {
                    arg_doc.push_str("(Parse failed)\n");
                    argument_parse_failed = true;
                    // TODO !corbett capture parse failures documentation
                    // UrlSegmentValue::ParseFailed(segment_type, req_segment)
                }
            } else {
                // No type information. Assume pat_segment is a literal.
                let req_segment = req_segments.next().unwrap_or("");
                if req_segment != pat_segment {
                    found_literal_mismatch = true;
                    arg_doc.push_str(&format!(
                        "Request segment {} does not match route segment {}.\n",
                        req_segment, pat_segment
                    ));
                }
                // TODO !corbett else capture the matching literal in bindings
                // TODO !corebtt if the edit distance is small, capture spelling suggestion
            }
        }
        if !found_literal_mismatch {
            arg_doc.push_str(&format!(
                "Literals match for {}\n",
                &route_pattern.as_str().unwrap(),
            ));
        }
        let mut length_matches = false;
        if req_segments.next().is_none() {
            arg_doc.push_str(&format!(
                "Length match for {}\n",
                &route_pattern.as_str().unwrap(),
            ));
            length_matches = true;
        }
        if argument_parse_failed {
            arg_doc.push_str(&"Argument parsing failed.\n".to_string());
        } else {
            arg_doc.push_str(&"No argument parsing errors!\n".to_string());
        }
        if !argument_parse_failed && length_matches && !found_literal_mismatch {
            let route_pattern_str = route_pattern.as_str().unwrap();
            arg_doc.push_str(&format!("Route matches request: {}\n", &route_pattern_str));
            matching_route_count += 1;
            matching_route = String::from(route_pattern_str);
        } else {
            arg_doc.push_str("Route does not match request.\n");
        }
    }
    match matching_route_count {
        0 => {
            arg_doc.push_str("\nNeed documentation");
            Err(arg_doc)
        }
        1 => {
            let route_bindings = bindings.remove(&matching_route).unwrap_or_default();
            Ok((matching_route, route_bindings))
        }
        _ => {
            arg_doc.push_str("\nAmbiguity in api.toml");
            Err(arg_doc)
        }
    }
}

/// Handle API requests defined in api.toml.
///
/// This function duplicates the logic for deciding which route was requested. This
/// is an unfortunate side-effect of defining the routes in an external file.
// todo !corbett Convert the error feedback into HTML
async fn entry_page(req: tide::Request<WebState>) -> Result<tide::Response, tide::Error> {
    match parse_route(&req) {
        Ok((pattern, bindings)) => dispatch_url(req, pattern.as_str(), &bindings).await,
        Err(arg_doc) => Ok(tide::Response::builder(200).body(arg_doc).build()),
    }
}

async fn handle_web_socket(
    req: tide::Request<WebState>,
    wsc: WebSocketConnection,
) -> tide::Result<()> {
    match parse_route(&req) {
        Ok((pattern, bindings)) => dispatch_web_socket(req, wsc, pattern.as_str(), &bindings).await,
        Err(arg_doc) => Err(tide::Error::from_str(StatusCode::BadRequest, arg_doc)),
    }
}

// This route is a demonstration of a form with a WebSocket connection
// for asynchronous updates. Once we have useful forms, this can go...
fn add_form_demonstration(web_server: &mut tide::Server<WebState>) {
    web_server
        .at("/transfer/:id/:recipient/:amount")
        .with(WebSocket::new(handle_web_socket))
        .get(form_demonstration);
}

/// Initialize the web server.
///
/// `opt_web_path` is the path to the web assets directory. If the path
/// is empty, the default is constructed assuming Cargo is used to
/// build the executable in the customary location.
///
/// `own_id` is the identifier of this instance of the executable. The
/// port the web server listens on is `own_id + 50000`, unless the
/// PORT environment variable is set.
fn init_web_server(
    opt_api_path: &str,
    opt_web_path: &str,
    own_id: u64,
    node: Arc<RwLock<FullNode<'static>>>,
) -> Result<task::JoinHandle<Result<(), std::io::Error>>, tide::Error> {
    // Take the command line option for the web asset directory path
    // provided it is not empty. Otherwise, construct the default from
    // the executable path.
    let web_path = if opt_web_path.is_empty() {
        default_web_path()
    } else {
        PathBuf::from(opt_web_path)
    };
    let api_path = if opt_api_path.is_empty() {
        default_api_path()
    } else {
        PathBuf::from(opt_api_path)
    };
    println!("Web path: {:?}", web_path);
    let api = disco::load_messages(&api_path);
    let mut web_server = tide::with_state(WebState {
        connections: Default::default(),
        web_path: web_path.clone(),
        api: api.clone(),
        node,
    });
    web_server
        .with(server::trace)
        .with(server::add_error_body::<_, SpectrumError>);

    // Define the routes handled by the web server.
    web_server.at("/public").serve_dir(web_path)?;
    web_server.at("/").get(disco::compose_help);

    add_form_demonstration(&mut web_server);

    // Define the routes handled by the validator and bulletin board. Eventually these should have
    // their own services. For demo purposes, since they are not really part of the query service,
    // we just handle them here in a pretty ad hoc fashion.
    web_server.at("/submit").post(submit_endpoint);
    web_server.at("/memos/:txid").post(memos_endpoint);
    web_server.at("/users").post(users_endpoint);

    // Add routes from a configuration file.
    if let Some(api_map) = api["route"].as_table() {
        api_map.values().for_each(|v| {
            let web_socket = v
                .get("WEB_SOCKET")
                .map(|v| v.as_bool().expect("expected boolean value for WEB_SOCKET"))
                .unwrap_or(false);
            let routes = match &v["PATH"] {
                toml::Value::String(s) => {
                    vec![s.clone()]
                }
                toml::Value::Array(a) => a
                    .iter()
                    .filter_map(|v| {
                        if let Some(s) = v.as_str() {
                            Some(String::from(s))
                        } else {
                            println!("Oops! Array element: {:?}", v);
                            None
                        }
                    })
                    .collect(),
                _ => panic!("Expecting a toml::String or toml::Array, but got: {:?}", &v),
            };
            for path in routes {
                let mut route = web_server.at(&path);
                if web_socket {
                    route.get(WebSocket::new(handle_web_socket));
                } else {
                    route.get(entry_page);
                }
            }
        });
    }

    let port = std::env::var("PORT").unwrap_or_else(|_| (50000 + &own_id).to_string());
    let addr = format!("0.0.0.0:{}", port);
    let join_handle = async_std::task::spawn(web_server.listen(addr));
    Ok(join_handle)
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt().pretty().init();

    // Get configuration
    let node_config = get_node_config();

    // Override the path to the universal parameter file if it's specified
    if let Some(dir) = NodeOpt::from_args().universal_param_path {
        std::env::set_var("UNIVERSAL_PARAM_PATH", dir);
    }

    // Get secret key set
    let seed: [u8; 32] = node_config["seed"]
        .as_array()
        .expect("Missing seed value")
        .iter()
        .map(|i| i.as_integer().expect("Invalid seed value") as u8)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Error while converting the seed into an array");
    let nodes = node_config["nodes"]
        .as_table()
        .expect("Missing nodes info")
        .len() as u64;
    let threshold = ((nodes * 2) / 3) + 1;

    // Generate key sets
    let secret_keys =
        tc::SecretKeySet::random(threshold as usize - 1, &mut ChaChaRng::from_seed(seed));
    let public_keys = secret_keys.public_keys();

    // Generate public key for each node
    let pk_dir = get_pk_dir();
    if NodeOpt::from_args().gen_pk {
        for node_id in 0..nodes {
            let pub_key = PubKey::from_secret_key_set_escape_hatch(&secret_keys, node_id);
            let pub_key_str = serde_json::to_string(&pub_key)
                .unwrap_or_else(|err| panic!("Error while serializing the public key: {}", err));
            let mut pk_file = File::create(format!("{}/pk_{}", pk_dir, node_id))
                .unwrap_or_else(|err| panic!("Error while creating a public key file: {}", err));
            pk_file
                .write_all(pub_key_str.as_bytes())
                .unwrap_or_else(|err| {
                    panic!("Error while writing to the public key file: {}", err)
                });
        }
        println!("Public key files created");
    }

    // TODO !nathan.yospe, jeb.bearer - add option to reload vs init
    let load_from_store = NodeOpt::from_args().load_from_store;
    if load_from_store {
        println!("restoring from persisted session");
    } else {
        println!("initializing new session");
    }

    if let Some(own_id) = NodeOpt::from_args().id {
        println!("Current node: {}", own_id);
        let secret_key_share = secret_keys.secret_key_share(own_id);

        // Get networking information
        let (own_network, _) =
            get_networking(own_id, "0.0.0.0", get_host(node_config.clone(), own_id).1).await;
        #[allow(clippy::type_complexity)]
        let mut other_nodes: Vec<(u64, PubKey, String, u16)> = Vec::new();
        for id in 0..nodes {
            if id != own_id {
                let (ip, port) = get_host(node_config.clone(), id);
                let pub_key = get_public_key(id);
                other_nodes.push((id, pub_key, ip, port));
            }
        }

        // Connect the networking implementations
        for (id, pub_key, ip, port) in other_nodes {
            let socket = format!("{}:{}", ip, port);
            while own_network
                .connect_to(pub_key.clone(), &socket)
                .await
                .is_err()
            {
                debug!("  - Retrying");
                async_std::task::sleep(std::time::Duration::from_millis(10_000)).await;
            }
            println!("  - Connected to node {}", id);
        }

        // Wait for the networking implementations to connect
        while (own_network.connection_table_size().await as u64) < nodes - 1 {
            async_std::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        println!("All nodes connected to network");

        // Initialize the state and phaselock
        let (mut state, mut phaselock) = init_state_and_phaselock(
            public_keys,
            secret_key_share,
            nodes,
            threshold,
            own_id,
            own_network,
            NodeOpt::from_args().full,
            load_from_store,
        )
        .await;
        let mut events = phaselock.subscribe();

        // If we are running a full node, also host a query API to inspect the accumulated state.
        let web_server = if let Node::Full(node) = &phaselock {
            Some(
                init_web_server(
                    &NodeOpt::from_args().api_path,
                    &NodeOpt::from_args().web_path,
                    own_id,
                    node.clone(),
                )
                .expect("Failed to initialize web server"),
            )
        } else {
            None
        };

        #[cfg(target_os = "linux")]
        let bytes_per_page = procfs::page_size().unwrap() as u64;
        #[cfg(target_os = "linux")]
        println!("{} bytes per page", bytes_per_page);

        let fence = || std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        let report_mem = || {
            fence();
            #[cfg(target_os = "linux")]
            {
                let process_stats = procfs::process::Process::myself().unwrap().statm().unwrap();
                println!(
                    "{:.3}MiB | raw: {:?}",
                    ((process_stats.size * bytes_per_page) as f64) / ((1u64 << 20) as f64),
                    process_stats
                );
            }
            fence();
        };

        // Start consensus for each transaction
        let mut round = 0;
        let num_txn = NodeOpt::from_args().num_txn;

        // When `num_txn` is set, run `num_txn` rounds.
        // Otherwise, keeping running till the process is killed.
        let mut txn: Option<(usize, _, _, ElaboratedTransaction)> = None;
        let mut txn_proposed_round = 0;
        while num_txn.map(|count| round < count).unwrap_or(true) {
            println!("Starting round {}", round + 1);
            report_mem();
            println!("Commitment: {}", phaselock.current_state().await.commit());

            // Generate a transaction if the node ID is 0 and if there isn't a wallet to generate it.
            if own_id == 0 {
                if let Some(tx) = txn.as_ref() {
                    println!("  - Reproposing a transaction");
                    if txn_proposed_round + 5 < round {
                        // TODO
                        phaselock.submit_transaction(tx.clone().3).await.unwrap();
                        txn_proposed_round = round;
                    }
                } else if let Some(mut true_state) = core::mem::take(&mut state) {
                    println!("  - Proposing a transaction");
                    let (true_state, mut transactions) =
                        async_std::task::spawn_blocking(move || {
                            let txs = true_state
                                .generate_transactions(
                                    vec![(true, 0, 0, 0, 0, -2)],
                                    TxnPrintInfo::new_no_time(round as usize, 1),
                                )
                                .unwrap();
                            (true_state, txs)
                        })
                        .await;
                    txn = Some(transactions.remove(0));
                    state = Some(true_state);
                    phaselock
                        .submit_transaction(txn.clone().unwrap().3)
                        .await
                        .unwrap();
                    txn_proposed_round = round;
                }
            }

            // If the output below is changed, update the message for line.trim() in Validator::new as well
            println!("  - Starting consensus");
            phaselock.start_consensus().await;
            let success = loop {
                println!("Waiting for PhaseLock event");
                let event = events.next().await.expect("PhaseLock unexpectedly closed");

                match event.event {
                    EventType::Decide { block: _, state } => {
                        if !state.is_empty() {
                            let commitment = TaggedBase64::new("LEDG", state[0].commit().as_ref())
                                .unwrap()
                                .to_string();
                            println!(
                                "  - Round {} completed. Commitment: {}",
                                round + 1,
                                commitment
                            );
                            break true;
                        }
                    }
                    EventType::ViewTimeout { view_number: _ } => {
                        println!("  - Round {} timed out.", round + 1);
                        break false;
                    }
                    EventType::Error { error } => {
                        println!("  - Round {} error: {}", round + 1, error);
                        break false;
                    }
                    _ => {
                        println!("EVENT: {:?}", event);
                    }
                }
            };

            if success {
                // Add the transaction if the node ID is 0 (i.e., the transaction is proposed by the
                // current node), and there is no attached wallet.
                if let Some((ix, keys_and_memos, sig, t)) = core::mem::take(&mut txn) {
                    let state = state.as_mut().unwrap();
                    println!("  - Adding the transaction");
                    let mut blk = ElaboratedBlock::default();
                    let (owner_memos, kixs) = {
                        let mut owner_memos = vec![];
                        let mut kixs = vec![];

                        for (kix, memo) in keys_and_memos {
                            kixs.push(kix);
                            owner_memos.push(memo);
                        }
                        (owner_memos, kixs)
                    };

                    // If we're running a full node, publish the receiver memos.
                    if let Node::Full(node) = &mut phaselock {
                        node.write()
                            .await
                            .post_memos(round, ix as u64, owner_memos.clone(), sig)
                            .await
                            .unwrap();
                    }

                    state
                        .try_add_transaction(
                            &mut blk,
                            t,
                            ix,
                            owner_memos,
                            kixs,
                            TxnPrintInfo::new_no_time(round as usize, 1),
                        )
                        .unwrap();
                    state
                        .validate_and_apply(blk, 0.0, TxnPrintInfo::new_no_time(round as usize, 1))
                        .unwrap();
                }
            }

            round += 1;
        }

        println!("All rounds completed");

        if NodeOpt::from_args().wait {
            if let Some(join_handle) = web_server {
                join_handle.await.unwrap_or_else(|err| {
                    panic!("web server exited with an error: {}", err);
                });
            }
        }
    }

    Ok(())
}
