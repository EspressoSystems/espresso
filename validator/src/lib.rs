// Copyright © 2021 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]

use crate::routes::{
    dispatch_url, dispatch_web_socket, server_error, RouteBinding, UrlSegmentType, UrlSegmentValue,
};
use async_std::sync::{Arc, RwLock};
use async_std::task;
use async_trait::async_trait;
use jf_cap::{
    structs::{AssetDefinition, FreezeFlag, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, TransactionVerifyingKey,
};
use jf_primitives::merkle_tree::FilledMTBuilder;
use key_set::{KeySet, VerifierKeySet};
use phaselock::{
    traits::implementations::{AtomicStorage, WNetwork},
    types::Message,
    PhaseLock, PhaseLockConfig, PhaseLockError, PubKey, H_256,
};
use rand_chacha::{rand_core::SeedableRng as _, ChaChaRng};
use rand_chacha_02::{rand_core::SeedableRng as _, ChaChaRng as ChaChaRng02};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use server::request_body;
use std::collections::hash_map::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::StructOpt;
use threshold_crypto as tc;
use tide::StatusCode;
use tide_websockets::{WebSocket, WebSocketConnection};
use tracing::{debug, event, Level};
use zerok_lib::{
    api::EspressoError,
    api::{server, BlockId, PostMemos, TransactionId, UserPubKey},
    committee::Committee,
    node,
    node::{EventStream, PhaseLockEvent, QueryService, Validator},
    state::{
        ElaboratedBlock, ElaboratedTransaction, FullPersistence, LWPersistence, SetMerkleTree,
        ValidatorState, MERKLE_HEIGHT,
    },
    testing::{MultiXfrRecordSpec, MultiXfrTestState},
    universal_params::UNIVERSAL_PARAM,
};

mod disco;
mod ip;
mod routes;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub const MINIMUM_NODES: usize = 5;

const GENESIS_SEED: [u8; 32] = [0x7au8; 32];

#[derive(Debug, StructOpt)]
pub struct NodeOpt {
    /// Whether to load from persisted state.
    ///
    #[structopt(long = "load_from_store", short = "l")]
    pub load_from_store: bool,

    /// Path to persistence files.
    ///
    /// Persistence files will be nested under the specified directory
    #[structopt(long = "store_path", short = "s")]
    pub store_path: Option<PathBuf>,

    /// Whether the current node should run a full node.
    #[structopt(long = "full", short = "f")]
    pub full: bool,

    /// Path to assets including web server files.
    #[structopt(long = "assets")]
    pub web_path: Option<PathBuf>,

    /// Path to API specification and messages.
    #[structopt(long = "api")]
    pub api_path: Option<PathBuf>,

    #[structopt(long, env = "ESPRESSO_VALIDATOR_PORT", default_value = "5000")]
    pub web_server_port: u16,
}

impl Default for NodeOpt {
    fn default() -> Self {
        Self::from_iter(std::iter::empty::<String>())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub ip: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub seed: [u8; 32],
    pub nodes: Vec<NodeConfig>,
}

impl ConsensusConfig {
    pub fn from_file(path: &Path) -> Self {
        // Read node info from node configuration file
        let mut config_file = File::open(&path)
            .unwrap_or_else(|_| panic!("Cannot find node config file: {}", path.display()));
        let mut config_str = String::new();
        config_file
            .read_to_string(&mut config_str)
            .unwrap_or_else(|err| panic!("Error while reading node config file: {}", err));
        toml::from_str(&config_str).expect("Error while reading node config file")
    }
}

/// Returns the project directory.
pub fn project_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns "<project>/public/".
fn default_web_path() -> PathBuf {
    const ASSET_DIR: &str = "public";
    let dir = project_path();
    [&dir, Path::new(ASSET_DIR)].iter().collect()
}

/// Returns the default directory to store persistence files.
fn default_store_path(node_id: u64) -> PathBuf {
    const STORE_DIR: &str = "store";
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

/// Gets the directory to public key files.
fn get_store_dir(options: &NodeOpt, node_id: u64) -> PathBuf {
    options
        .store_path
        .clone()
        .unwrap_or_else(|| default_store_path(node_id))
}

/// Gets IP address and port number of a node from node configuration file.
fn get_host(node: &NodeConfig) -> (String, u16) {
    let ip = node.ip.clone();
    let port = node.port;
    (ip, port)
}

/// Trys to get a networking implementation with the given id and port number.
///
/// Also starts the background task.
async fn get_networking<
    T: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug + 'static,
>(
    pub_key: PubKey,
    listen_addr: &str,
    port: u16,
) -> WNetwork<T> {
    debug!(?pub_key);
    let network = WNetwork::new(pub_key, listen_addr, port, None).await;
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
        return n;
    }
    panic!("Failed to open a port");
}

type PLNetwork = WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, ValidatorState, H_256>>;
type PLStorage = AtomicStorage<ElaboratedBlock, ValidatorState, H_256>;
type LWNode = node::LightWeightNode<PLNetwork, PLStorage>;
type FullNode<'a> = node::FullNode<'a, PLNetwork, PLStorage>;

#[derive(Clone)]
pub enum Node {
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

#[derive(Clone, Debug)]
pub struct GenesisState {
    pub validator: ValidatorState,
    pub records: MerkleTree,
    pub nullifiers: SetMerkleTree,
    pub memos: Vec<(ReceiverMemo, u64)>,
}

impl GenesisState {
    pub fn new(faucet_pub_keys: impl IntoIterator<Item = UserPubKey>) -> Self {
        let mut rng = ChaChaRng::from_seed(GENESIS_SEED);
        let mut records = FilledMTBuilder::new(MERKLE_HEIGHT).unwrap();
        let mut memos = Vec::new();

        // Process the initial native token records for the faucet.
        for (i, pub_key) in faucet_pub_keys.into_iter().enumerate() {
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
        Self {
            validator,
            records,
            nullifiers,
            memos,
        }
    }

    pub fn new_for_test() -> (Self, MultiXfrTestState) {
        let state = MultiXfrTestState::initialize(
            GENESIS_SEED,
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
        .unwrap();

        let validator = state.validator.clone();
        let records = state.record_merkle_tree.clone();
        let nullifiers = state.nullifiers.clone();
        let memos = state.unspent_memos();
        (
            Self {
                validator,
                records,
                nullifiers,
                memos,
            },
            state,
        )
    }
}

/// Creates the initial state and phaselock for simulation.
#[allow(clippy::too_many_arguments)]
async fn init_phaselock(
    options: &NodeOpt,
    public_keys: tc::PublicKeySet,
    secret_key_share: tc::SecretKeyShare,
    known_nodes: Vec<PubKey>,
    threshold: u64,
    node_id: u64,
    networking: WNetwork<Message<ElaboratedBlock, ElaboratedTransaction, ValidatorState, H_256>>,
    full_node: bool,
    load_from_store: bool,
    state: GenesisState,
) -> Node {
    // Create the initial phaselock
    let stake_table = known_nodes.iter().map(|key| (key.clone(), 1)).collect();
    let config = PhaseLockConfig {
        total_nodes: known_nodes.len() as u32,
        threshold: threshold as u32,
        max_transactions: 100,
        known_nodes,
        next_view_timeout: 10_000,
        timeout_ratio: (11, 10),
        round_start_delay: 1,
        start_delay: 1,
    };
    debug!(?config);
    let genesis = ElaboratedBlock::default();

    let lw_persistence =
        LWPersistence::new(Path::new(&get_store_dir(options, node_id)), "validator").unwrap();
    let stored_state = if load_from_store {
        lw_persistence
            .load_latest_state()
            .unwrap_or_else(|_| state.validator.clone())
    } else {
        state.validator.clone()
    };

    let univ_param = if full_node {
        Some(&*UNIVERSAL_PARAM)
    } else {
        None
    };

    let storage = get_store_dir(options, node_id);
    let phaselock_persistence = [Path::new(&storage), Path::new("phaselock")]
        .iter()
        .collect::<PathBuf>();
    let node_persistence = [Path::new(&storage), Path::new("node")]
        .iter()
        .collect::<PathBuf>();
    let phaselock = PhaseLock::init(
        genesis,
        public_keys,
        secret_key_share,
        node_id,
        config,
        state.validator,
        networking,
        AtomicStorage::open(&phaselock_persistence).unwrap(),
        lw_persistence,
        Committee::new(stake_table),
    )
    .await
    .unwrap();
    debug!("phaselock launched");

    let validator = if full_node {
        let full_persisted = FullPersistence::new(&node_persistence, "full_node").unwrap();

        let records = if load_from_store {
            let mut builder = FilledMTBuilder::new(MERKLE_HEIGHT).unwrap();
            for leaf in full_persisted.rmt_leaf_iter() {
                builder.push(leaf.unwrap().0);
            }
            builder.build()
        } else {
            state.records
        };
        let nullifiers = if load_from_store {
            full_persisted
                .get_latest_nullifier_set()
                .unwrap_or_else(|_| Default::default())
        } else {
            state.nullifiers
        };
        let node = FullNode::new(
            phaselock,
            univ_param.unwrap(),
            stored_state,
            records,
            nullifiers,
            state.memos,
            full_persisted,
        );
        Node::Full(Arc::new(RwLock::new(node)))
    } else {
        Node::Light(phaselock)
    };

    validator
}

#[derive(Clone)]
#[allow(dead_code)]
struct Connection {
    id: String,
    wsc: WebSocketConnection,
}

#[derive(Clone)]
pub struct WebState {
    #[allow(dead_code)]
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
                server_error(EspressoError::Param {
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

// TODO: factor this out
#[derive(Debug, Deserialize, Serialize)]
pub struct InsertPubKey {
    pub pub_key_bytes: Vec<u8>,
    pub sig: jf_cap::Signature,
}

/// Lookup a user public key from a signed public key address. Fail with
/// tide::StatusCode::BadRequest if key deserialization or the signature check
/// fail.
fn verify_sig_and_get_pub_key(insert_request: InsertPubKey) -> Result<UserPubKey, tide::Error> {
    let pub_key: UserPubKey = bincode::deserialize(&insert_request.pub_key_bytes)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    pub_key
        .verify_sig(&insert_request.pub_key_bytes, &insert_request.sig)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    Ok(pub_key)
}

async fn users_endpoint(mut req: tide::Request<WebState>) -> Result<tide::Response, tide::Error> {
    let insert_request: InsertPubKey = net::server::request_body(&mut req).await?;
    let pub_key = verify_sig_and_get_pub_key(insert_request)?;
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
            arg_doc.push_str("Argument parsing failed.\n");
        } else {
            arg_doc.push_str("No argument parsing errors!\n");
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
    #[allow(dead_code)] wsc: WebSocketConnection,
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
pub fn init_web_server(
    options: &NodeOpt,
    node: Arc<RwLock<FullNode<'static>>>,
) -> Result<task::JoinHandle<Result<(), std::io::Error>>, tide::Error> {
    // Take the command line option for the web asset directory path
    // provided it is not empty. Otherwise, construct the default from
    // the executable path.
    let web_path = options.web_path.clone().unwrap_or_else(default_web_path);
    let api_path = options.api_path.clone().unwrap_or_else(default_api_path);
    debug!("Web path: {:?}", web_path);
    let api = disco::load_messages(&api_path);
    let mut web_server = tide::with_state(WebState {
        connections: Default::default(),
        web_path: web_path.clone(),
        api: api.clone(),
        node,
    });
    web_server
        .with(server::trace)
        .with(server::add_error_body::<_, EspressoError>);

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

    let port = options.web_server_port;
    let addr = format!("0.0.0.0:{}", port);
    let join_handle = async_std::task::spawn(web_server.listen(addr));
    Ok(join_handle)
}

fn secret_keys(config: &ConsensusConfig) -> (u64, tc::SecretKeySet) {
    // Generate key sets
    let threshold = ((config.nodes.len() as u64 * 2) / 3) + 1;
    (
        threshold,
        tc::SecretKeySet::random(
            threshold as usize - 1,
            &mut ChaChaRng02::from_seed(config.seed),
        ),
    )
}

pub fn gen_pub_keys(config: &ConsensusConfig) -> Vec<PubKey> {
    let (_, secret_keys) = secret_keys(config);

    // Generate public key for each node
    config
        .nodes
        .iter()
        .enumerate()
        .map(|(node_id, _)| PubKey::from_secret_key_set_escape_hatch(&secret_keys, node_id as u64))
        .collect()
}

pub async fn init_validator(
    options: &NodeOpt,
    config: &ConsensusConfig,
    pub_keys: Vec<PubKey>,
    genesis: GenesisState,
    own_id: usize,
) -> Node {
    // TODO !nathan.yospe, jeb.bearer - add option to reload vs init
    let load_from_store = options.load_from_store;
    if load_from_store {
        debug!("restoring from persisted session");
    } else {
        debug!("initializing new session");
    }

    debug!("Current node: {}", own_id);
    let (threshold, secret_keys) = secret_keys(config);
    let secret_key_share = secret_keys.secret_key_share(own_id);

    // Get networking information
    let own_network = get_networking(
        pub_keys[own_id].clone(),
        "0.0.0.0",
        get_host(&config.nodes[own_id]).1,
    )
    .await;
    #[allow(clippy::type_complexity)]
    let mut other_nodes: Vec<(u64, &PubKey, String, u16)> = Vec::new();
    for (id, node) in config.nodes.iter().enumerate() {
        if id != own_id {
            let (ip, port) = get_host(node);
            other_nodes.push((id as u64, &pub_keys[id], ip, port));
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
        debug!("  - Connected to node {}", id);
    }

    // Wait for the networking implementations to connect
    while own_network.connection_table_size().await < config.nodes.len() - 1 {
        async_std::task::sleep(std::time::Duration::from_millis(10)).await;
    }
    debug!("All nodes connected to network");

    // Initialize the state and phaselock
    init_phaselock(
        options,
        secret_keys.public_keys(),
        secret_key_share,
        pub_keys,
        threshold,
        own_id as u64,
        own_network,
        options.full,
        load_from_store,
        genesis,
    )
    .await
}
