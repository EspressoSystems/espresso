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

#![deny(warnings)]
#![allow(clippy::format_push_string)]

use crate::full_node_data_source::QueryData;
use crate::routes::{
    dispatch_url, dispatch_web_socket, server_error, RouteBinding, UrlSegmentType, UrlSegmentValue,
};
use ark_serialize::*;
use async_std::sync::{Arc, RwLock};
use async_std::task;
use async_trait::async_trait;
use clap::{Args, Parser};
use cld::ClDuration;
use dirs::data_local_dir;
use espresso_core::{
    committee::Committee,
    genesis::GenesisNote,
    state::{
        ChainVariables, ElaboratedBlock, ElaboratedTransaction, LWPersistence, NullifierHistory,
        SetMerkleTree, ValidatorState,
    },
    testing::{MultiXfrRecordSpec, MultiXfrTestState},
    universal_params::VERIF_CRS,
    PrivKey, PubKey,
};
use hotshot::traits::implementations::Libp2pNetwork;
use hotshot::traits::NetworkError;
use hotshot::types::ed25519::{Ed25519Priv, Ed25519Pub};
use hotshot::{
    traits::implementations::AtomicStorage,
    types::{HotShotHandle, Message, SignatureKey},
    HotShot, HotShotConfig, HotShotError, H_256,
};
use jf_cap::structs::{Amount, AssetDefinition, FreezeFlag, RecordOpening};
use jf_utils::tagged_blob;
use libp2p::identity::ed25519::SecretKey;
use libp2p::identity::Keypair;
use libp2p::{multiaddr, Multiaddr, PeerId};
use libp2p_networking::network::{MeshParams, NetworkNodeConfigBuilder, NetworkNodeType};
use rand_chacha::{rand_core::SeedableRng as _, ChaChaRng};
use server::request_body;
use snafu::Snafu;
use std::collections::hash_map::HashMap;
use std::collections::HashSet;
use std::env;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::num::{NonZeroUsize, ParseIntError};
use std::path::{Path, PathBuf};
use std::str;
use std::str::FromStr;
use std::time::Duration;
use surf::Url;
use tide::StatusCode;
use tide_websockets::{WebSocket, WebSocketConnection};
use tracing::{debug, event, Level};
use validator_node::update_query_data_source::UpdateQueryDataSourceTypes;
use validator_node::{
    api::EspressoError,
    api::{server, UserPubKey},
    node,
    node::{EventStream, HotShotEvent, Validator},
    validator_node::ValidatorNodeImpl,
};

mod disco;
pub mod full_node_data_source;
pub mod full_node_esqs;
mod ip;
mod routes;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub const MINIMUM_NODES: usize = 6;

const GENESIS_SEED: [u8; 32] = [0x7au8; 32];
const DEFAULT_SECRET_KEY_SEED: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Parse a (url|ip):[0-9]+ into a multiaddr
pub fn parse_url(s: &str) -> Result<Multiaddr, multiaddr::Error> {
    let (ip, port) = s
        .split_once(':')
        .ok_or(multiaddr::Error::InvalidMultiaddr)?;
    if ip.chars().any(|c| c.is_alphabetic()) {
        // special case localhost
        if ip == "localhost" {
            Multiaddr::from_str(&format!("/ip4/{}/tcp/{}", "127.0.0.1", port))
        } else {
            // is domain
            Multiaddr::from_str(&format!("/dns/{}/tcp/{}", ip, port))
        }
    } else {
        // is ip address
        Multiaddr::from_str(&format!("/ip4/{}/tcp/{}", ip, port))
    }
}

type PLNetwork = Libp2pNetwork<
    Message<ElaboratedBlock, ElaboratedTransaction, ValidatorState, Ed25519Pub, H_256>,
    Ed25519Pub,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ratio {
    pub numerator: u64,
    pub denominator: u64,
}

impl From<Ratio> for (u64, u64) {
    fn from(r: Ratio) -> Self {
        (r.numerator, r.denominator)
    }
}

impl Display for Ratio {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.numerator, self.denominator)
    }
}

#[derive(Debug, Snafu)]
pub enum ParseRatioError {
    #[snafu(display("numerator and denominator must be separated by :"))]
    MissingDelimiter,
    InvalidNumerator {
        err: ParseIntError,
    },
    InvalidDenominator {
        err: ParseIntError,
    },
}

impl FromStr for Ratio {
    type Err = ParseRatioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (num, den) = s.split_once(':').ok_or(ParseRatioError::MissingDelimiter)?;
        Ok(Self {
            numerator: num
                .parse()
                .map_err(|err| ParseRatioError::InvalidNumerator { err })?,
            denominator: den
                .parse()
                .map_err(|err| ParseRatioError::InvalidDenominator { err })?,
        })
    }
}

#[derive(Debug, Parser)]
pub struct NodeOpt {
    /// Whether to reset the persisted state.
    ///
    /// If the path to a node's persistence files doesn't exist, its persisted state will be reset
    /// regardless of this argument.
    #[clap(long, short)]
    pub reset_store_state: bool,

    /// Path to persistence files for all nodes.
    ///
    /// Persistence files will be nested under the specified directory.
    #[clap(long, short, env = "ESPRESSO_VALIDATOR_STORE_PATH")]
    pub store_path: Option<PathBuf>,

    /// Whether the current node should run a full node.
    #[clap(long, short)]
    pub full: bool,

    /// Path to assets including web server files.
    #[clap(long = "assets", env = "ESPRESSO_VALIDATOR_WEB_PATH")]
    pub web_path: Option<PathBuf>,

    /// Path to API specification and messages.
    #[clap(long = "api", env = "ESPRESSO_VALIDATOR_API_PATH")]
    pub api_path: Option<PathBuf>,

    /// Port for the query service.
    #[clap(long, env = "ESPRESSO_VALIDATOR_QUERY_PORT", default_value = "5000")]
    pub web_server_port: u16,

    /// Port of the current node if it's non-bootstrap.
    ///
    /// Overrides `nonbootstrap_base_port`.
    ///
    /// If the node is bootstrap, thip option will be overriden by the corresponding port in
    /// `--bootstrap-nodes`.
    #[clap(long, env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_PORT")]
    pub nonbootstrap_port: Option<u16>,

    /// The base port for the non-bootstrap nodes.
    ///
    /// If specified, the consesnsu port for node `i` will be `nonbootstrap_base_port + i`.
    ///
    /// Will be overriden by `nonbootstrap_port`.
    #[clap(long, default_value = "9000")]
    pub nonbootstrap_base_port: usize,

    /// Minimum time to wait for submitted transactions before proposing a block.
    ///
    /// Increasing this trades off latency for throughput: the rate of new block proposals gets
    /// slower, but each block is proportionally larger. Because of batch verification, larger
    /// blocks should lead to increased throughput.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME",
        default_value = "0s",
        parse(try_from_str = parse_duration)
    )]
    pub min_propose_time: Duration,

    /// Maximum time to wait for submitted transactions before proposing a block.
    ///
    /// If a validator has not received any transactions after `min-propose-time`, it will wait up
    /// to `max-propose-time` before giving up and submitting an empty block.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME",
        default_value = "10s",
        parse(try_from_str = parse_duration)
    )]
    pub max_propose_time: Duration,

    /// Base duration for next-view timeout.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_NEXT_VIEW_TIMEOUT",
        default_value = "100s",
        parse(try_from_str = parse_duration)
    )]
    pub next_view_timeout: Duration,

    /// The exponential backoff ratio for the next-view timeout.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_TIMEOUT_RATIO",
        default_value = "11:10"
    )]
    pub timeout_ratio: Ratio,

    /// The delay a leader inserts before starting pre-commit.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_ROUND_START_DELAY",
        default_value = "1ms",
        parse(try_from_str = parse_duration)
    )]
    pub round_start_delay: Duration,

    /// Delay after init before starting consensus.
    #[clap(long, env = "ESPRESSO_VALIDATOR_START_DELAY", default_value = "1ms",
        parse(try_from_str = parse_duration))]
    pub start_delay: Duration,

    /// Maximum number of transactions in a block.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_MAX_TRANSACTIONS",
        default_value = "10000"
    )]
    pub max_transactions: NonZeroUsize,
}

#[derive(Clone, Debug, Snafu)]
pub struct ParseDurationError {
    reason: String,
}

/// Parse a [Duration] from a string using [ClDuration], converting to a [Snafu] error.
pub fn parse_duration(s: &str) -> Result<Duration, ParseDurationError> {
    ClDuration::from_str(s)
        .map(Duration::from)
        .map_err(|err| ParseDurationError {
            reason: err.to_string(),
        })
}

impl Default for NodeOpt {
    fn default() -> Self {
        Self::parse_from(std::iter::empty::<String>())
    }
}

impl NodeOpt {
    pub fn check(&self) -> Result<(), String> {
        if self.max_propose_time < self.min_propose_time {
            return Err("max propose time must not be less than min propose time".into());
        }
        if self.max_propose_time.is_zero() {
            return Err("max propose time must be non-zero".into());
        }
        if self.next_view_timeout <= self.max_propose_time {
            return Err("next view timeout must be greater than max propose time".into());
        }
        if self.next_view_timeout <= self.round_start_delay {
            return Err("next view timeout must be greater than round start delay".into());
        }
        Ok(())
    }
}

#[tagged_blob("SEED")]
#[derive(Clone, Copy, Debug)]
pub struct SecretKeySeed(pub [u8; 32]);

impl CanonicalSerialize for SecretKeySeed {
    fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        w.write_all(&self.0)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.0.len()
    }
}

impl CanonicalDeserialize for SecretKeySeed {
    fn deserialize<R: Read>(mut r: R) -> Result<Self, SerializationError> {
        let mut bytes = [0; 32];
        r.read_exact(&mut bytes)?;
        Ok(bytes.into())
    }
}

impl From<[u8; 32]> for SecretKeySeed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<SecretKeySeed> for [u8; 32] {
    fn from(seed: SecretKeySeed) -> [u8; 32] {
        seed.0
    }
}

/// Options for the validator connections during the consensus.
///
/// All validators should have the same consensus options.
///
/// The default values of `replication_factor` and mesh parameters for bootstrap and non-bootstrap
/// nodes are set arbitrarily. They should increase as the number of nodes increases, and must meet
/// the following requirements.
/// 1. `mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high`.
/// 2. `mesh_outbound_min <= mesh_n / 2`.
#[derive(Clone, Debug, Args)]
pub struct ConsensusOpt {
    /// Seed number used to generate secret key set for all nodes.
    #[clap(long, env = "ESPRESSO_VALIDATOR_SECRET_KEY_SEED")]
    pub secret_key_seed: Option<SecretKeySeed>,

    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_REPLICATION_FACTOR",
        default_value = "5"
    )]
    pub replication_factor: usize,

    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_HIGH",
        default_value = "50"
    )]
    pub bootstrap_mesh_n_high: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_LOW",
        default_value = "10"
    )]
    pub bootstrap_mesh_n_low: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_OUTBOUND_MIN",
        default_value = "5"
    )]
    pub bootstrap_mesh_outbound_min: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N",
        default_value = "15"
    )]
    pub bootstrap_mesh_n: usize,

    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_HIGH",
        default_value = "15"
    )]
    pub nonbootstrap_mesh_n_high: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_LOW",
        default_value = "8"
    )]
    pub nonbootstrap_mesh_n_low: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_OUTBOUND_MIN",
        default_value = "4"
    )]
    pub nonbootstrap_mesh_outbound_min: usize,
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N",
        default_value = "12"
    )]
    pub nonbootstrap_mesh_n: usize,

    /// URLs of the bootstrap nodes, in the format of `<host>:<port>`.
    #[clap(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_NODES",
        default_value = "localhost:9000,localhost:9001,localhost:9002,localhost:9003,localhost:9004,localhost:9005,localhost:9006",
        value_delimiter = ','
    )]
    pub bootstrap_nodes: Vec<Url>,
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
fn default_store_path(node_id: usize) -> PathBuf {
    let mut data_dir = data_local_dir()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("./")));
    data_dir.push("espresso");
    data_dir.push("validator");
    data_dir.push(format!("node{}", node_id));
    data_dir
}

/// Returns the default path to the API file.
fn default_api_path() -> PathBuf {
    const API_FILE: &str = "api/api.toml";
    let dir = project_path();
    [&dir, Path::new(API_FILE)].iter().collect()
}

/// Gets the directory to persistence files.
///
/// The returned path can be passed to `reset_store_dir` to remove the contents, if the
/// `--reset-store-state` argument is true.
fn get_store_dir(options: &NodeOpt, node_id: usize) -> PathBuf {
    options
        .store_path
        .clone()
        .unwrap_or_else(|| default_store_path(node_id))
}

fn get_secret_key_seed(consensus_opt: &ConsensusOpt) -> [u8; 32] {
    consensus_opt
        .secret_key_seed
        .unwrap_or(SecretKeySeed(DEFAULT_SECRET_KEY_SEED))
        .into()
}

pub struct UpdateQueryDataSourceTypesBinder;

impl UpdateQueryDataSourceTypes for UpdateQueryDataSourceTypesBinder {
    type CU = QueryData;
    type AV = QueryData;
    type MS = QueryData;
    type ST = QueryData;
    type EH = QueryData;
}

type PLStorage = AtomicStorage<ElaboratedBlock, ValidatorState, H_256>;
pub type Consensus = HotShotHandle<ValidatorNodeImpl<PLNetwork, PLStorage>, H_256>;
type LWNode = node::LightWeightNode<PLNetwork, PLStorage>;
type FullNode<'a> = node::FullNode<'a, PLNetwork, PLStorage, UpdateQueryDataSourceTypesBinder>;

#[derive(Clone)]
pub enum Node {
    Light(LWNode),
    Full(Arc<RwLock<FullNode<'static>>>),
}

#[async_trait]
impl Validator for Node {
    type Event = HotShotEvent;

    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), HotShotError> {
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

    async fn current_state(&self) -> Result<Option<ValidatorState>, HotShotError> {
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

pub fn genesis(
    chain_id: u16,
    faucet_pub_keys: impl IntoIterator<Item = UserPubKey>,
) -> GenesisNote {
    let mut rng = ChaChaRng::from_seed(GENESIS_SEED);

    // Process the initial native token records for the faucet.
    let faucet_records = faucet_pub_keys
        .into_iter()
        .map(|pub_key| {
            // Create the initial grant.
            event!(
                Level::INFO,
                "creating initial native token record for {}",
                pub_key.address()
            );
            RecordOpening::new(
                &mut rng,
                Amount::from(1u64 << 32),
                AssetDefinition::native(),
                pub_key,
                FreezeFlag::Unfrozen,
            )
        })
        .collect();
    GenesisNote::new(
        ChainVariables::new(chain_id, VERIF_CRS.clone()),
        Arc::new(faucet_records),
    )
}

pub fn genesis_for_test() -> (GenesisNote, MultiXfrTestState) {
    let mut state = MultiXfrTestState::initialize(
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

    // [GenesisNote] doesn't support a non-empty nullifiers set, so we clear the nullifiers set in
    // our test state. This effectively "unspends" the records which were used to set up the initial
    // state. This is fine for testing purposes.
    state.nullifiers = SetMerkleTree::default();
    state.validator.past_nullifiers = NullifierHistory::default();

    let genesis = GenesisNote::new(
        ChainVariables::new(42, VERIF_CRS.clone()),
        Arc::new(state.records().collect()),
    );
    (genesis, state)
}

/// Creates the initial state and hotshot for simulation.
#[allow(clippy::too_many_arguments)]
async fn init_hotshot(
    options: &NodeOpt,
    known_nodes: Vec<PubKey>,
    priv_key: PrivKey,
    threshold: u64,
    node_id: usize,
    networking: PLNetwork,
    genesis: GenesisNote,
    num_bootstrap: usize,
) -> Consensus {
    // Create the initial hotshot
    let stake_table = known_nodes.iter().map(|key| (key.clone(), 1)).collect();
    let pub_key = known_nodes[node_id].clone();
    let config = HotShotConfig {
        total_nodes: NonZeroUsize::new(known_nodes.len()).unwrap(),
        threshold: NonZeroUsize::new(threshold as usize).unwrap(),
        max_transactions: options.max_transactions,
        known_nodes,
        next_view_timeout: options.next_view_timeout.as_millis() as u64,
        timeout_ratio: options.timeout_ratio.into(),
        round_start_delay: options.round_start_delay.as_millis() as u64,
        start_delay: options.start_delay.as_millis() as u64,
        propose_min_round_time: options.min_propose_time,
        propose_max_round_time: options.max_propose_time,
        num_bootstrap,
    };
    debug!(?config);

    let storage = get_store_dir(options, node_id);
    let storage_path = Path::new(&storage);
    let lw_persistence = if options.reset_store_state {
        debug!("Initializing new session");
        LWPersistence::new(storage_path, "validator").unwrap()
    } else {
        debug!("Restoring from persisted session");
        LWPersistence::load(storage_path, "validator").unwrap()
    };
    let genesis = ElaboratedBlock::genesis(genesis);
    let state = lw_persistence.load_latest_state().unwrap_or_else(|_| {
        // HotShot does not currently support genesis nicely. It should take a genesis block and
        // apply it to the default state. However, it currently takes the genesis block _and_ the
        // resulting state. This means we must apply the genesis block to the default state
        // ourselves.
        let mut state = ValidatorState::default();
        state
            .validate_and_apply(0, genesis.block.clone(), genesis.proofs.clone())
            .unwrap();
        state
    });

    let hotshot_storage_path = [storage_path, Path::new("hotshot")]
        .iter()
        .collect::<PathBuf>();
    let hotshot_storage = if options.reset_store_state {
        AtomicStorage::create(&hotshot_storage_path).unwrap()
    } else {
        AtomicStorage::open(&hotshot_storage_path).unwrap()
    };

    let hotshot = HotShot::init(
        genesis.clone(),
        config.known_nodes.clone(),
        pub_key,
        priv_key,
        node_id as u64,
        config,
        state,
        networking,
        hotshot_storage,
        lw_persistence,
        Committee::new(stake_table),
    )
    .await
    .unwrap();

    debug!("Hotshot online!");
    hotshot
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

/// Generate a list of private and public keys for `consensus_opt.bootstrap_nodes.len()` bootstrap
/// keys, with a given `consensus_opt.seed` seed.
pub fn gen_bootstrap_keys(consensus_opt: &ConsensusOpt) -> Vec<KeyPair> {
    let mut keys = Vec::with_capacity(consensus_opt.bootstrap_nodes.len());

    for node_id in 0..consensus_opt.bootstrap_nodes.len() {
        let private = PrivKey::generated_from_seed_indexed(
            get_secret_key_seed(consensus_opt),
            node_id as u64,
        );
        let public = PubKey::from_private(&private);

        keys.push(KeyPair { public, private })
    }
    keys
}

/// Generate a list of private and public keys for the given number of nodes with a given
/// `consensus_opt.seed` seed.
pub fn gen_keys(consensus_opt: &ConsensusOpt, num_nodes: usize) -> Vec<KeyPair> {
    let mut keys = Vec::with_capacity(num_nodes);

    for node_id in 0..num_nodes {
        let private = PrivKey::generated_from_seed_indexed(
            get_secret_key_seed(consensus_opt),
            node_id as u64,
        );
        let public = PubKey::from_private(&private);

        keys.push(KeyPair { public, private })
    }
    keys
}

pub struct KeyPair {
    pub public: PubKey,
    pub private: PrivKey,
}

/// Create a new libp2p network.
#[allow(clippy::too_many_arguments)]
pub async fn new_libp2p_network(
    pubkey: Ed25519Pub,
    bs: Vec<(Option<PeerId>, Multiaddr)>,
    node_id: usize,
    node_type: NetworkNodeType,
    bound_addr: Multiaddr,
    identity: Option<Keypair>,
    consensus_opt: &ConsensusOpt,
) -> Result<PLNetwork, NetworkError> {
    let mut config_builder = NetworkNodeConfigBuilder::default();
    // NOTE we may need to change this as we scale
    config_builder.replication_factor(NonZeroUsize::new(consensus_opt.replication_factor).unwrap());
    // `to_connect_addrs` is an empty field that will be removed. We will pass `bs` into
    // `Libp2pNetwork::new` as the addresses to connect.
    config_builder.to_connect_addrs(HashSet::new());
    config_builder.node_type(node_type);
    config_builder.bound_addr(Some(bound_addr));

    if let Some(identity) = identity {
        config_builder.identity(identity);
    }

    let mesh_params = match node_type {
        NetworkNodeType::Bootstrap => MeshParams {
            mesh_n_high: consensus_opt.bootstrap_mesh_n_high,
            mesh_n_low: consensus_opt.bootstrap_mesh_n_low,
            mesh_outbound_min: consensus_opt.bootstrap_mesh_outbound_min,
            mesh_n: consensus_opt.bootstrap_mesh_n,
        },
        NetworkNodeType::Regular => MeshParams {
            mesh_n_high: consensus_opt.nonbootstrap_mesh_n_high,
            mesh_n_low: consensus_opt.nonbootstrap_mesh_n_low,
            mesh_outbound_min: consensus_opt.nonbootstrap_mesh_outbound_min,
            mesh_n: consensus_opt.nonbootstrap_mesh_n,
        },
        NetworkNodeType::Conductor => unreachable!(),
    };

    config_builder.mesh_params(Some(mesh_params));

    let config = config_builder.build().unwrap();

    Libp2pNetwork::new(
        config,
        pubkey,
        Arc::new(RwLock::new(bs)),
        consensus_opt.bootstrap_nodes.len(),
        node_id,
    )
    .await
}

pub async fn init_validator(
    node_opt: &NodeOpt,
    consensus_opt: &ConsensusOpt,
    priv_key: PrivKey,
    pub_keys: Vec<PubKey>,
    genesis: GenesisNote,
    own_id: usize,
) -> Consensus {
    debug!("Current node: {}", own_id);

    let num_bootstrap = consensus_opt.bootstrap_nodes.len();

    let mut bootstrap_nodes = vec![];
    for i in 0..num_bootstrap {
        let priv_key =
            Ed25519Priv::generated_from_seed_indexed(get_secret_key_seed(consensus_opt), i as u64);
        let libp2p_priv_key = SecretKey::from_bytes(&mut priv_key.to_bytes()[0..32]).unwrap();
        bootstrap_nodes.push(libp2p_priv_key);
    }

    let bootstrap_priv: Vec<_> = bootstrap_nodes
        .into_iter()
        .enumerate()
        .map(|(idx, kp)| {
            let multiaddr = parse_url(consensus_opt.bootstrap_nodes[idx].as_str()).unwrap();
            (libp2p::identity::Keypair::Ed25519(kp.into()), multiaddr)
        })
        .take(num_bootstrap)
        .collect();

    let to_connect_addrs: Vec<_> = bootstrap_priv
        .clone()
        .into_iter()
        .map(|(kp, ma)| (Some(PeerId::from_public_key(&kp.public())), ma))
        .collect();

    let (node_type, own_identity, port) = if own_id < num_bootstrap {
        (
            NetworkNodeType::Bootstrap,
            Some(bootstrap_priv[own_id].0.clone()),
            consensus_opt.bootstrap_nodes[own_id]
                .as_str()
                .split_once(':')
                .unwrap()
                .1
                .parse::<u16>()
                .unwrap(),
        )
    } else {
        (
            NetworkNodeType::Regular,
            None,
            match &node_opt.nonbootstrap_port {
                Some(port) => *port,
                None => (node_opt.nonbootstrap_base_port + own_id) as u16,
            },
        )
    };

    // hotshot requires this threshold to be at least 2/3rd of the nodes for safety guarantee reasons
    let threshold = ((pub_keys.len() as u64 * 2) / 3) + 1;

    let own_network = new_libp2p_network(
        pub_keys[own_id].clone(),
        to_connect_addrs,
        own_id,
        node_type,
        parse_url(&format!("0.0.0.0:{:?}", port)).unwrap(),
        own_identity,
        consensus_opt,
    )
    .await
    .unwrap();

    let known_nodes = pub_keys.clone();

    debug!("All nodes connected to network");

    // Initialize the state and hotshot
    init_hotshot(
        node_opt,
        known_nodes,
        priv_key,
        threshold,
        own_id,
        own_network,
        genesis,
        num_bootstrap,
    )
    .await
}

pub fn open_data_source(
    options: &NodeOpt,
    id: usize,
    consensus: Consensus,
) -> Arc<RwLock<QueryData>> {
    let storage = get_store_dir(options, id);
    Arc::new(RwLock::new(if options.reset_store_state {
        QueryData::new(&storage, consensus).unwrap()
    } else {
        QueryData::load(&storage, consensus).unwrap()
    }))
}
