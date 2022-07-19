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

use crate::full_node_mem_data_source::QueryData;
use crate::routes::{
    dispatch_url, dispatch_web_socket, server_error, RouteBinding, UrlSegmentType, UrlSegmentValue,
};
use ark_serialize::*;
use async_std::sync::{Arc, RwLock};
use async_std::task;
use async_trait::async_trait;
use dirs::data_local_dir;
use hotshot::traits::implementations::Libp2pNetwork;
use hotshot::traits::NetworkError;
use hotshot::types::ed25519::{Ed25519Priv, Ed25519Pub};
use hotshot::{
    traits::implementations::AtomicStorage,
    types::{Message, SignatureKey},
    HotShot, HotShotConfig, HotShotError, H_256,
};
use jf_cap::{
    structs::{Amount, AssetDefinition, FreezeFlag, ReceiverMemo, RecordCommitment, RecordOpening},
    MerkleTree, TransactionVerifyingKey,
};
use jf_primitives::merkle_tree::FilledMTBuilder;
use jf_utils::tagged_blob;
use key_set::{KeySet, VerifierKeySet};
use libp2p::identity::ed25519::SecretKey;
use libp2p::identity::Keypair;
use libp2p::{multiaddr, Multiaddr, PeerId};
use libp2p_networking::network::{MeshParams, NetworkNodeConfigBuilder, NetworkNodeType};
use rand_chacha::{rand_core::SeedableRng as _, ChaChaRng};
use serde::{Deserialize, Serialize};
use server::request_body;
use std::collections::hash_map::HashMap;
use std::collections::HashSet;
use std::env;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use std::{fs, fs::File};
use structopt::StructOpt;
use tide::{http::Url, StatusCode};
use tide_websockets::{WebSocket, WebSocketConnection};
use tracing::{debug, event, Level};
use validator_node::{
    api::EspressoError,
    api::{server, BlockId, PostMemos, TransactionId, UserPubKey},
    node,
    node::{EventStream, HotShotEvent, QueryService, Validator},
};
use zerok_lib::{
    committee::Committee,
    state::{
        ElaboratedBlock, ElaboratedTransaction, FullPersistence, LWPersistence, SetMerkleTree,
        ValidatorState, MERKLE_HEIGHT,
    },
    testing::{MultiXfrRecordSpec, MultiXfrTestState},
    universal_params::UNIVERSAL_PARAM,
};
use zerok_lib::{PrivKey, PubKey};

mod disco;
pub mod full_node_mem_data_source;
mod ip;
mod routes;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub const MINIMUM_NODES: usize = 5;

const GENESIS_SEED: [u8; 32] = [0x7au8; 32];

/// Parse a (url|ip):[0-9]+ into a multiaddr
pub fn parse_url(s: &str) -> Result<Multiaddr, multiaddr::Error> {
    let (ip, port) = s
        .split_once(':')
        .ok_or(multiaddr::Error::InvalidMultiaddr)?;
    if ip.chars().any(|c| c.is_alphabetic()) {
        // speecial case localhost
        if ip == "localhost" {
            Multiaddr::from_str(&format!("/dns/{}/tcp/{}", "127.0.0.1", port))
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

#[derive(Debug, StructOpt)]
pub struct NodeOpt {
    /// Whether to reset the persisted state.
    ///
    /// If the path to a node's persistence files doesn't exist, its persisted state will be reset
    /// regardless of this argument.
    #[structopt(long, short)]
    pub reset_store_state: bool,

    /// Path to persistence files for all nodes.
    ///
    /// Persistence files will be nested under the specified directory.
    #[structopt(long, short, env = "ESPRESSO_VALIDATOR_STORE_PATH")]
    pub store_path: Option<PathBuf>,

    /// Whether the current node should run a full node.
    #[structopt(long, short)]
    pub full: bool,

    /// Path to assets including web server files.
    #[structopt(long = "assets", env = "ESPRESSO_VALIDATOR_WEB_PATH")]
    pub web_path: Option<PathBuf>,

    /// Path to API specification and messages.
    #[structopt(long = "api", env = "ESPRESSO_VALIDATOR_API_PATH")]
    pub api_path: Option<PathBuf>,

    /// Port for the query service.
    #[structopt(long, env = "ESPRESSO_VALIDATOR_PORT", default_value = "5000")]
    pub web_server_port: u16,

    /// Minimum time (in seconds) to wait for submitted transactions before proposing a block.
    ///
    /// Increasing this trades off latency for throughput: the rate of new block proposals gets
    /// slower, but each block is proportionally larger. Because of batch verification, larger
    /// blocks should lead to increased throughput.
    #[structopt(
        long = "min-propose-time",
        env = "ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME",
        default_value = "1"
    )]
    pub min_propose_time_secs: u64,

    /// Maximum time (in seconds) to wait for submitted transactions before proposing a block.
    ///
    /// If a validator has not received any transactions after `min-propose-time`, it will wait up
    /// to `max-propose-time` before giving up and submitting an empty block.
    #[structopt(
        long = "max-propose-time",
        env = "ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME",
        default_value = "10"
    )]
    pub max_propose_time_secs: u64,
}

impl Default for NodeOpt {
    fn default() -> Self {
        Self::from_iter(std::iter::empty::<String>())
    }
}

impl NodeOpt {
    pub fn min_propose_time(&self) -> Duration {
        Duration::from_secs(self.min_propose_time_secs)
    }

    pub fn max_propose_time(&self) -> Duration {
        Duration::from_secs(self.max_propose_time_secs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub url: Url,
    pub host: String,
    pub port: u16,
}

impl From<Url> for NodeConfig {
    fn from(url: Url) -> Self {
        Self {
            port: url.port_or_known_default().unwrap(),
            host: url.host_str().unwrap().to_string(),
            url,
        }
    }
}

/// The structure of a NodeConfig in a consensus config TOML file.
///
/// This struct exists to be deserialized and converted to [NodeConfig].
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConsensusConfigFileNode {
    ip: String,
    port: u16,
}

impl From<ConsensusConfigFileNode> for NodeConfig {
    fn from(cfg: ConsensusConfigFileNode) -> Self {
        Url::parse(&format!("http://{}:{}", cfg.ip, cfg.port))
            .unwrap()
            .into()
    }
}

impl From<NodeConfig> for ConsensusConfigFileNode {
    fn from(cfg: NodeConfig) -> Self {
        Self {
            ip: cfg.host,
            port: cfg.port,
        }
    }
}

impl NodeConfig {
    pub fn socket_addr(&self) -> (&str, u16) {
        (&self.host, self.port)
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

/// The structure of a node-config.toml file.
///
/// This struct exists to be deserialized and converted to [ConsensusConfig].
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConsensusConfigFile {
    seed: [u8; 32],
    num_bootstrap: usize,
    replication_factor: usize,
    bootstrap_mesh_n_high: usize,
    bootstrap_mesh_n_low: usize,
    bootstrap_mesh_outbound_min: usize,
    bootstrap_mesh_n: usize,
    mesh_n_high: usize,
    mesh_n_low: usize,
    mesh_outbound_min: usize,
    mesh_n: usize,
    nodes: Vec<ConsensusConfigFileNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "ConsensusConfigFile", into = "ConsensusConfigFile")]
pub struct ConsensusConfig {
    pub seed: SecretKeySeed,
    pub num_bootstrap: usize,
    pub replication_factor: usize,
    pub bootstrap_mesh_n_high: usize,
    pub bootstrap_mesh_n_low: usize,
    pub bootstrap_mesh_outbound_min: usize,
    pub bootstrap_mesh_n: usize,
    pub mesh_n_high: usize,
    pub mesh_n_low: usize,
    pub mesh_outbound_min: usize,
    pub mesh_n: usize,
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

impl From<ConsensusConfigFile> for ConsensusConfig {
    fn from(cfg: ConsensusConfigFile) -> Self {
        Self {
            seed: cfg.seed.into(),
            num_bootstrap: cfg.num_bootstrap,
            nodes: cfg.nodes.into_iter().map(NodeConfig::from).collect(),
            replication_factor: cfg.replication_factor,
            bootstrap_mesh_n_high: cfg.bootstrap_mesh_n_high,
            bootstrap_mesh_n_low: cfg.bootstrap_mesh_n_low,
            bootstrap_mesh_outbound_min: cfg.bootstrap_mesh_outbound_min,
            bootstrap_mesh_n: cfg.bootstrap_mesh_n,
            mesh_n_high: cfg.mesh_n_high,
            mesh_n_low: cfg.mesh_n_low,
            mesh_outbound_min: cfg.mesh_outbound_min,
            mesh_n: cfg.mesh_n,
        }
    }
}

impl From<ConsensusConfig> for ConsensusConfigFile {
    fn from(cfg: ConsensusConfig) -> Self {
        Self {
            seed: cfg.seed.into(),
            num_bootstrap: cfg.num_bootstrap,
            nodes: cfg
                .nodes
                .into_iter()
                .map(ConsensusConfigFileNode::from)
                .collect(),
            replication_factor: cfg.replication_factor,
            bootstrap_mesh_n_high: cfg.bootstrap_mesh_n_high,
            bootstrap_mesh_n_low: cfg.bootstrap_mesh_n_low,
            bootstrap_mesh_outbound_min: cfg.bootstrap_mesh_outbound_min,
            bootstrap_mesh_n: cfg.bootstrap_mesh_n,
            mesh_n_high: cfg.mesh_n_high,
            mesh_n_low: cfg.mesh_n_low,
            mesh_outbound_min: cfg.mesh_outbound_min,
            mesh_n: cfg.mesh_n,
        }
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

/// Removes the contents in the persistence files.
fn reset_store_dir(store_dir: PathBuf) {
    let path = store_dir.as_path();
    fs::remove_dir_all(path).expect("Failed to remove persistence files");
}

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
                Amount::from(1u64 << 32),
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

/// Creates the initial state and hotshot for simulation.
#[allow(clippy::too_many_arguments)]
async fn init_hotshot(
    options: &NodeOpt,
    known_nodes: Vec<PubKey>,
    priv_key: PrivKey,
    threshold: u64,
    node_id: usize,
    networking: PLNetwork,
    full_node: bool,
    state: GenesisState,
    data_source: Arc<RwLock<QueryData>>,
    num_bootstrap: usize,
) -> Node {
    // Create the initial hotshot
    let stake_table = known_nodes.iter().map(|key| (key.clone(), 1)).collect();
    let pub_key = known_nodes[node_id].clone();
    let config = HotShotConfig {
        total_nodes: NonZeroUsize::new(known_nodes.len()).unwrap(),
        threshold: NonZeroUsize::new(threshold as usize).unwrap(),
        max_transactions: NonZeroUsize::new(100).unwrap(),
        known_nodes,
        next_view_timeout: 10_000,
        timeout_ratio: (11, 10),
        round_start_delay: 1,
        start_delay: 1,
        propose_min_round_time: options.min_propose_time(),
        propose_max_round_time: options.max_propose_time(),
        num_bootstrap,
    };
    debug!(?config);
    let genesis = ElaboratedBlock::default();

    let storage = get_store_dir(options, node_id);
    let storage_path = Path::new(&storage);
    let reset_store_state = if storage_path.exists() {
        if options.reset_store_state {
            reset_store_dir(storage.clone());
            true
        } else {
            false
        }
    } else {
        true
    };
    if reset_store_state {
        debug!("Initializing new session");
    } else {
        debug!("Restoring from persisted session");
    }
    let lw_persistence = LWPersistence::new(storage_path, "validator").unwrap();
    let stored_state = if reset_store_state {
        state.validator.clone()
    } else {
        lw_persistence
            .load_latest_state()
            .unwrap_or_else(|_| state.validator.clone())
    };

    let univ_param = if full_node {
        Some(&*UNIVERSAL_PARAM)
    } else {
        None
    };

    let hotshot_persistence = [storage_path, Path::new("hotshot")]
        .iter()
        .collect::<PathBuf>();
    let node_persistence = [storage_path, Path::new("node")]
        .iter()
        .collect::<PathBuf>();

    let hotshot = HotShot::init(
        genesis,
        config.known_nodes.clone(),
        pub_key,
        priv_key,
        node_id as u64,
        config,
        state.validator,
        networking,
        AtomicStorage::open(&hotshot_persistence).unwrap(),
        lw_persistence,
        Committee::new(stake_table),
    )
    .await
    .unwrap();

    debug!("Hotshot online!");

    let validator = if full_node {
        let full_persisted = FullPersistence::new(&node_persistence, "full_node").unwrap();

        let records = if reset_store_state {
            state.records
        } else {
            let mut builder = FilledMTBuilder::new(MERKLE_HEIGHT).unwrap();
            for leaf in full_persisted.rmt_leaf_iter() {
                builder.push(leaf.unwrap().0);
            }
            builder.build()
        };
        let nullifiers = if reset_store_state {
            state.nullifiers
        } else {
            full_persisted
                .get_latest_nullifier_set()
                .unwrap_or_else(|_| Default::default())
        };
        let node = FullNode::new(
            hotshot,
            univ_param.unwrap(),
            stored_state,
            records,
            nullifiers,
            state.memos,
            full_persisted,
            data_source.clone(),
            data_source.clone(),
            data_source.clone(),
        );
        Node::Full(Arc::new(RwLock::new(node)))
    } else {
        Node::Light(hotshot)
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

/// Generate a list of private and public keys for `config.nodes.len()` bootstrap keys, with a
/// given `config.seed` seed.
pub fn gen_bootstrap_keys(config: &ConsensusConfig) -> Vec<KeyPair> {
    let mut keys = Vec::with_capacity(config.nodes.len());

    for node_id in 0..config.nodes.len() {
        let private = PrivKey::generated_from_seed_indexed(config.seed.0, node_id as u64);
        let public = PubKey::from_private(&private);

        keys.push(KeyPair { public, private })
    }
    keys
}

/// Generate a list of private and public keys for the given number of nodes with a given `config.
/// seed` seed.
pub fn gen_keys(config: &ConsensusConfig, num_nodes: usize) -> Vec<KeyPair> {
    let mut keys = Vec::with_capacity(num_nodes);

    for node_id in 0..num_nodes {
        let private = PrivKey::generated_from_seed_indexed(config.seed.0, node_id as u64);
        let public = PubKey::from_private(&private);

        keys.push(KeyPair { public, private })
    }
    keys
}

pub struct KeyPair {
    pub public: PubKey,
    pub private: PrivKey,
}

/// Craate a new libp2p network.
#[allow(clippy::too_many_arguments)]
pub async fn new_libp2p_network(
    pubkey: Ed25519Pub,
    bs: Vec<(Option<PeerId>, Multiaddr)>,
    node_id: usize,
    node_type: NetworkNodeType,
    bound_addr: Multiaddr,
    identity: Option<Keypair>,
    consensus_config: &ConsensusConfig,
) -> Result<PLNetwork, NetworkError> {
    let mut config_builder = NetworkNodeConfigBuilder::default();
    // NOTE we may need to change this as we scale
    config_builder
        .replication_factor(NonZeroUsize::new(consensus_config.replication_factor).unwrap());
    config_builder.to_connect_addrs(HashSet::new());
    config_builder.node_type(node_type);
    config_builder.bound_addr(Some(bound_addr));

    if let Some(identity) = identity {
        config_builder.identity(identity);
    }

    let mesh_params = match node_type {
        NetworkNodeType::Bootstrap => MeshParams {
            mesh_n_high: consensus_config.bootstrap_mesh_n_high,
            mesh_n_low: consensus_config.bootstrap_mesh_n_low,
            mesh_outbound_min: consensus_config.bootstrap_mesh_outbound_min,
            mesh_n: consensus_config.bootstrap_mesh_n,
        },
        NetworkNodeType::Regular => MeshParams {
            mesh_n_high: consensus_config.mesh_n_high,
            mesh_n_low: consensus_config.mesh_n_low,
            mesh_outbound_min: consensus_config.mesh_outbound_min,
            mesh_n: consensus_config.mesh_n,
        },
        NetworkNodeType::Conductor => unreachable!(),
    };

    config_builder.mesh_params(Some(mesh_params));

    let config = config_builder.build().unwrap();

    Libp2pNetwork::new(
        config,
        pubkey,
        Arc::new(RwLock::new(bs)),
        consensus_config.num_bootstrap,
        node_id as usize,
    )
    .await
}

pub async fn init_validator(
    options: &NodeOpt,
    config: &ConsensusConfig,
    priv_key: PrivKey,
    pub_keys: Vec<PubKey>,
    genesis: GenesisState,
    own_id: usize,
    data_source: Arc<RwLock<QueryData>>,
) -> Node {
    debug!("Current node: {}", own_id);

    let num_bootstrap = config.num_bootstrap;

    let mut bootstrap_nodes = vec![];
    for i in 0..num_bootstrap {
        let priv_key = Ed25519Priv::generated_from_seed_indexed(config.seed.0, i as u64);
        let libp2p_priv_key = SecretKey::from_bytes(&mut priv_key.to_bytes()[0..32]).unwrap();
        bootstrap_nodes.push(libp2p_priv_key);
    }

    let bootstrap_priv: Vec<_> = bootstrap_nodes
        .into_iter()
        .enumerate()
        .map(|(idx, kp)| {
            let multiaddr = parse_url(&format!(
                "{}:{}",
                config.nodes[idx].host, config.nodes[idx].port
            ))
            .unwrap();
            (libp2p::identity::Keypair::Ed25519(kp.into()), multiaddr)
        })
        .take(num_bootstrap)
        .collect();

    let mut to_connect_addrs: Vec<_> = bootstrap_priv
        .clone()
        .into_iter()
        .map(|(kp, ma)| (Some(PeerId::from_public_key(&kp.public())), ma))
        .collect();

    let (node_type, own_identity) = if own_id < num_bootstrap {
        // TODO jr
        // <https://github.com/EspressoSystems/espresso/issues/463>
        // When we upgrade to phaselock 0.1.1,
        // we can delete this line. The reason is because
        // 0.1.0 HotShot is overly strict in matching the number of bootstrap nodes.
        // This is fixed on HotShot main
        to_connect_addrs.remove(own_id);
        (
            NetworkNodeType::Bootstrap,
            Some(bootstrap_priv[own_id].0.clone()),
        )
    } else {
        (NetworkNodeType::Regular, None)
    };

    // hotshot requires this threshold to be at least 2/3rd of the nodes for safety guarantee reasons
    let threshold = ((config.nodes.len() as u64 * 2) / 3) + 1;

    let own_network = new_libp2p_network(
        pub_keys[own_id].clone(),
        to_connect_addrs,
        own_id as usize,
        node_type,
        parse_url(&format!("0.0.0.0:{:?}", config.nodes[own_id].port)).unwrap(),
        own_identity,
        config,
    )
    .await
    .unwrap();

    let known_nodes = pub_keys.clone();

    debug!("All nodes connected to network");

    // Initialize the state and hotshot
    init_hotshot(
        options,
        known_nodes,
        priv_key,
        threshold,
        own_id,
        own_network,
        options.full,
        genesis,
        data_source,
        num_bootstrap,
    )
    .await
}
