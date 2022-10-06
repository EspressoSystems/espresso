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

use ark_serialize::*;
use ark_std::rand::{CryptoRng, RngCore};
use async_std::sync::{Arc, RwLock};
use clap::{Args, Parser};
use cld::ClDuration;
use dirs::data_local_dir;
use espresso_core::reward::{mock_eligibility, CollectRewardNote};
use espresso_core::state::{EspressoTransaction, EspressoTxnHelperProofs, KVMerkleProof};
use espresso_core::{
    committee::Committee,
    genesis::GenesisNote,
    stake_table::{StakeTableHash, StakingPrivKey},
    state::{
        ChainVariables, ElaboratedBlock, ElaboratedTransaction, LWPersistence, NullifierHistory,
        SetMerkleTree, ValidatorState,
    },
    testing::{MultiXfrRecordSpec, MultiXfrTestState},
    universal_params::VERIF_CRS,
    PrivKey, PubKey,
};
use espresso_esqs::full_node_data_source::QueryData;
use futures::{select, Future, FutureExt};
use hotshot::traits::implementations::Libp2pNetwork;
use hotshot::traits::NetworkError;
use hotshot::types::ed25519::{Ed25519Priv, Ed25519Pub};
use hotshot::types::EventType;
use hotshot::{
    traits::implementations::AtomicStorage,
    types::{HotShotHandle, Message, SignatureKey},
    HotShot, HotShotConfig, H_256,
};
use jf_cap::keys::UserAddress;
use jf_cap::{
    keys::UserPubKey,
    structs::{Amount, AssetDefinition, FreezeFlag, RecordOpening},
};
use jf_utils::tagged_blob;
use libp2p::identity::ed25519::SecretKey;
use libp2p::identity::Keypair;
use libp2p::{multiaddr, Multiaddr, PeerId};
use libp2p_networking::network::{MeshParams, NetworkNodeConfigBuilder, NetworkNodeType};
use node_impl::ValidatorNodeImpl;
use rand_chacha::{rand_core::SeedableRng as _, ChaChaRng};
use snafu::Snafu;
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
use tracing::{debug, event, Level};

mod node_impl;
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
    #[arg(long, short)]
    pub reset_store_state: bool,

    /// Path to persistence files for all nodes.
    ///
    /// Persistence files will be nested under the specified directory.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_STORE_PATH")]
    pub store_path: Option<PathBuf>,

    /// Port of the current node if it's non-bootstrap.
    ///
    /// Overrides `nonbootstrap_base_port`.
    ///
    /// If the node is bootstrap, thip option will be overriden by the corresponding port in
    /// `--bootstrap-nodes`.
    #[arg(long, env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_PORT")]
    pub nonbootstrap_port: Option<u16>,

    /// The base port for the non-bootstrap nodes.
    ///
    /// If specified, the consesnsu port for node `i` will be `nonbootstrap_base_port + i`.
    ///
    /// Will be overriden by `nonbootstrap_port`.
    #[arg(long, default_value = "9000")]
    pub nonbootstrap_base_port: usize,

    /// Minimum time to wait for submitted transactions before proposing a block.
    ///
    /// Increasing this trades off latency for throughput: the rate of new block proposals gets
    /// slower, but each block is proportionally larger. Because of batch verification, larger
    /// blocks should lead to increased throughput.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME",
        default_value = "0s",
        value_parser = parse_duration
    )]
    pub min_propose_time: Duration,

    /// Maximum time to wait for submitted transactions before proposing a block.
    ///
    /// If a validator has not received any transactions after `min-propose-time`, it will wait up
    /// to `max-propose-time` before giving up and submitting an empty block.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME",
        default_value = "10s",
        value_parser = parse_duration
    )]
    pub max_propose_time: Duration,

    /// Base duration for next-view timeout.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NEXT_VIEW_TIMEOUT",
        default_value = "100s",
        value_parser = parse_duration
    )]
    pub next_view_timeout: Duration,

    /// The exponential backoff ratio for the next-view timeout.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_TIMEOUT_RATIO",
        default_value = "11:10"
    )]
    pub timeout_ratio: Ratio,

    /// The delay a leader inserts before starting pre-commit.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_ROUND_START_DELAY",
        default_value = "1ms",
        value_parser = parse_duration
    )]
    pub round_start_delay: Duration,

    /// Delay after init before starting consensus.
    #[arg(long, env = "ESPRESSO_VALIDATOR_START_DELAY", default_value = "1ms",
        value_parser = parse_duration)]
    pub start_delay: Duration,

    /// Maximum number of transactions in a block.
    #[arg(
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
    #[arg(long, env = "ESPRESSO_VALIDATOR_SECRET_KEY_SEED")]
    pub secret_key_seed: Option<SecretKeySeed>,

    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_REPLICATION_FACTOR",
        default_value = "5"
    )]
    pub replication_factor: usize,

    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_HIGH",
        default_value = "50"
    )]
    pub bootstrap_mesh_n_high: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_LOW",
        default_value = "10"
    )]
    pub bootstrap_mesh_n_low: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_OUTBOUND_MIN",
        default_value = "5"
    )]
    pub bootstrap_mesh_outbound_min: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N",
        default_value = "15"
    )]
    pub bootstrap_mesh_n: usize,

    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_HIGH",
        default_value = "15"
    )]
    pub nonbootstrap_mesh_n_high: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_LOW",
        default_value = "8"
    )]
    pub nonbootstrap_mesh_n_low: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_OUTBOUND_MIN",
        default_value = "4"
    )]
    pub nonbootstrap_mesh_outbound_min: usize,
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N",
        default_value = "12"
    )]
    pub nonbootstrap_mesh_n: usize,

    /// URLs of the bootstrap nodes, in the format of `<host>:<port>`.
    #[arg(
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

/// Returns the default directory to store persistence files.
fn default_store_path(node_id: usize) -> PathBuf {
    let mut data_dir = data_local_dir()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("./")));
    data_dir.push("espresso");
    data_dir.push("validator");
    data_dir.push(format!("node{}", node_id));
    data_dir
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

type PLStorage = AtomicStorage<ElaboratedBlock, ValidatorState, H_256>;
pub type Consensus = HotShotHandle<ValidatorNodeImpl<PLNetwork, PLStorage>, H_256>;

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

pub async fn run_consensus<F: Send + Future>(mut consensus: Consensus, kill: F) {
    consensus.start().await;
    let mut kill = kill.boxed().fuse();
    loop {
        let mut event_future = consensus.next_event().boxed().fuse();
        select! {
            _ = kill => {
                tracing::debug!("Validator killed");
                return;
            }
            event = event_future => {
                match event {
                    Ok(event) => match event.event {
                        EventType::Decide { state, block: _, qcs: _ } => {
                            if let Some(state) = state.last() {
                                tracing::debug!(". - Committed state {}", state.commit());
                            }
                        }
                        EventType::ViewTimeout { view_number } => {
                            tracing::debug!("  - Round {:?} timed out.", view_number);
                        }
                        EventType::Error { error } => {
                            tracing::error!("  - HotShot error: {}", error);
                        }
                        event => {
                            tracing::debug!("EVENT: {:?}", event);
                        }
                    }
                    Err(error) => {
                        tracing::error!("  - HotShot error while getting event: {}", error);
                    }
                }
            }
        }
    }
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
        QueryData::new(&storage, Box::new(consensus)).unwrap()
    } else {
        QueryData::load(&storage, Box::new(consensus)).unwrap()
    }))
}

#[allow(dead_code)] // FIXME use this function in main
async fn collect_reward_daemon<R: CryptoRng + RngCore>(
    rng: &mut R,
    stake_proof: KVMerkleProof<StakeTableHash>,
    stake_amount: Amount,
    staking_priv_key: &StakingPrivKey,
    cap_address: &UserAddress,
    mut hotshot: Consensus,
) {
    loop {
        let event = hotshot
            .next_event()
            .await
            .expect("HotShot unexpectedly closed");
        if let EventType::Decide {
            block: _,
            state,
            qcs,
        } = event.event
        {
            for (validator_state, qc) in state.iter().rev().zip(qcs.iter().rev()) {
                let view_number = qc.view_number;
                // 0. check if I'm elected
                if let Some(vrf_proof) =
                    mock_eligibility::prove_eligibility(view_number.into(), staking_priv_key)
                {
                    // 1. generate collect reward transaction
                    let (note, proof) = CollectRewardNote::generate(
                        rng,
                        validator_state,
                        view_number,
                        validator_state.block_height,
                        staking_priv_key,
                        cap_address.clone(),
                        stake_amount,
                        stake_proof.clone(),
                        vrf_proof,
                    )
                    .expect("Failed to create Collect Reward Note");
                    let elaborated_tx = ElaboratedTransaction {
                        txn: EspressoTransaction::Reward(Box::new(note)),
                        proofs: EspressoTxnHelperProofs::Reward(Box::new(proof)),
                        memos: None,
                    };

                    // 2. submit transaction
                    hotshot
                        .submit_transaction(elaborated_tx)
                        .await
                        .expect("Failed to submit reward transaction")

                    // 3. Check block if contain stake transfer transaction and update stake proof
                    // TODO we haven't implemented stake transfer yet
                }
            }
        }
    }
}
