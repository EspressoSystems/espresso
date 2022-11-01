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
use clap::Parser;
use cld::ClDuration;
use dirs::data_local_dir;
use espresso_core::reward::{
    mock_eligibility, CollectRewardNote, CollectedRewards, CollectedRewardsSet,
};
use espresso_core::stake_table::StakingKey;
use espresso_core::state::{EspressoTransaction, EspressoTxnHelperProofs, KVMerkleProof};
use espresso_core::{
    genesis::GenesisNote,
    stake_table::{StakeTableHash, StakingPrivKey},
    state::{
        ChainVariables, ElaboratedBlock, ElaboratedTransaction, LWPersistence, ValidatorState,
    },
    universal_params::VERIF_CRS,
};
use espresso_esqs::full_node::{self};
use espresso_esqs::full_node_data_source::QueryData;
use espresso_validator_api::data_source::ValidatorDataSource;
use futures::{select, Future, FutureExt};
use hotshot::types::{ed25519::Ed25519Priv, EventType};
use hotshot::{
    traits::{
        election::vrf::{VRFStakeTableConfig, VrfImpl, SORTITION_PARAMETER},
        implementations::MemoryStorage,
    },
    types::{HotShotHandle, SignatureKey as _},
    HotShot, HotShotInitializer,
};
use hotshot_types::{ExecutionType, HotShotConfig};
use jf_cap::{
    keys::{UserAddress, UserPubKey},
    structs::{Amount, AssetDefinition, FreezeFlag, RecordOpening},
};
use jf_utils::tagged_blob;
use libp2p::identity::ed25519::SecretKey;
use libp2p::{multiaddr, Multiaddr, PeerId};
use libp2p_networking::network::NetworkNodeType;
use node_impl::{SignatureKey, ValidatorNodeImpl};
use rand_chacha::{rand_core::SeedableRng as _, ChaChaRng};
use snafu::Snafu;
use static_assertions::const_assert;
use std::convert::TryInto;
use std::env;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::num::{NonZeroUsize, ParseIntError};
use std::path::{Path, PathBuf};
use std::str;
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, event, Level};
use url::Url;

mod network;
pub mod node_impl;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod validator;

#[macro_export]
macro_rules! div_ceil {
    ($num:expr, $den:expr) => {
        ($num + $den - 1) / $den
    };
}

pub const COMMITTEE_SIZE: u64 = SORTITION_PARAMETER;
// More than 2/3 of the expected committee size is required to reach quorum.
pub const QUORUM_THRESHOLD: u64 = 2 * COMMITTEE_SIZE / 3 + 1;
// For the fixed-stake testnet, we arbitrarily assign each node enough stake so that at least 4
// nodes are required for quorum.
pub const STAKE_PER_NODE: u64 = QUORUM_THRESHOLD / 4;

// We need enough nodes so that the total stake (i.e. `num_nodes * STAKE_PER_NODE`) is at least
// `COMMITTEE_SIZE`, so `num_nodes >= COMMITTEE_SIZE / STAKE_PER_NODE`.
pub const MINIMUM_NODES: usize = div_ceil!(COMMITTEE_SIZE, STAKE_PER_NODE) as usize;
pub const MINIMUM_BOOTSTRAP_NODES: usize = 5;
pub const GENESIS_SEED: [u8; 32] = [0x7au8; 32];
const DEFAULT_SECRET_KEY_SEED: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

const_assert!(QUORUM_THRESHOLD < COMMITTEE_SIZE);
const_assert!(MINIMUM_NODES as u64 * STAKE_PER_NODE >= COMMITTEE_SIZE);
const_assert!(MINIMUM_NODES >= MINIMUM_BOOTSTRAP_NODES);

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

/// Options for validator nodes, including node-specific options, consensus options, and other
/// options that are consistent among nodes.
#[derive(Parser)]
pub struct NodeOpt {
    //
    // 1. Node-specific options.
    //
    /// Id of the current node.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_ID")]
    pub id: usize,

    /// Location of the current node.
    ///
    /// If not provided, the IP address will be used for dashboard display.
    #[clap(long, env = "ESPRESSO_VALIDATOR_LOCATION")]
    pub location: Option<String>,

    /// Port of the current node if it's non-bootstrap.
    ///
    /// Overrides `nonbootstrap_base_port`.
    ///
    /// If the node is bootstrap, thip option will be overriden by the corresponding port in
    /// `--bootstrap-nodes`.
    #[arg(long, env = "ESPRESSO_VALIDATOR_NONBOOTSTRAP_PORT")]
    pub nonbootstrap_port: Option<u16>,

    /// Whether to reset the persisted state.
    ///
    /// If the path to a node's persistence files doesn't exist, its persisted state will be reset
    /// regardless of this argument.
    #[arg(long, short)]
    pub reset_store_state: bool,

    //
    // 2. Consensus options for all nodes.
    // The default values of `replication_factor` and mesh parameters for bootstrap and non-bootstrap
    // nodes are set arbitrarily. They should increase as the number of nodes increases, and must meet
    // the following requirements.
    // * `mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high`.
    // * `mesh_outbound_min <= mesh_n / 2`.
    //
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

    //
    // 3. Other options for all nodes.
    //
    /// Number of nodes, including a fixed number of bootstrap nodes and a dynamic number of non-
    /// bootstrap nodes.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_NUM_NODES")]
    pub num_nodes: usize,

    /// Path to persistence files for all nodes.
    ///
    /// Persistence files will be nested under the specified directory.
    #[arg(long, short, env = "ESPRESSO_VALIDATOR_STORE_PATH")]
    pub store_path: Option<PathBuf>,

    /// The base port for the non-bootstrap nodes.
    ///
    /// If specified, the consesnsu port for node `i` will be `nonbootstrap_base_port + i`.
    ///
    /// Will be overriden by `nonbootstrap_port`.
    #[arg(long, default_value = "9000")]
    pub nonbootstrap_base_port: usize,

    /// URL for a CDN server to use for optimistic communication.
    ///
    /// Note that the configuration provided by the CDN will override consensus-level configuration
    /// specified in these options.
    #[arg(long, env = "ESPRESSO_CDN_SERVER_URL")]
    pub cdn: Option<Url>,

    /// Use in conjunction with --cdn to use libp2p for consensus networking.
    ///
    /// The centralized server will still be used for orchestration (e.g. synchronizing startup), as
    /// opposed to the default configuration (with netiher --cdn nor --libp2p) where libp2p
    /// networking is used without any orchestration.
    #[arg(long, requires = "cdn", env = "ESPRESSO_VALIDATOR_LIBP2P")]
    pub libp2p: bool,

    /// Minimum time to wait for submitted transactions before proposing a block.
    ///
    /// Increasing this trades off latency for throughput: the rate of new block proposals gets
    /// slower, but each block is proportionally larger. Because of batch verification, larger
    /// blocks should lead to increased throughput.
    ///
    /// `min-propose-time` is set to 0s by default, since minimum block size can be controlled using
    /// `min-transactions`, which is a more intentional, declarative setting. You may still wish to
    /// set a non-zero `min-propose-time` to allow for larger blocks in higher volumes while setting
    /// `min-transactions` to something small to handle low-volume conditions.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME",
        default_value = "0s",
        value_parser = parse_duration
    )]
    pub min_propose_time: Duration,

    /// Maximum time to wait for submitted transactions before proposing a block.
    ///
    /// If a validator has not received `min-transactions` after `min-propose-time`, it will wait up
    /// to `max-propose-time` before giving up and submitting a block with whatever transactions it
    /// does have.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME",
        default_value = "30s",
        value_parser = parse_duration
    )]
    pub max_propose_time: Duration,

    /// Minimum number of transactions to include in a block, if possible.
    ///
    /// After `min-propose-time`, a leader will propose a block as soon as it has at least
    /// `min-transactions`. Note that a block with fewer than `min-transactions` may still be
    /// proposed, if `min-transactions` are not submitted before `max-propose-time`.
    ///
    /// The default is 1, because a non-zero value of `min-transactions` is required in order for
    /// `max-propose-time` to have any effect -- if `min-transactions = 0`, then an empty block will
    /// be proposed each view after `min-propose-time`. Setting `min-transactions` to 1 limits the
    /// number of empty blocks proposed while still allowing a block to be proposed as soon as any
    /// transaction has been received. In a setting where high volume is expected most of the time,
    /// you might set this greater than 1 to encourage larger blocks and better throughput, while
    /// setting `max-propose-time` very large to handle low-volume conditions without affecting
    /// latency in high-volume conditions.
    #[clap(long, env = "ESPRESSO_VALIDATOR_MIN_TRANSACTIONS", default_value = "1")]
    pub min_transactions: usize,

    /// Base duration for next-view timeout.
    #[arg(
        long,
        env = "ESPRESSO_VALIDATOR_NEXT_VIEW_TIMEOUT",
        default_value = "60s",
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

    /// Whether to color log output with ANSI color codes.
    #[arg(long, env = "ESPRESSO_COLORED_LOGS")]
    pub colored_logs: bool,

    /// Unique identifier for this instance of Espresso.
    #[arg(long, env = "ESPRESSO_VALIDATOR_CHAIN_ID", default_value = "0")]
    pub chain_id: u16,

    #[command(subcommand)]
    pub esqs: Option<full_node::Command>,
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
        if self.num_nodes < MINIMUM_NODES {
            return Err(format!(
                "number of nodes must not be less than {}",
                MINIMUM_NODES
            ));
        }
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
fn get_store_dir(node_opt: &NodeOpt) -> PathBuf {
    node_opt
        .store_path
        .clone()
        .unwrap_or_else(|| default_store_path(node_opt.id))
}

fn get_secret_key_seed(seed: Option<SecretKeySeed>) -> [u8; 32] {
    seed.unwrap_or(SecretKeySeed(DEFAULT_SECRET_KEY_SEED))
        .into()
}

type Network = network::HybridNetwork;
type Storage = MemoryStorage<ValidatorState>;
pub type Consensus = HotShotHandle<ValidatorNodeImpl<Network, Storage>>;

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

/// Creates the initial state and hotshot for simulation.
#[allow(clippy::too_many_arguments)]
async fn init_hotshot(
    node_opt: &NodeOpt,
    known_nodes: Vec<StakingKey>,
    priv_key: StakingPrivKey,
    networking: Network,
    genesis: GenesisNote,
) -> Consensus {
    // Create the initial hotshot
    let known_nodes = known_nodes
        .into_iter()
        .map(SignatureKey::from)
        .collect::<Vec<_>>();
    let stake_distribution = known_nodes
        .iter()
        .map(|_| STAKE_PER_NODE.try_into().unwrap())
        .collect::<Vec<_>>();
    let pub_key = known_nodes[node_opt.id].clone();
    let vrf_config = VRFStakeTableConfig {
        sortition_parameter: COMMITTEE_SIZE,
        distribution: stake_distribution,
    };
    let config = HotShotConfig {
        total_nodes: NonZeroUsize::new(known_nodes.len()).unwrap(),
        threshold: NonZeroUsize::new(QUORUM_THRESHOLD as usize).unwrap(),
        max_transactions: node_opt.max_transactions,
        known_nodes: known_nodes.clone(),
        next_view_timeout: node_opt.next_view_timeout.as_millis() as u64,
        timeout_ratio: node_opt.timeout_ratio.into(),
        round_start_delay: node_opt.round_start_delay.as_millis() as u64,
        start_delay: node_opt.start_delay.as_millis() as u64,
        propose_min_round_time: node_opt.min_propose_time,
        propose_max_round_time: node_opt.max_propose_time,
        min_transactions: node_opt.min_transactions,
        num_bootstrap: node_opt.bootstrap_nodes.len(),
        execution_type: ExecutionType::Continuous,
        election_config: None,
    };
    debug!(?config);

    let storage = get_store_dir(node_opt);
    let storage_path = Path::new(&storage);
    let lw_persistence = if node_opt.reset_store_state {
        debug!("Initializing new session");
        LWPersistence::new(storage_path, "validator").unwrap()
    } else {
        debug!("Restoring from persisted session");
        LWPersistence::load(storage_path, "validator").unwrap()
    };
    let initializer = match lw_persistence.load_latest_leaf() {
        Ok(leaf) => HotShotInitializer::from_reload(leaf),
        Err(_) => {
            // If we have reset the store state, or if there are no past leaves in storage, restart
            // from genesis.
            HotShotInitializer::from_genesis(ElaboratedBlock::genesis(genesis)).unwrap()
        }
    };
    let hotshot = HotShot::init(
        pub_key,
        priv_key,
        node_opt.id as u64,
        config,
        networking,
        MemoryStorage::new(),
        VrfImpl::with_initial_stake(known_nodes, &vrf_config),
        initializer,
    )
    .await
    .unwrap();
    lw_persistence.launch(hotshot.clone().into_stream());

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
                        EventType::Decide { leaf_chain } => {
                            if let Some(leaf) = leaf_chain.last() {
                                tracing::debug!(". - Committed state {}", leaf.state.commit());
                            }
                        }
                        EventType::NextLeaderViewTimeout { view_number } => {
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

/// Generate a list of private and public keys for the given number of nodes with a given seed.
pub fn gen_keys(seed: Option<SecretKeySeed>, num_nodes: usize) -> Vec<StakingPrivKey> {
    (0..num_nodes)
        .into_iter()
        .map(|node_id| {
            StakingKey::generated_from_seed_indexed(get_secret_key_seed(seed), node_id as u64).1
        })
        .collect()
}

pub async fn init_validator(
    node_opt: &NodeOpt,
    priv_key: StakingPrivKey,
    pub_keys: Vec<StakingKey>,
    genesis: GenesisNote,
) -> Consensus {
    debug!("Current node: {}", node_opt.id);

    let num_bootstrap = node_opt.bootstrap_nodes.len();

    let mut bootstrap_nodes = vec![];
    for i in 0..num_bootstrap {
        let priv_key = Ed25519Priv::generated_from_seed_indexed(
            get_secret_key_seed(node_opt.secret_key_seed),
            i as u64,
        );
        let libp2p_priv_key = SecretKey::from_bytes(&mut priv_key.to_bytes()[0..32]).unwrap();
        bootstrap_nodes.push(libp2p_priv_key);
    }

    let bootstrap_priv: Vec<_> = bootstrap_nodes
        .into_iter()
        .enumerate()
        .map(|(idx, kp)| {
            let multiaddr = parse_url(node_opt.bootstrap_nodes[idx].as_str()).unwrap();
            (libp2p::identity::Keypair::Ed25519(kp.into()), multiaddr)
        })
        .take(num_bootstrap)
        .collect();

    let to_connect_addrs: Vec<_> = bootstrap_priv
        .clone()
        .into_iter()
        .map(|(kp, ma)| (Some(PeerId::from_public_key(&kp.public())), ma))
        .collect();

    let (node_type, own_identity, port) = if node_opt.id < num_bootstrap {
        (
            NetworkNodeType::Bootstrap,
            Some(bootstrap_priv[node_opt.id].0.clone()),
            node_opt.bootstrap_nodes[node_opt.id]
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
                None => (node_opt.nonbootstrap_base_port + node_opt.id) as u16,
            },
        )
    };

    let own_network = match node_opt.cdn.clone() {
        Some(cdn) if !node_opt.libp2p => Network::new_cdn(pub_keys.clone(), cdn, node_opt.id)
            .await
            .unwrap(),
        _ => {
            let network = Network::new_p2p(
                pub_keys[node_opt.id].clone(),
                to_connect_addrs,
                node_type,
                parse_url(&format!("0.0.0.0:{:?}", port)).unwrap(),
                own_identity,
                node_opt,
            )
            .await
            .unwrap();

            if let Some(cdn) = node_opt.cdn.clone() {
                // If there is a centralized server, use it as a barrier, so we don't proceed beyond
                // this point until all nodes have reached this point and connected to the server.
                // We will still use the libp2p network for consensus itself.
                Network::new_cdn(pub_keys.clone(), cdn, node_opt.id)
                    .await
                    .unwrap();
            }

            network
        }
    };

    let known_nodes = pub_keys.clone();

    debug!("All nodes connected to network");

    // Initialize the state and hotshot
    init_hotshot(node_opt, known_nodes, priv_key, own_network, genesis).await
}

pub fn open_data_source(node_opt: &NodeOpt, consensus: Consensus) -> Arc<RwLock<QueryData>> {
    let storage = get_store_dir(node_opt);
    Arc::new(RwLock::new(if node_opt.reset_store_state {
        QueryData::new(&storage, Box::new(consensus), node_opt.location.clone()).unwrap()
    } else {
        QueryData::load(&storage, Box::new(consensus), node_opt.location.clone()).unwrap()
    }))
}

#[allow(dead_code)] // FIXME use this function in main
async fn collect_reward_daemon<R: CryptoRng + RngCore>(
    rng: &mut R,
    stake_proof: KVMerkleProof<StakeTableHash>,
    stake_amount: Amount,
    mut collected_rewards: CollectedRewardsSet,
    staking_priv_key: &StakingPrivKey,
    cap_address: &UserAddress,
    mut hotshot: Consensus,
) {
    let staking_key = StakingKey::from_private(staking_priv_key);
    loop {
        let event = hotshot
            .next_event()
            .await
            .expect("HotShot unexpectedly closed");
        if let EventType::Decide { leaf_chain } = event.event {
            for leaf in leaf_chain.iter().rev() {
                let validator_state = &leaf.state;
                let blk = &leaf.deltas;
                let view_number = leaf.justify_qc.view_number;

                // 0. check if I'm elected
                if let Some(vrf_proof) =
                    mock_eligibility::prove_eligibility(view_number, staking_priv_key)
                {
                    let claimed_reward = CollectedRewards {
                        staking_key: staking_key.clone(),
                        time: view_number,
                    };
                    let uncollected_reward_proof =
                        collected_rewards.lookup(claimed_reward).unwrap().1;
                    // 1. generate collect reward transaction
                    let (note, proof) = CollectRewardNote::generate(
                        rng,
                        &validator_state.historical_stake_tables,
                        validator_state.block_height - 1,
                        validator_state.total_stake,
                        view_number,
                        validator_state.block_height,
                        staking_priv_key,
                        cap_address.clone(),
                        stake_amount,
                        stake_proof.clone(),
                        uncollected_reward_proof,
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
                        .expect("Failed to submit reward transaction");

                    // 3. update collected_reward_set
                    for txn in blk.block.0.iter() {
                        if let EspressoTransaction::Reward(note) = txn {
                            let staking_key = note.staking_key();
                            let collected_reward = CollectedRewards {
                                staking_key,
                                time: view_number,
                            };
                            collected_rewards.insert(collected_reward, ());
                        }
                    }

                    // 4. Check block if contain stake transfer transaction and update stake proof
                    // TODO we haven't implemented stake transfer yet
                }
            }
        }
    }
}
