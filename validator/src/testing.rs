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

use crate::{
    gen_keys, genesis, init_validator, open_data_source, parse_duration, run_consensus,
    ConsensusOpt, NodeOpt, MINIMUM_BOOTSTRAP_NODES, MINIMUM_NODES,
};
use address_book::{error::AddressBookError, store::FileStore};
use async_std::task::sleep;
use async_std::task::{block_on, spawn, JoinHandle};
use async_trait::async_trait;
use espresso_core::ledger::EspressoLedger;
use espresso_core::StakingKey;
use espresso_esqs::full_node::{self, EsQS};
use futures::Future;
use futures::{channel::oneshot, future::join_all};
use hotshot::types::SignatureKey;
use jf_cap::keys::UserPubKey;
use portpicker::pick_unused_port;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::{rand_core::RngCore, ChaChaRng};
use seahorse::hd::KeyTree;
use seahorse::loader::KeystoreLoader;
use seahorse::KeySnafu;
use seahorse::KeystoreError;
use snafu::ResultExt;
use std::env;
use std::io;
use std::mem::take;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use surf_disco::Url;
use tempdir::TempDir;

mod rewards;

pub struct UnencryptedKeystoreLoader {
    pub dir: TempDir,
}

#[async_trait]
impl KeystoreLoader<EspressoLedger> for UnencryptedKeystoreLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.dir.path().into()
    }

    async fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<EspressoLedger>> {
        let key = KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)?;
        Ok(((), key))
    }

    async fn load(
        &mut self,
        _meta: &mut Self::Meta,
    ) -> Result<KeyTree, KeystoreError<EspressoLedger>> {
        KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)
    }
}
pub struct TestNode {
    esqs: Option<EsQS>,
    kill: oneshot::Sender<()>,
    wait: JoinHandle<()>,
}

impl TestNode {
    pub async fn kill(self) {
        self.kill.send(()).ok();
        self.wait.await;
    }
}

pub struct AddressBook {
    port: u16,
    _store: TempDir,
    _wait: JoinHandle<io::Result<()>>,
}

impl AddressBook {
    pub async fn init() -> Self {
        let dir = TempDir::new("address_book").unwrap();
        let store = FileStore::new(dir.path().to_owned());
        let port = pick_unused_port().unwrap();
        let base_url: String = format!("127.0.0.1:{port}");
        let api_path = std::env::current_dir()
            .unwrap()
            .join("..")
            .join("address-book")
            .join("api")
            .join("api.toml");

        let app = address_book::init_web_server(api_path.to_str().unwrap().to_string(), store)
            .expect("address_book app");
        let handle = spawn(app.serve(base_url.clone()));

        let ab = AddressBook {
            port,
            _store: dir,
            _wait: handle,
        };
        assert!(surf_disco::connect::<AddressBookError>(ab.url(), None).await);
        ab
    }

    pub fn url(&self) -> Url {
        Url::parse(&format!("http://localhost:{}", self.port)).unwrap()
    }

    pub async fn kill(self) {
        // There is unfortunately no way to kill the address book, since it is a Tide thread. We
        // just leak the underlying thread.
    }
}

pub struct TestNetwork {
    pub query_api: Url,
    pub submit_api: Url,
    pub address_book_api: Url,
    pub nodes: Vec<TestNode>,
    address_book: Option<AddressBook>,
    _store: TempDir,
}

impl TestNetwork {
    pub async fn kill(mut self) {
        Self::kill_impl(take(&mut self.nodes), take(&mut self.address_book)).await
    }

    async fn kill_impl(nodes: Vec<TestNode>, address_book: Option<AddressBook>) {
        join_all(nodes.into_iter().map(|node| node.kill())).await;
        if let Some(address_book) = address_book {
            address_book.kill().await;
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        block_on(Self::kill_impl(
            take(&mut self.nodes),
            take(&mut self.address_book),
        ));
    }
}

/// Create a minimal network of validators for testing.
///
/// This function will start the minimal number of validators needed to run consensus. One of the
/// validators will be a full node with a query service, which can be used to follow the ledger
/// state and submit transactions. The URL for the query service is returned.
pub async fn minimal_test_network(
    rng: &mut ChaChaRng,
    faucet_pub_key: UserPubKey,
    rewards_pub_key: Option<UserPubKey>,
) -> TestNetwork {
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let bootstrap_ports = (0..MINIMUM_BOOTSTRAP_NODES)
        .into_iter()
        .map(|_| pick_unused_port().unwrap());
    let consensus_opt = ConsensusOpt {
        secret_key_seed: Some(seed.into()),
        replication_factor: 4,
        bootstrap_mesh_n_high: 50,
        bootstrap_mesh_n_low: 10,
        bootstrap_mesh_outbound_min: 4,
        bootstrap_mesh_n: 15,
        nonbootstrap_mesh_n_high: 15,
        nonbootstrap_mesh_n_low: 8,
        nonbootstrap_mesh_outbound_min: 4,
        nonbootstrap_mesh_n: 12,
        bootstrap_nodes: bootstrap_ports
            .map(|p| format!("localhost:{}", p).parse().unwrap())
            .collect(),
    };

    println!("generating public keys");
    let start = Instant::now();
    let keys = gen_keys(&consensus_opt, MINIMUM_NODES);
    let pub_keys = keys
        .iter()
        .map(StakingKey::from_private)
        .collect::<Vec<_>>();
    println!("generated public keys in {:?}", start.elapsed());

    let store = TempDir::new("minimal_test_network_store").unwrap();

    let mut nodes_futures = vec![];
    for (i, key) in keys.iter().enumerate() {
        let consensus_opt = consensus_opt.clone();
        let pub_keys = pub_keys.clone();
        let mut store_path = store.path().to_owned();
        let priv_key = key.clone();
        let facuet_pub_key = faucet_pub_key.clone();
        let rewards_pub_key = rewards_pub_key.clone();

        store_path.push(i.to_string());
        let new_rng = ChaChaRng::from_rng(&mut *rng).unwrap();
        let future = async move {
            let node_opt = NodeOpt {
                store_path: Some(store_path),
                nonbootstrap_base_port: pick_unused_port().unwrap() as usize,
                // Set fairly short view times (propose any transactions available after 5s, propose
                // an empty block after 10s). In testing, we generally have low volumes, so we don't
                // gain much from waiting longer to batch larger blocks, but with low views we get
                // low latency and the tests run much faster.
                min_propose_time: Duration::from_secs(5),
                min_transactions: 1,
                max_propose_time: parse_duration(
                    &env::var("ESPRESSO_TEST_MAX_PROPOSE_TIME")
                        .unwrap_or_else(|_| "10s".to_string()),
                )
                .unwrap(),
                next_view_timeout: parse_duration(
                    &env::var("ESPRESSO_TEST_VIEW_TIMEOUT").unwrap_or_else(|_| "60s".to_string()),
                )
                .unwrap(),
                faucet_pub_key: vec![facuet_pub_key],
                rewards_pub_key,
                ..NodeOpt::new(MINIMUM_NODES)
            };
            let genesis = genesis(&node_opt, &consensus_opt);
            let consensus = init_validator(
                new_rng,
                &node_opt,
                &consensus_opt,
                priv_key,
                pub_keys,
                genesis,
                i,
            )
            .await;
            let data_source = open_data_source(
                &node_opt,
                i,
                Some("My location".to_string()),
                consensus.clone(),
            );

            // If applicable, run a query service.
            let esqs = if i == 0 {
                let port = pick_unused_port().unwrap();
                tracing::info!("spawning EsQS at http://localhost:{}", port);
                Some(
                    EsQS::new(
                        &full_node::Command::with_port(port),
                        data_source,
                        consensus.clone(),
                    )
                    .unwrap(),
                )
            } else {
                None
            };

            let (kill, recv_kill) = oneshot::channel();
            let wait = spawn(run_consensus(consensus, recv_kill));
            TestNode { esqs, kill, wait }
        };
        nodes_futures.push(future);
    }
    let nodes = join_all(nodes_futures).await;

    let address_book = AddressBook::init().await;
    let address_book_api = address_book.url();

    TestNetwork {
        query_api: nodes[0].esqs.as_ref().unwrap().url(),
        submit_api: nodes[0].esqs.as_ref().unwrap().url(),
        address_book_api,
        nodes,
        address_book: Some(address_book),
        _store: store,
    }
}

pub async fn retry<Fut: Future<Output = bool>>(f: impl Fn() -> Fut) {
    if std::env::var("ESPRESSO_TEST_DISABLE_RETRY_TIMEOUT").is_ok() {
        while !f().await {
            sleep(Duration::from_secs(5)).await;
        }
    } else {
        let mut backoff = Duration::from_millis(100);
        for _ in 0..13 {
            if f().await {
                return;
            }
            sleep(backoff).await;
            backoff *= 2;
        }
        panic!("retry loop did not complete in {:?}", backoff);
    }
}
