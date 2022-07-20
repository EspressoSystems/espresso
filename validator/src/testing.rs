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
    full_node_mem_data_source::QueryData, gen_keys, init_validator, init_web_server,
    ConsensusConfig, GenesisState, Node, NodeOpt, MINIMUM_NODES,
};
use async_std::task::{block_on, spawn, JoinHandle};
use futures::{channel::oneshot, future::join_all};
use jf_cap::keys::UserPubKey;
use portpicker::pick_unused_port;
use rand_chacha::{rand_core::RngCore, ChaChaRng};
use std::io;
use std::iter;
use std::mem::take;
use std::time::Instant;
use surf::Url;
use tempdir::TempDir;
use validator_node::{
    keystore::{
        loader::{KeystoreLoader, MnemonicPasswordLogin},
        network::NetworkBackend,
        EspressoKeystore,
    },
    node::Validator,
};
use zerok_lib::{ledger::EspressoLedger, universal_params::UNIVERSAL_PARAM};

pub struct TestNode {
    pub query_api: Option<Url>,
    pub submit_api: Option<Url>,
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
        let store = address_book::FileStore::new(dir.path().to_owned());
        let port = pick_unused_port().unwrap();
        let join = address_book::init_web_server(port, store).await.unwrap();
        address_book::wait_for_server(port).await;
        Self {
            port,
            _store: dir,
            _wait: join,
        }
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
    pub async fn create_keystore(
        &self,
        loader: &mut impl KeystoreLoader<EspressoLedger, Meta = MnemonicPasswordLogin>,
    ) -> EspressoKeystore<'static, NetworkBackend<'static>, MnemonicPasswordLogin> {
        let backend = NetworkBackend::new(
            &UNIVERSAL_PARAM,
            self.query_api.clone(),
            self.address_book_api.clone(),
            self.submit_api.clone(),
        )
        .await
        .unwrap();
        EspressoKeystore::new(backend, loader).await.unwrap()
    }

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
pub async fn minimal_test_network(rng: &mut ChaChaRng, faucet_pub_key: UserPubKey) -> TestNetwork {
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let nodes = iter::from_fn(|| {
        let port = pick_unused_port().unwrap();
        Some(
            Url::parse(&format!("http://localhost:{}", port))
                .unwrap()
                .into(),
        )
    })
    .take(MINIMUM_NODES)
    .collect();
    let config = ConsensusConfig {
        seed: seed.into(),
        nodes,
        // NOTE these are arbitrarily chosen.
        num_bootstrap: 4,
        replication_factor: 3,
        bootstrap_mesh_n_high: 7,
        bootstrap_mesh_n_low: 4,
        bootstrap_mesh_outbound_min: 3,
        bootstrap_mesh_n: 6,
        mesh_n_high: 7,
        mesh_n_low: 4,
        mesh_outbound_min: 3,
        mesh_n: 6,
    };

    println!("generating public keys");
    let start = Instant::now();
    let keys = gen_keys(&config);
    let pub_keys = keys
        .iter()
        .map(|key| key.public.clone())
        .collect::<Vec<_>>();
    println!("generated public keys in {:?}", start.elapsed());

    let store = TempDir::new("minimal_test_network_store").unwrap();
    let genesis = GenesisState::new(iter::once(faucet_pub_key));
    let nodes = join_all((0..MINIMUM_NODES).into_iter().map(|i| {
        let config = config.clone();
        let genesis = genesis.clone();
        let pub_keys = pub_keys.clone();
        let mut store_path = store.path().to_owned();
        let priv_key = keys[i].private.clone();

        store_path.push(i.to_string());
        async move {
            let mut opt = NodeOpt {
                store_path: Some(store_path),
                ..NodeOpt::default()
            };
            if i == 0 {
                opt.full = true;
                opt.web_server_port = pick_unused_port().unwrap();
            }
            let data_source =
                async_std::sync::Arc::new(async_std::sync::RwLock::new(QueryData::new()));

            let node = init_validator(
                &opt,
                &config,
                priv_key,
                pub_keys,
                genesis,
                i,
                data_source.clone(),
            )
            .await;

            // If applicable, run a query service.
            let url = if let Node::Full(node) = &node {
                // This returns a JoinHandle for the server, but there's no way to kill a Tide
                // server (this is a known bug/limitation of Tide) so all we can really do is drop
                // the handle, detaching the task.
                init_web_server(&opt, node.clone()).unwrap();
                Some(
                    format!("http://0.0.0.0:{}", opt.web_server_port)
                        .parse()
                        .unwrap(),
                )
            } else {
                None
            };

            let (kill, recv_kill) = oneshot::channel();
            let wait = spawn(node.run(recv_kill));
            TestNode {
                query_api: url.clone(),
                submit_api: url,
                kill,
                wait,
            }
        }
    }))
    .await;

    let address_book = AddressBook::init().await;
    let address_book_api = address_book.url();

    TestNetwork {
        query_api: nodes[0].query_api.clone().unwrap(),
        submit_api: nodes[0].submit_api.clone().unwrap(),
        address_book_api,
        nodes,
        address_book: Some(address_book),
        _store: store,
    }
}
