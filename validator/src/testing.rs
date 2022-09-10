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
    full_node_esqs, gen_keys, genesis, init_validator, open_data_source, ConsensusOpt, NodeOpt,
    UpdateQueryDataSourceTypesBinder, MINIMUM_NODES,
};
use address_book::store::FileStore;
use async_std::{
    sync::{Arc, RwLock},
    task::{block_on, spawn, JoinHandle},
};
use espresso_core::{
    ledger::EspressoLedger, state::ElaboratedBlock, universal_params::UNIVERSAL_PARAM,
};
use futures::{channel::oneshot, future::join_all};
use jf_cap::keys::UserPubKey;
use portpicker::pick_unused_port;
use rand_chacha::{rand_core::RngCore, ChaChaRng};
use std::io;
use std::iter;
use std::mem::take;
use std::time::{Duration, Instant};
use surf::Url;
use tempdir::TempDir;
use tide_disco::{wait_for_server, SERVER_STARTUP_RETRIES, SERVER_STARTUP_SLEEP_MS};
use validator_node::{
    keystore::{
        loader::{KeystoreLoader, MnemonicPasswordLogin},
        network::NetworkBackend,
        EspressoKeystore,
    },
    node::Validator,
    update_query_data_source::UpdateQueryDataSource,
};

pub struct TestNode {
    pub query_api: Option<Url>,
    pub submit_api: Option<Url>,
    _update_data_source:
        Option<Arc<RwLock<UpdateQueryDataSource<UpdateQueryDataSourceTypesBinder>>>>,
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
        let base_url: String = format!("http://127.0.0.1:{port}");
        let api_path = std::env::current_dir()
            .unwrap()
            .join("..")
            .join("address-book")
            .join("api")
            .join("api.toml");

        let app = address_book::init_web_server(api_path.to_str().unwrap().to_string(), store)
            .expect("address_book app");
        let handle = spawn(app.serve(base_url.clone()));
        wait_for_server(
            &Url::parse(&base_url).unwrap(),
            SERVER_STARTUP_RETRIES,
            SERVER_STARTUP_SLEEP_MS,
        )
        .await;

        let ab = AddressBook {
            port,
            _store: dir,
            _wait: handle,
        };
        wait_for_server(&ab.url(), SERVER_STARTUP_RETRIES, SERVER_STARTUP_SLEEP_MS).await;
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
    let base_port = pick_unused_port().unwrap();
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
        bootstrap_nodes: vec![Url::parse(&format!("localhost:{}", base_port)).unwrap()],
    };

    println!("generating public keys");
    let start = Instant::now();
    let keys = gen_keys(&consensus_opt, MINIMUM_NODES);
    let pub_keys = keys
        .iter()
        .map(|key| key.public.clone())
        .collect::<Vec<_>>();
    println!("generated public keys in {:?}", start.elapsed());

    let store = TempDir::new("minimal_test_network_store").unwrap();
    let genesis = genesis(0, iter::once(faucet_pub_key));
    let nodes = join_all((0..MINIMUM_NODES).into_iter().map(|i| {
        let consensus_opt = consensus_opt.clone();
        let genesis = genesis.clone();
        let pub_keys = pub_keys.clone();
        let mut store_path = store.path().to_owned();
        let priv_key = keys[i].private.clone();

        store_path.push(i.to_string());
        async move {
            let mut node_opt = NodeOpt {
                store_path: Some(store_path),
                nonbootstrap_base_port: base_port as usize,
                next_view_timeout: Duration::from_secs(10 * 60),
                ..NodeOpt::default()
            };
            if i == 0 {
                node_opt.full = true;
            }
            let consensus = init_validator(
                &node_opt,
                &consensus_opt,
                priv_key,
                pub_keys,
                genesis.clone(),
                i,
            )
            .await;
            let data_source = open_data_source(&node_opt, i, consensus.clone());

            // If applicable, run a query service.
            let (url, update_data_source) = if node_opt.full {
                let port = pick_unused_port().unwrap();
                tracing::info!("spawning EsQS at http://localhost:{}", port);
                // This returns a JoinHandle for the server, but there's no way to kill a Tide
                // server (this is a known bug/limitation of Tide) so all we can really do is drop
                // the handle, detaching the task.
                spawn(
                    full_node_esqs::init_server(
                        &full_node_esqs::Command::with_port(port),
                        data_source.clone(),
                    )
                    .unwrap(),
                );
                (
                    Some(format!("http://localhost:{}", port).parse().unwrap()),
                    Some(UpdateQueryDataSource::new(
                        consensus.subscribe(),
                        data_source.clone(),
                        data_source.clone(),
                        data_source.clone(),
                        data_source.clone(),
                        data_source,
                        ElaboratedBlock::genesis(genesis),
                    )),
                )
            } else {
                (None, None)
            };

            let (kill, recv_kill) = oneshot::channel();
            let wait = spawn(consensus.run(recv_kill));
            TestNode {
                query_api: url.clone(),
                submit_api: url,
                _update_data_source: update_data_source,
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
