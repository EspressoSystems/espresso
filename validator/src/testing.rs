use crate::{
    gen_pub_keys, init_validator, init_web_server, ConsensusConfig, GenesisState, Node, NodeConfig,
    NodeOpt, MINIMUM_NODES,
};
use async_std::task::{block_on, spawn, JoinHandle};
use futures::{channel::oneshot, future::join_all};
use jf_cap::keys::UserPubKey;
use portpicker::pick_unused_port;
use rand_chacha::{rand_core::RngCore, ChaChaRng};
use std::iter;
use std::mem::take;
use std::time::Instant;
use surf::Url;
use tempdir::TempDir;
use zerok_lib::node::Validator;

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

pub struct TestNetwork {
    pub query_api: Url,
    pub submit_api: Url,
    pub nodes: Vec<TestNode>,
    _store: TempDir,
}

impl TestNetwork {
    pub async fn kill(mut self) {
        Self::kill_impl(take(&mut self.nodes)).await
    }

    async fn kill_impl(nodes: Vec<TestNode>) {
        join_all(nodes.into_iter().map(|node| node.kill())).await;
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        block_on(Self::kill_impl(take(&mut self.nodes)));
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
        Some(NodeConfig {
            ip: "localhost".into(),
            port: pick_unused_port().unwrap(),
        })
    })
    .take(MINIMUM_NODES)
    .collect();
    let config = ConsensusConfig { seed, nodes };

    println!("generating public keys");
    let start = Instant::now();
    let pub_keys = gen_pub_keys(&config);
    println!("generated public keys in {:?}", start.elapsed());

    let store = TempDir::new("minimal_test_network_store").unwrap();
    let genesis = GenesisState::new(iter::once(faucet_pub_key));
    let nodes = join_all((0..MINIMUM_NODES).into_iter().map(|i| {
        let config = config.clone();
        let genesis = genesis.clone();
        let pub_keys = pub_keys.clone();
        let mut store_path = store.path().to_owned();
        store_path.push(i.to_string());
        async move {
            let mut opt = NodeOpt::default();
            opt.store_path = Some(store_path);
            if i == 0 {
                opt.full = true;
                opt.web_server_port = pick_unused_port().unwrap();
            }
            let node = init_validator(&opt, &config, pub_keys, genesis, i).await;

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

    TestNetwork {
        query_api: nodes[0].query_api.clone().unwrap(),
        submit_api: nodes[0].submit_api.clone().unwrap(),
        nodes,
        _store: store,
    }
}
