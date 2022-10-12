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

use crate::ConsensusOpt;
use async_std::{
    sync::{Arc, RwLock},
    task::sleep,
};
use async_trait::async_trait;
use espresso_core::{state::ValidatorState, PubKey};
use hotshot::{
    traits::{
        implementations::{CentralizedServerNetwork, Libp2pNetwork},
        NetworkError, NetworkingImplementation,
    },
    types::Message,
};
use hotshot_types::traits::network::NetworkChange;
use libp2p::identity::Keypair;
use libp2p_networking::{
    network::{MeshParams, NetworkNodeConfigBuilder, NetworkNodeType},
    reexport::{Multiaddr, PeerId},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use surf::Url;

#[derive(Clone, Debug)]
pub enum HybridNetwork {
    P2P(Libp2pNetwork<Message<ValidatorState, PubKey>, PubKey>),
    Cdn(CentralizedServerNetwork<PubKey>),
}

impl HybridNetwork {
    /// Create a new libp2p network.
    pub async fn new_p2p(
        pubkey: PubKey,
        bs: Vec<(Option<PeerId>, Multiaddr)>,
        node_id: usize,
        node_type: NetworkNodeType,
        bound_addr: Multiaddr,
        identity: Option<Keypair>,
        consensus_opt: &ConsensusOpt,
    ) -> Result<Self, NetworkError> {
        let mut config_builder = NetworkNodeConfigBuilder::default();
        // NOTE we may need to change this as we scale
        config_builder
            .replication_factor(NonZeroUsize::new(consensus_opt.replication_factor).unwrap());
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

        Ok(Self::P2P(
            Libp2pNetwork::new(
                config,
                pubkey,
                Arc::new(RwLock::new(bs)),
                consensus_opt.bootstrap_nodes.len(),
                node_id,
            )
            .await?,
        ))
    }

    /// Create a new Cdn-based network.
    pub async fn new_cdn(
        known_nodes: Vec<PubKey>,
        server: Url,
        node_id: usize,
    ) -> Result<Self, NetworkError> {
        let pub_key = known_nodes[node_id];
        let num_nodes = known_nodes.len();
        let network = CentralizedServerNetwork::connect(
            known_nodes,
            (
                server.host_str().unwrap(),
                server.port_or_known_default().unwrap(),
            )
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
            pub_key,
        );
        loop {
            let connected = network.get_connected_client_count().await;
            if connected as usize >= num_nodes {
                break;
            }
            tracing::debug!("waiting for peers to connect ({}/{})", connected, num_nodes);
            sleep(Duration::from_secs(1)).await;
        }
        Ok(Self::Cdn(network))
    }
}

macro_rules! impl_networking {
    {
        $(async fn $name:ident$
            (<$($type_param:ident $(: $type_constraint:tt)?),*>)?
            (&self $(, $($param:ident : $param_type:ty),* $(,)?)?)
        $(-> $result_type:ty)?;)*
    } =>
    {
        #[async_trait]
        impl NetworkingImplementation<Message<ValidatorState, PubKey>, PubKey> for HybridNetwork {
            $(
                async fn $name
                    $(<$($type_param $(: $type_constraint)?),*>)?
                    (&self $(, $($param : $param_type),*)?)
                $(-> $result_type)? {
                    match self {
                        Self::P2P(p2p) =>
                            NetworkingImplementation::<Message<ValidatorState, PubKey>, PubKey>::
                                $name(p2p, $($($param),*)?).await,
                        Self::Cdn(cdn) =>
                            NetworkingImplementation::<Message<ValidatorState, PubKey>, PubKey>::
                                $name(cdn, $($($param),*)?).await,
                    }
                }
            )*
        }
    }
}

impl_networking! {
    async fn ready(&self) -> bool;
    async fn broadcast_message(
        &self,
        message: Message<ValidatorState, PubKey>,
    ) -> Result<(), NetworkError>;
    async fn message_node(
        &self,
        message: Message<ValidatorState, PubKey>,
        recipient: PubKey,
    ) -> Result<(), NetworkError>;
    async fn broadcast_queue(&self,) -> Result<Vec<Message<ValidatorState, PubKey>>, NetworkError>;
    async fn next_broadcast(&self) -> Result<Message<ValidatorState, PubKey>, NetworkError>;
    async fn direct_queue(&self) -> Result<Vec<Message<ValidatorState, PubKey>>, NetworkError>;
    async fn next_direct(&self) -> Result<Message<ValidatorState, PubKey>, NetworkError>;
    async fn known_nodes(&self) -> Vec<PubKey>;
    async fn network_changes(&self) -> Result<Vec<NetworkChange<PubKey>>, NetworkError>;
    async fn shut_down(&self) -> ();
    async fn put_record(
        &self,
        key: impl Serialize + Send + Sync + 'static,
        value: impl Serialize + Send + Sync + 'static,
    ) -> Result<(), NetworkError>;
    async fn get_record<V: (for<'a> Deserialize<'a>)>(
        &self,
        key: impl Serialize + Send + Sync + 'static,
    ) -> Result<V, NetworkError>;
    async fn notify_of_subsequent_leader(&self, pk: PubKey, cancelled: Arc<AtomicBool>);
}
