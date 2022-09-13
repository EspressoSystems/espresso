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

use address_book::InsertPubKey;
use async_std::{sync::Arc, task::sleep};
use async_trait::async_trait;
use async_tungstenite::async_std::connect_async;
use async_tungstenite::tungstenite::{
    client::IntoClientRequest, http::header as ws_headers, Message,
};
use espresso_availability_api::query_data::StateQueryData;
use espresso_core::{
    ledger::EspressoLedger,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::ElaboratedTransaction,
    universal_params::MERKLE_HEIGHT,
};
use espresso_metastate_api::api::NullifierCheck;
use futures::future::ready;
use futures::prelude::*;
use jf_cap::keys::{UserAddress, UserKeyPair, UserPubKey};
use jf_cap::proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey, UniversalParam};
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use key_set::{ProverKeySet, SizedKey};
use net::client::*;
use reef::Ledger;
use seahorse::transactions::Transaction;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    sparse_merkle_tree::SparseMerkleTree,
    txn_builder::TransactionState,
    BincodeSnafu, ClientConfigSnafu, CryptoSnafu, KeystoreBackend, KeystoreError, KeystoreState,
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use std::pin::Pin;
use std::time::Duration;
use surf::http::content::{Accept, MediaTypeProposal};
use surf::http::{headers, mime};
pub use surf::Url;

pub struct NetworkBackend<'a> {
    univ_param: &'a UniversalParam,
    query_client: surf::Client,
    address_book_client: surf::Client,
    validator_client: surf::Client,
}

impl<'a> NetworkBackend<'a> {
    pub async fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        address_book_url: Url,
        validator_url: Url,
    ) -> Result<NetworkBackend<'a>, KeystoreError<EspressoLedger>> {
        let backend = Self {
            query_client: Self::client(query_url)?,
            address_book_client: Self::client(address_book_url)?,
            validator_client: Self::client(validator_url)?,
            univ_param,
        };
        backend.wait_for_esqs().await?;
        Ok(backend)
    }

    fn client(base_url: Url) -> Result<surf::Client, KeystoreError<EspressoLedger>> {
        let client: surf::Client = surf::Config::new()
            .set_base_url(base_url)
            .try_into()
            .context(ClientConfigSnafu)?;
        Ok(client)
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, KeystoreError<EspressoLedger>> {
        let mut res = self
            .query_client
            .get(uri.as_ref())
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!("EsQS request GET {} failed: {}", uri.as_ref(), source),
            })?;
        response_body(&mut res)
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!(
                    "Failed to parse response from GET {}: {}",
                    uri.as_ref(),
                    source
                ),
            })
    }

    async fn post<T: Serialize>(
        client: &surf::Client,
        uri: impl AsRef<str>,
        body: &T,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        client
            .post(uri.as_ref())
            .body_bytes(bincode::serialize(body).context(BincodeSnafu)?)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!("EsQS request POST {} failed: {}", uri.as_ref(), source),
            })?;
        Ok(())
    }

    fn accept_header() -> Accept {
        let mut accept = Accept::new();
        // Signal that we would prefer a byte stream using the efficient bincode serialization,
        // but failing that we will take any format the server supports.
        //
        // MediaTypeProposal::new() only fails if the weight is outside the range [0, 1]. Since we
        // are using literal values for the weights, unwrap() is appropriate.
        accept.push(MediaTypeProposal::new(mime::BYTE_STREAM, Some(1.0)).unwrap());
        accept.set_wildcard(true);
        accept
    }

    async fn wait_for_esqs(&self) -> Result<(), KeystoreError<EspressoLedger>> {
        let mut backoff = Duration::from_millis(500);
        let url = &self
            .query_client
            .config()
            .base_url
            .as_ref()
            .expect("esqs config has no base url");
        for _ in 0..8 {
            // We use a direct `surf::connect` instead of
            // `self.query_client.connect` because the client middleware isn't
            // set up to handle connect requests, only API requests.
            if surf::connect(&url).send().await.is_ok() {
                return Ok(());
            }
            tracing::warn!(
                "unable to connect to EsQS at {}; sleeping for {:?}",
                url,
                backoff
            );
            sleep(backoff).await;
            backoff *= 2;
        }

        let msg = format!("failed to connect to EQS after {:?}", backoff);
        tracing::error!("{}", msg);
        Err(KeystoreError::Failed { msg })
    }
}

#[async_trait]
impl<'a> KeystoreBackend<'a, EspressoLedger> for NetworkBackend<'a> {
    type EventStream =
        Pin<Box<dyn Send + Unpin + Stream<Item = (LedgerEvent<EspressoLedger>, EventSource)>>>;

    async fn create(
        &mut self,
    ) -> Result<KeystoreState<'a, EspressoLedger>, KeystoreError<EspressoLedger>> {
        let block_id: u64 = self.get("status/latest_block_id").await?;
        let snapshot: StateQueryData = self
            .get(format!("availability/getstate/{}", block_id))
            .await?;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.univ_param;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_cap::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoSnafu)?
                .0,
            freeze: snapshot
                .state
                .chain
                .verif_crs
                .freeze
                .iter()
                .map(|k| {
                    Ok::<FreezeProvingKey, KeystoreError<EspressoLedger>>(
                        jf_cap::proof::freeze::preprocess(
                            univ_param,
                            k.num_inputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoSnafu)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
            xfr: snapshot
                .state
                .chain
                .verif_crs
                .xfr
                .iter()
                .map(|k| {
                    Ok::<TransferProvingKey, KeystoreError<EspressoLedger>>(
                        jf_cap::proof::transfer::preprocess(
                            univ_param,
                            k.num_inputs(),
                            k.num_outputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoSnafu)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
        });

        let state = KeystoreState {
            proving_keys,
            txn_state: TransactionState {
                nullifiers: SetMerkleTree::sparse(snapshot.state.nullifiers_root()),
                record_mt: SparseMerkleTree::restore_from_frontier(
                    snapshot.state.record_merkle_commitment,
                    &snapshot.state.record_merkle_frontier,
                )
                .ok_or_else(|| KeystoreError::Failed {
                    msg: "failed to restore sparse Merkle tree from frontier".to_string(),
                })?,
                validator: snapshot.state,
                now: EventIndex::from_source(
                    EventSource::QueryService,
                    snapshot.continuation_event_index as usize,
                ),
            },
        };

        Ok(state)
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        // All events come from a single source, the EsQS, which aggregates blocks and memos.
        let from = from.index(EventSource::QueryService);
        let to = to.map(|to| to.index(EventSource::QueryService));

        let mut url = self
            .query_client
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .join(&format!("catchup/subscribe_for_events/{}", from))
            .unwrap();
        url.set_scheme("ws").unwrap();
        let mut socket_req = url.into_client_request().unwrap();
        socket_req.headers_mut().insert(
            ws_headers::ACCEPT,
            "application/octet-stream".parse().unwrap(),
        );

        //todo !jeb.bearer handle connection failures.
        //      https://github.com/EspressoSystems/seahorse/issues/117
        // This should only fail if the server is incorrect or down, so we should handle by retrying
        // or failing over to a different server.
        let all_events = connect_async(socket_req)
            .await
            .expect("failed to connect to server")
            .0;
        let chosen_events: Pin<Box<dyn Stream<Item = _> + Send>> = if let Some(to) = to {
            Box::pin(all_events.take(to - from))
        } else {
            Box::pin(all_events)
        };

        Box::pin(
            chosen_events
                //todo !jeb.bearer handle stream errors
                //      https://github.com/EspressoSystems/seahorse/issues/117
                // If there is an error in the stream, or the server sends us invalid data, we
                // should retry or fail over to a different server.
                .filter_map(|msg| {
                    let item = match msg {
                        Ok(Message::Binary(bytes)) => match bincode::deserialize(&bytes) {
                            Ok(Some(e)) => Some(e),
                            Ok(None) => {
                                tracing::error!("missing event from catchup service");
                                None
                            }
                            Err(err) => {
                                tracing::error!("malformed event from catchup service: {}", err);
                                None
                            }
                        },
                        msg => {
                            tracing::warn!("unexpected message from catchup service: {:?}", msg);
                            None
                        }
                    }
                    .map(|event| (event, EventSource::QueryService));
                    ready(item)
                }),
        )
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, KeystoreError<EspressoLedger>> {
        let mut res = self
            .address_book_client
            .post("request_pubkey")
            .content_type(mime::JSON)
            .body_json(address)
            .unwrap()
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!(
                    "Address book request POST /request_pubkey failed: {}",
                    source
                ),
            })?;
        response_body(&mut res)
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!(
                    "Failed to parse response from GET /request_pubkey: {}",
                    source
                ),
            })
    }

    async fn get_nullifier_proof(
        &self,
        block_id: u64,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), KeystoreError<EspressoLedger>> {
        if let Some(ret) = set.contains(nullifier) {
            Ok(ret)
        } else {
            let NullifierCheck { proof, spent } = self
                .get(format!(
                    "/metastate/check_nullifier/{}/{}",
                    block_id, nullifier
                ))
                .await?;
            set.remember(nullifier, proof.clone()).unwrap();
            Ok((spent, proof))
        }
    }

    async fn register_user_key(
        &mut self,
        key_pair: &UserKeyPair,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        let pub_key_bytes = bincode::serialize(&key_pair.pub_key()).unwrap();
        let sig = key_pair.sign(&pub_key_bytes);
        let json_request = InsertPubKey { pub_key_bytes, sig };
        match self
            .address_book_client
            .post("insert_pubkey")
            .content_type(mime::JSON)
            .body_json(&json_request)
            .unwrap()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(KeystoreError::Failed {
                msg: format!("error inserting public key: {}", err),
            }),
        }
    }

    async fn submit(
        &mut self,
        mut txn: ElaboratedTransaction,
        txn_info: Transaction<EspressoLedger>,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        if let Some(signed_memos) = txn_info.memos() {
            txn.memos = Some((
                signed_memos.memos.iter().flatten().cloned().collect(),
                signed_memos.sig.clone(),
            ));
        }

        Self::post(&self.validator_client, "/validator/submit", &txn).await
    }

    async fn finalize(&mut self, _txn: Transaction<EspressoLedger>, _txid: Option<(u64, u64)>) {
        // -> Result<(), KeystoreError<EspressoLedger>>
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<EspressoLedger>> {
        Ok((
            MerkleTree::new(EspressoLedger::merkle_height()).unwrap(),
            Default::default(),
        ))
    }
}
