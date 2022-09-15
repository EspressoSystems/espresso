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

use address_book::{error::AddressBookError, InsertPubKey};
use async_std::sync::Arc;
use async_trait::async_trait;
use espresso_availability_api::query_data::StateQueryData;
use espresso_core::{
    ledger::EspressoLedger,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::ElaboratedTransaction,
    universal_params::MERKLE_HEIGHT,
};
use espresso_esqs::ApiError;
use espresso_metastate_api::api::NullifierCheck;
use futures::future::ready;
use futures::prelude::*;
use jf_cap::keys::{UserAddress, UserKeyPair, UserPubKey};
use jf_cap::proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey, UniversalParam};
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use key_set::{ProverKeySet, SizedKey};
use reef::Ledger;
use seahorse::transactions::Transaction;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    sparse_merkle_tree::SparseMerkleTree,
    txn_builder::TransactionState,
    CryptoSnafu, KeystoreBackend, KeystoreError, KeystoreState,
};
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt;
use std::pin::Pin;
use std::time::Duration;
use surf_disco::{Client, Url};

pub struct NetworkBackend<'a> {
    univ_param: &'a UniversalParam,
    query_client: Client<ApiError>,
    address_book_client: Client<AddressBookError>,
    validator_client: Client<ApiError>,
}

impl<'a> NetworkBackend<'a> {
    pub async fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        address_book_url: Url,
        validator_url: Url,
    ) -> Result<NetworkBackend<'a>, KeystoreError<EspressoLedger>> {
        let backend = Self {
            query_client: Client::new(query_url),
            address_book_client: Client::new(address_book_url),
            validator_client: Client::new(validator_url),
            univ_param,
        };
        backend.wait_for_esqs().await?;
        Ok(backend)
    }

    async fn get<T: DeserializeOwned>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, KeystoreError<EspressoLedger>> {
        self.query_client
            .get(uri.as_ref())
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!("EsQS request GET {} failed: {}", uri.as_ref(), source),
            })
    }

    async fn post<T: Serialize, E: surf_disco::Error>(
        client: &Client<E>,
        uri: impl AsRef<str>,
        body: &T,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        client
            .post(uri.as_ref())
            .body_binary(body)
            .map_err(|source| KeystoreError::Failed {
                msg: format!("failed to build request POST {}: {}", uri.as_ref(), source),
            })?
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!("request POST {} failed: {}", uri.as_ref(), source),
            })
    }

    async fn wait_for_esqs(&self) -> Result<(), KeystoreError<EspressoLedger>> {
        let timeout = Duration::from_secs(300);
        if self.query_client.connect(Some(timeout)).await {
            Ok(())
        } else {
            let msg = format!("failed to connect to EQS after {:?}", timeout);
            tracing::error!("{}", msg);
            Err(KeystoreError::Failed { msg })
        }
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

        //todo !jeb.bearer handle connection failures.
        //      https://github.com/EspressoSystems/seahorse/issues/117
        // This should only fail if the server is incorrect or down, so we should handle by retrying
        // or failing over to a different server.
        let all_events = self
            .query_client
            .socket(&format!("catchup/subscribe_for_events/{}", from))
            .subscribe()
            .await
            .expect("failed to connect to server");
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
                .filter_map(|msg| ready(msg.ok().map(|e| (e, EventSource::QueryService)))),
        )
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, KeystoreError<EspressoLedger>> {
        self.address_book_client
            .post("request_pubkey")
            .body_json(address)
            .unwrap()
            .send()
            .await
            .map_err(|source| KeystoreError::Failed {
                msg: format!(
                    "Address book request POST /request_pubkey failed: {}",
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
        self.address_book_client
            .post("insert_pubkey")
            .body_json(&json_request)
            .unwrap()
            .send()
            .await
            .map_err(|err| KeystoreError::Failed {
                msg: format!("error inserting public key: {}", err),
            })
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
