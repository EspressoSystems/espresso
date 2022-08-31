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

// Copyright (c) 2022 Espresso Systems (espressosys.com)

use crate::WebState;
use api::{server, BlockId, Hash, TaggedBlob, TransactionId, UnspentRecord};
use espresso_core::{
    ledger::EspressoLedger,
    state::{state_comm::LedgerStateCommitment, ElaboratedBlock},
};
use futures::prelude::*;
use hotshot::traits::BlockContents;
use itertools::izip;
use seahorse::events::LedgerEvent;
use serde::{Deserialize, Serialize};
use server::{best_response_type, response};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter, EnumString};
use tagged_base64::TaggedBase64;
use tide::http::{content::Accept, mime};
use tide::StatusCode;
use tide_websockets::WebSocketConnection;
use tracing::{event, Level};
use validator_node::{
    api,
    api::*,
    node::{LedgerSnapshot, LedgerSummary, LedgerTransition, QueryService},
};

#[derive(Debug, EnumString)]
pub enum UrlSegmentType {
    Boolean,
    Hexadecimal,
    Integer,
    TaggedBase64,
    Literal,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum UrlSegmentValue {
    Boolean(bool),
    Hexadecimal(u128),
    Integer(u128),
    Identifier(TaggedBase64),
    Unparsed(String),
    ParseFailed(UrlSegmentType, String),
    Literal(String),
}

use UrlSegmentValue::*;

impl UrlSegmentValue {
    pub fn parse(value: &str, ptype: &str) -> Option<Self> {
        Some(match ptype {
            "Boolean" => Boolean(value.parse::<bool>().ok()?),
            "Hexadecimal" => Hexadecimal(u128::from_str_radix(value, 16).ok()?),
            "Integer" => Integer(value.parse::<u128>().ok()?),
            "TaggedBase64" => Identifier(TaggedBase64::parse(value).ok()?),
            _ => panic!("Type specified in api.toml isn't supported: {}", ptype),
        })
    }

    pub fn as_boolean(&self) -> Result<bool, tide::Error> {
        if let Boolean(b) = self {
            Ok(*b)
        } else {
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                format!("expected boolean, got {:?}", self),
            ))
        }
    }

    pub fn as_index(&self) -> Result<usize, tide::Error> {
        if let Integer(ix) = self {
            Ok(*ix as usize)
        } else {
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                format!("expected index, got {:?}", self),
            ))
        }
    }

    pub fn as_identifier(&self) -> Result<TaggedBase64, tide::Error> {
        if let Identifier(i) = self {
            Ok(i.clone())
        } else {
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                format!("expected tagged base 64, got {:?}", self),
            ))
        }
    }

    pub fn to<T: TaggedBlob>(&self) -> Result<T, tide::Error> {
        T::from_tagged_blob(&self.as_identifier()?)
            .map_err(|err| tide::Error::from_str(StatusCode::BadRequest, format!("{}", err)))
    }
}

#[derive(Debug)]
pub struct RouteBinding {
    /// Placeholder from the route pattern, e.g. :id
    pub parameter: String,

    /// Type for parsing
    pub ptype: UrlSegmentType,

    /// Value
    pub value: UrlSegmentValue,
}

/// Index entries for documentation fragments
#[allow(non_camel_case_types)]
#[derive(AsRefStr, Copy, Clone, Debug, EnumIter, EnumString)]
pub enum ApiRouteKey {
    getblock,
    getblockcount,
    getblockhash,
    getblockid,
    getevent,
    getinfo,
    getmempool,
    getnullifier,
    getsnapshot,
    getstatecomm,
    gettransaction,
    getunspentrecord,
    getunspentrecordsetinfo,
    healthcheck,
    subscribe,
}

/// Verifiy that every variant of enum ApiRouteKey is defined in api.toml
// TODO !corbett Check all the other things that might fail after startup.
pub fn check_api(api: toml::Value) -> bool {
    let mut missing_definition = false;
    for key in ApiRouteKey::iter() {
        let key_str = key.as_ref();
        if api["route"].get(key_str).is_none() {
            println!("Missing API definition for [route.{}]", key_str);
            missing_definition = true;
        }
    }
    if missing_definition {
        panic!("api.toml is inconsistent with enum ApiRoutKey");
    }
    !missing_definition
}

// Wrapper around `api::server_error` forcing `EspressoError` as the error type.
pub fn server_error<E: Into<EspressoError>>(err: E) -> tide::Error {
    api::server_error(err)
}

// Get a block index from whatever form of block identifier was used in the URL.
async fn block_index(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<usize, tide::Error> {
    if let Some(b) = bindings.get(":index") {
        b.value.as_index()
    } else if let Some(b) = bindings.get(":bkid") {
        Ok(b.value.to::<BlockId>()?.0)
    } else if let Some(hash) = bindings.get(":hash") {
        query_service
            .get_block_id_by_hash(&hash.value.to::<Hash>()?.0)
            .await
            .map_err(server_error)
    } else {
        // latest
        Ok(query_service.num_blocks().await.map_err(server_error)? - 1)
    }
}

fn block_hash(block: &ElaboratedBlock) -> Hash {
    Hash(block.hash().as_ref().to_vec())
}

pub fn dummy_url_eval(
    route_pattern: &str,
    bindings: &HashMap<String, RouteBinding>,
) -> Result<tide::Response, tide::Error> {
    Ok(tide::Response::builder(200)
        .body(tide::Body::from_string(format!(
            "<!DOCTYPE html>
<html lang='en'>
  <head>
    <meta charset='utf-8'>
    <title>{}</title>
    <link rel='stylesheet' href='style.css'>
    <script src='script.js'></script>
  </head>
  <body>
    <h1>{}</h1>
    <p>{:?}</p>
  </body>
</html>",
            route_pattern.split_once('/').unwrap().0,
            route_pattern,
            bindings
        )))
        .content_type(tide::http::mime::HTML)
        .build())
}

////////////////////////////////////////////////////////////////////////////////
// Endpoints
//
// Each endpoint function handles one API endpoint, returning an instance of
// Serialize (or an error). The main entrypoint, dispatch_url, is in charge of
// serializing the endpoint responses according to the requested content type
// and building a Response object.
//

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Available,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
}

async fn healthcheck() -> Result<HealthCheck, tide::Error> {
    Ok(HealthCheck {
        status: HealthStatus::Available,
    })
}

async fn get_info(
    query_service: &(impl QueryService + Sync),
) -> Result<LedgerSummary, tide::Error> {
    query_service.get_summary().await.map_err(server_error)
}

async fn get_block_count(query_service: &(impl QueryService + Sync)) -> Result<usize, tide::Error> {
    let info = query_service.get_summary().await.map_err(server_error)?;
    Ok(info.num_blocks)
}

async fn get_block(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<CommittedBlock, tide::Error> {
    let index = block_index(bindings, query_service).await?;

    // Get the block and the validator state that resulted from applying this block.
    let transition = query_service.get_block(index).await.map_err(server_error)?;
    // The block numbered `index` is the block which was applied to the `index` state. Therefore,
    // the next state (the one that resulted from this block) is `index + 1`.
    let state = query_service
        .get_snapshot(index + 1, true, true)
        .await
        .map_err(server_error)?
        .state;

    Ok(CommittedBlock {
        id: BlockId(index),
        index,
        hash: block_hash(&transition.block),
        state_commitment: state.commit(),
        transactions: izip!(
            transition.block.block.0,
            transition.block.proofs,
            transition.block.memos,
            transition.uids,
            transition.block.signatures,
        )
        .enumerate()
        .map(
            |(i, (tx, proofs, memos, uids, signatures))| CommittedTransaction {
                id: TransactionId(BlockId(index), i),
                data: tx,
                proofs,
                output_uids: uids,
                output_memos: memos,
                memos_signature: signatures,
            },
        )
        .collect(),
    })
}

async fn get_block_id(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<BlockId, tide::Error> {
    let index = block_index(bindings, query_service).await?;
    Ok(BlockId(index))
}

async fn get_block_hash(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<Hash, tide::Error> {
    let index = block_index(bindings, query_service).await?;
    let block = query_service
        .get_block(index)
        .await
        .map_err(server_error)?
        .block;
    Ok(block_hash(&block))
}

async fn get_transaction(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<CommittedTransaction, tide::Error> {
    let TransactionId(block_id, tx_id) = bindings[":txid"].value.to()?;

    // First get the block containing the transaction.
    let LedgerTransition {
        mut block,
        mut uids,
        ..
    } = query_service
        .get_block(block_id.0)
        .await
        .map_err(server_error)?;

    // Extract the transaction and associated data from the block.
    if tx_id >= block.block.0.len() {
        return Err(tide::Error::from_str(
            StatusCode::BadRequest,
            "invalid transaction id",
        ));
    }
    let tx = block.block.0.swap_remove(tx_id);
    let proofs = block.proofs.swap_remove(tx_id);
    let memos = block.memos.swap_remove(tx_id);
    let signature = block.signatures.swap_remove(tx_id);
    let uids = uids.swap_remove(tx_id);

    Ok(CommittedTransaction {
        id: TransactionId(block_id, tx_id),
        data: tx,
        proofs,
        output_uids: uids,
        output_memos: memos,
        memos_signature: signature,
    })
}

async fn get_unspent_record(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<UnspentRecord, tide::Error> {
    if bindings[":mempool"].value.as_boolean()? {
        return Err(tide::Error::from_str(
            StatusCode::NotImplemented,
            "mempool queries unimplemented",
        ));
    }

    let TransactionId(block_id, tx_id) = bindings[":txid"].value.to()?;
    let output_index = bindings[":output_index"].value.as_index()?;

    // First get the block containing the transaction.
    let LedgerTransition { block, uids, .. } = query_service
        .get_block(block_id.0)
        .await
        .map_err(server_error)?;

    // Extract the transaction and associated data from the block.
    if tx_id >= block.block.0.len() {
        return Err(tide::Error::from_str(
            StatusCode::BadRequest,
            "invalid transaction id",
        ));
    }
    let tx = &block.block.0[tx_id];

    // Extract data about the requested output from the transaction.
    if output_index >= tx.output_len() {
        return Err(tide::Error::from_str(
            StatusCode::BadRequest,
            "invalid output index",
        ));
    }
    let comm = tx.output_commitments()[output_index];
    let uid = uids[tx_id][output_index];
    let memo = block.memos[tx_id][output_index].clone();
    Ok(UnspentRecord {
        commitment: comm,
        uid,
        memo: Some(memo),
    })
}

async fn get_snapshot(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<LedgerSnapshot, tide::Error> {
    let index = match bindings.get(":index") {
        Some(ix) => ix.value.as_index()?,
        None => {
            // No :index parameter indicates they want the latest snapshot.
            let LedgerSummary { num_blocks, .. } =
                query_service.get_summary().await.map_err(server_error)?;
            // Since block represent state transitions, there is a block in between each pair of
            // snapshots, and so the index of the last snapshot is one greater than the index of the
            // last block, or, equal to the total number of blocks.
            num_blocks
        }
    };
    let sparse = bindings[":sparse"].value.as_boolean()?;
    query_service
        .get_snapshot(index, sparse, sparse)
        .await
        .map_err(server_error)
}

async fn get_state_comm(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<LedgerStateCommitment, tide::Error> {
    let index = match bindings.get(":index") {
        Some(ix) => ix.value.as_index()?,
        None => {
            // No :index parameter indicates they want the latest snapshot.
            let LedgerSummary { num_blocks, .. } =
                query_service.get_summary().await.map_err(server_error)?;
            // Since block represent state transitions, there is a block in between each pair of
            // snapshots, and so the index of the last snapshot is one greater than the index of the
            // last block, or, equal to the total number of blocks.
            num_blocks
        }
    };
    let snapshot = query_service
        .get_snapshot(index, true, true)
        .await
        .map_err(server_error)?;
    Ok(snapshot.state.commit())
}

async fn get_nullifier(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<NullifierProof, tide::Error> {
    let (spent, proof) = query_service
        .nullifier_proof(
            bindings[":root"].value.to()?,
            bindings[":nullifier"].value.to()?,
        )
        .await
        .map_err(server_error)?;
    Ok(NullifierProof { spent, proof })
}

async fn get_event(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<LedgerEvent<EspressoLedger>, tide::Error> {
    let index = bindings[":index"].value.as_index()? as u64;
    let mut events = query_service.subscribe(index).await;
    events.next().await.ok_or_else(|| {
        tide::Error::from_str(StatusCode::InternalServerError, "event stream terminated")
    })
}

async fn subscribe(
    req: tide::Request<WebState>,
    conn: WebSocketConnection,
    bindings: &HashMap<String, RouteBinding>,
) -> Result<(), tide::Error> {
    let response_type = best_response_type(
        &mut Accept::from_headers(&req)?,
        &[mime::JSON, mime::BYTE_STREAM],
    )?;
    let index = bindings[":index"].value.as_index()? as u64;
    let mut events = req.state().node.read().await.subscribe(index).await;
    while let Some(event) = events.next().await {
        event!(Level::INFO, "broadcast event {}", <&str>::from(&event));
        if response_type == mime::JSON {
            conn.send_json(&event).await?;
        } else if response_type == mime::BYTE_STREAM {
            conn.send_bytes(bincode::serialize(&event)?).await?;
        } else {
            unreachable!();
        }
    }
    Ok(())
}

pub async fn dispatch_url(
    req: tide::Request<WebState>,
    route_pattern: &str,
    bindings: &HashMap<String, RouteBinding>,
) -> Result<tide::Response, tide::Error> {
    let first_segment = route_pattern
        .split_once('/')
        .unwrap_or((route_pattern, ""))
        .0;
    let key = ApiRouteKey::from_str(first_segment).expect("Unknown route");
    let query_service_guard = req.state().node.read().await;
    let query_service = &*query_service_guard;
    match key {
        ApiRouteKey::getblock => response(&req, get_block(bindings, query_service).await?),
        ApiRouteKey::getblockcount => response(&req, get_block_count(query_service).await?),
        ApiRouteKey::getblockhash => response(&req, get_block_hash(bindings, query_service).await?),
        ApiRouteKey::getblockid => response(&req, get_block_id(bindings, query_service).await?),
        ApiRouteKey::getevent => response(&req, get_event(bindings, query_service).await?),
        ApiRouteKey::getinfo => response(&req, get_info(query_service).await?),
        ApiRouteKey::getmempool => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::gettransaction => {
            response(&req, get_transaction(bindings, query_service).await?)
        }
        ApiRouteKey::getunspentrecord => {
            response(&req, get_unspent_record(bindings, query_service).await?)
        }
        ApiRouteKey::getunspentrecordsetinfo => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getsnapshot => response(&req, get_snapshot(bindings, query_service).await?),
        ApiRouteKey::getnullifier => response(&req, get_nullifier(bindings, query_service).await?),
        ApiRouteKey::getstatecomm => response(&req, get_state_comm(bindings, query_service).await?),
        ApiRouteKey::healthcheck => response(&req, healthcheck().await?),
        _ => Err(tide::Error::from_str(
            StatusCode::InternalServerError,
            "server called dispatch_url with an unsupported route; perhaps the route has not \
            been implemented, or requires a different kind of connection like a WebSocket",
        )),
    }
}

pub async fn dispatch_web_socket(
    req: tide::Request<WebState>,
    conn: WebSocketConnection,
    route_pattern: &str,
    bindings: &HashMap<String, RouteBinding>,
) -> Result<(), tide::Error> {
    let first_segment = route_pattern
        .split_once('/')
        .unwrap_or((route_pattern, ""))
        .0;
    let key = ApiRouteKey::from_str(first_segment).expect("Unknown route");
    match key {
        ApiRouteKey::subscribe => subscribe(req, conn, bindings).await,
        _ => Err(tide::Error::from_str(
            StatusCode::InternalServerError,
            "server called dispatch_web_socket with an unsupported route",
        )),
    }
}
