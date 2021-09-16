// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use jf_primitives::{jubjub_dsa::Signature, merkle_tree::NodeValue};
use jf_txn::structs::{Nullifier, ReceiverMemo, RecordCommitment};
use jf_txn::TransactionNote;
use phaselock::BlockContents;
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter, EnumString};
use tagged_base64::TaggedBase64;
use tide::prelude::*;
use tide::StatusCode;
use tracing::{event, Level};
use zerok_lib::node::{LedgerTransition, QueryService};

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

    pub fn as_b64(&self, tag: &str) -> Result<Vec<u8>, tide::Error> {
        if let Identifier(b64) = self {
            if b64.tag() == tag {
                Ok(b64.value())
            } else {
                Err(tide::Error::from_str(
                    StatusCode::BadRequest,
                    format!("expected base 64 with tag {}, got tag {}", tag, b64.tag()),
                ))
            }
        } else {
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                format!("expected base 64 with tag {}, got {:?}", tag, self),
            ))
        }
    }

    pub fn as_bkid(&self) -> Result<usize, tide::Error> {
        let bytes = self.as_b64("BK")?;
        bincode::deserialize(&bytes).map_err(server_error)
    }

    pub fn as_txid(&self) -> Result<(usize, usize), tide::Error> {
        let bytes = self.as_b64("TX")?;
        bincode::deserialize(&bytes).map_err(server_error)
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

    pub fn as_block_hash(&self) -> Result<Vec<u8>, tide::Error> {
        self.as_b64("HASH")
    }
}

// Helpers for converting binary data to JSON values. Most types can be converted to a JSON value by
// serializing to a blob and then encoding the binary data as tagged base 64.
mod js {
    use super::*;
    pub use serde_json::Value;

    pub fn b64(tag: &str, value: &[u8]) -> Result<Value, tide::Error> {
        Ok(Value::from(tagged_base64::to_string(
            &TaggedBase64::new(tag, value).map_err(|_| {
                tide::Error::from_str(
                    StatusCode::InternalServerError,
                    "failed to convert to tagged base 64",
                )
            })?,
        )))
    }

    pub fn bkid(block_id: usize) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(&block_id).map_err(server_error)?;
        b64("BK", &bytes)
    }

    pub fn txid(block_id: usize, tx_offset: usize) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(&(block_id, tx_offset)).map_err(server_error)?;
        b64("TX", &bytes)
    }

    pub fn nullifier(n: &Nullifier) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(n).map_err(server_error)?;
        b64("NUL", &bytes)
    }

    pub fn record_comm(c: &RecordCommitment) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(c).map_err(server_error)?;
        b64("REC", &bytes)
    }

    pub fn node_value(n: &NodeValue) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(n).map_err(server_error)?;
        b64("HASH", &bytes)
    }

    pub fn memo(m: &ReceiverMemo) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(m).map_err(server_error)?;
        b64("MEMO", &bytes)
    }

    pub fn signature(s: &Signature) -> Result<Value, tide::Error> {
        let bytes = bincode::serialize(s).map_err(server_error)?;
        b64("SIG", &bytes)
    }
}

fn server_error(err: impl std::error::Error + Debug + Send + Sync + 'static) -> tide::Error {
    event!(
        Level::ERROR,
        "internal error while processing request: {:?}",
        err
    );
    tide::Error::new(StatusCode::InternalServerError, err)
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
    getinfo,
    getmempool,
    gettransaction,
    getunspentrecord,
    getunspentrecordsetinfo,
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
            route_pattern.to_string(),
            bindings
        )))
        .content_type(tide::http::mime::HTML)
        .build())
}

pub async fn get_block(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    // Get a block index from whatever form of block identifier was used in the URL.
    let index = if let Some(b) = bindings.get(":index") {
        b.value.as_index()?
    } else if let Some(b) = bindings.get(":bkid") {
        b.value.as_bkid()?
    } else if let Some(hash) = bindings.get(":hash") {
        query_service
            .get_block_id_by_hash(&hash.value.as_block_hash()?)
            .await
            .map_err(server_error)?
    } else {
        // getblock/latest
        query_service.num_blocks().await.map_err(server_error)? - 1
    };

    // Get the block and the validator state that resulted from applying this block.
    let block = query_service
        .get_block(index)
        .await
        .map_err(server_error)?
        .block;
    // The block numbered `index` is the block which was applied to the `index` state. Therefore,
    // the next state (the one that resulted from this block) is `index + 1`.
    let state = query_service
        .get_snapshot(index + 1)
        .await
        .map_err(server_error)?
        .state;

    Ok(tide::Response::from(json!({
        "id": js::bkid(index)?,
        "index": index,
        "hash": js::b64("HASH", block.hash().as_ref())?,
        "state_commitment": js::b64("HASH", &state.commit())?,
        "transaction_data": block.block.0.iter().enumerate().map(|(i, _)| {
            Ok(json!({
                "id": js::txid(index, i)?,
            }))
        }).collect::<Result<Vec<_>, tide::Error>>()?,
    })))
}

pub async fn get_transaction(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<tide::Response, tide::Error> {
    let (block_id, tx_id) = bindings[":txid"].value.as_txid()?;

    // First get the block containing the transaction.
    let LedgerTransition {
        block, memos, uids, ..
    } = query_service
        .get_block(block_id)
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
    let uids = &uids[tx_id];
    // The memos and signature may not be provided yet for this transaction, so memos[tx_id] may be
    // None. We want to work with the memos and the signature separately, and in fact we want to
    // work with each memo as a separate entity which may or may not be present, even though all are
    // present or none are, since we will attach each memo to a separate transaction output. So we
    // explode the single Option<(Vec<Memo>, Signature)> into a Vec<Option<Memo>> and an
    // Option<Signature>.
    let (memos, sig) = match &memos[tx_id] {
        Some((memos, sig)) => (memos.iter().map(Some).collect::<Vec<_>>(), Some(sig)),
        None => (vec![None; tx.output_len()], None),
    };

    Ok(tide::Response::from(json!({
        "id": js::txid(block_id, tx_id)?,
        "type": match tx {
            TransactionNote::Transfer(_) => "transfer",
            TransactionNote::Mint(_) => "mint",
            TransactionNote::Freeze(_) => "freeze",
        },
        "fee": match tx {
            TransactionNote::Transfer(xfr) => xfr.aux_info.fee,
            TransactionNote::Mint(mint) => mint.aux_info.fee,
            TransactionNote::Freeze(freeze) => freeze.aux_info.fee,
        },
        "inputs": tx.nullifiers().into_iter().map(|n| {
            js::nullifier(&n)
        }).collect::<Result<Vec<_>, tide::Error>>()?,
        "outputs": tx.output_commitments().into_iter().zip(uids).zip(memos).map(|((comm, uid), memo)| {
            Ok(json!({
                "commitment": js::record_comm(&comm)?,
                "uid": uid,
                "memo": match memo {
                    Some(memo) => Some(js::memo(memo)?),
                    None => None,
                },
            }))
        }).collect::<Result<Vec<_>, tide::Error>>()?,
        "memos_signature": match sig {
            Some(sig) => Some(js::signature(sig)?),
            None => None,
        },
        "merkle_root": js::node_value(&tx.merkle_root())?,
    })))
}

pub async fn dispatch_url(
    route_pattern: &str,
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let first_segment = route_pattern.split_once('/').unwrap().0;
    let key = ApiRouteKey::from_str(first_segment).expect("Unknown route");
    match key {
        ApiRouteKey::getblock => get_block(bindings, query_service).await,
        ApiRouteKey::getblockcount => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getblockhash => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getblockid => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getinfo => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getmempool => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::gettransaction => get_transaction(bindings, query_service).await,
        ApiRouteKey::getunspentrecord => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getunspentrecordsetinfo => dummy_url_eval(route_pattern, bindings),
    }
}
