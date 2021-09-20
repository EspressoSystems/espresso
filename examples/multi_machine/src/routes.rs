// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use crate::WebState;
use futures::prelude::*;
use jf_primitives::merkle_tree::NodePos;
use jf_txn::structs::{Nullifier, ReceiverMemo, RecordCommitment};
use jf_txn::TransactionNote;
use jf_txn::{MerklePath, NodeValue, Signature};
use phaselock::BlockContents;
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter, EnumString};
use tagged_base64::TaggedBase64;
use tide::prelude::*;
use tide::sse;
use tide::StatusCode;
use tracing::{event, Level};
use zerok_lib::canonical;
use zerok_lib::node::{LedgerEvent, LedgerTransition, QueryService};
use zerok_lib::ElaboratedBlock;

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
        canonical::deserialize(&bytes).map_err(server_error)
    }

    pub fn as_txid(&self) -> Result<(usize, usize), tide::Error> {
        let bytes = self.as_b64("TX")?;
        canonical::deserialize(&bytes).map_err(server_error)
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

    pub fn hash(bytes: &[u8]) -> Result<Value, tide::Error> {
        b64("HASH", bytes)
    }

    pub fn bkid(block_id: usize) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(&block_id).map_err(server_error)?;
        b64("BK", &bytes)
    }

    // Serialize a committed block, with references to the ledger such as the block's unique ID and
    // the IDs of its transactions.
    pub fn block(
        block: &ElaboratedBlock,
        block_id: usize,
        state_comm: &[u8],
    ) -> Result<Value, tide::Error> {
        Ok(json!({
            "id": bkid(block_id)?,
            "index": block_id,
            "hash": hash(block.hash().as_ref())?,
            "state_commitment": hash(state_comm)?,
            "transaction_data": block.block.0.iter().enumerate().map(|(i, _)| {
                Ok(json!({
                    "id": txid(block_id, i)?,
                }))
            }).collect::<Result<Vec<_>, tide::Error>>()?,
        }))
    }

    // Serialize an uncommitted block.
    pub fn block_contents(block: &ElaboratedBlock) -> Result<Value, tide::Error> {
        Ok(json!({
            "hash": hash(block.hash().as_ref())?,
            "transaction_data": block.block.0.iter().map(tx_contents).collect::<Result<Vec<_>, _>>()?,
        }))
    }

    pub fn txid(block_id: usize, tx_offset: usize) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(&(block_id, tx_offset)).map_err(server_error)?;
        b64("TX", &bytes)
    }

    pub fn tx_contents(tx: &TransactionNote) -> Result<Value, tide::Error> {
        Ok(json!({
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
                nullifier(&n)
            }).collect::<Result<Vec<_>, tide::Error>>()?,
            "outputs": tx.output_commitments().into_iter().map(|comm| Ok(json!({
                "commitment": record_comm(&comm)?
            }))).collect::<Result<Vec<_>, tide::Error>>()?,
            "merkle_root": node_value(&tx.merkle_root())?,
        }))
    }

    pub fn tx_output(
        comm: &RecordCommitment,
        uid: u64,
        memo: Option<&ReceiverMemo>,
    ) -> Result<Value, tide::Error> {
        Ok(json!({
            "commitment": record_comm(comm)?,
            "uid": uid,
            "memo": match memo {
                Some(memo) => Some(js::memo(memo)?),
                None => None,
            },
        }))
    }

    pub fn nullifier(n: &Nullifier) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(n).map_err(server_error)?;
        b64("NUL", &bytes)
    }

    pub fn record_comm(c: &RecordCommitment) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(c).map_err(server_error)?;
        b64("REC", &bytes)
    }

    pub fn node_value(n: &NodeValue) -> Result<Value, tide::Error> {
        hash(&canonical::serialize(n).map_err(server_error)?)
    }

    pub fn memo(m: &ReceiverMemo) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(m).map_err(server_error)?;
        b64("MEMO", &bytes)
    }

    pub fn signature(s: &Signature) -> Result<Value, tide::Error> {
        let bytes = canonical::serialize(s).map_err(server_error)?;
        b64("SIG", &bytes)
    }

    pub fn merkle_path(path: &MerklePath) -> Result<Value, tide::Error> {
        Ok(Value::from(
            path.nodes
                .iter()
                .map(|node| {
                    Ok(json!({
                        "sibling1": node_value(&node.sibling1)?,
                        "sibling2": node_value(&node.sibling2)?,
                        "pos": match node.pos {
                            NodePos::Left => "left",
                            NodePos::Middle => "middle",
                            NodePos::Right => "right",
                        }
                    }))
                })
                .collect::<Result<Vec<_>, tide::Error>>()?,
        ))
    }

    pub fn to_string(value: &Value) -> Result<String, tide::Error> {
        serde_json::ser::to_string(value).map_err(server_error)
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

async fn get_info(
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let info = query_service.get_summary().await.map_err(server_error)?;
    Ok(tide::Response::from(json!({
        "num_blocks": info.num_blocks,
        "num_records": info.num_records,
        //todo !jeb.bearer add more info
    })))
}

async fn get_block_count(
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let info = query_service.get_summary().await.map_err(server_error)?;
    Ok(tide::Response::from(json!(info.num_blocks)))
}

// Get a block index from whatever form of block identifier was used in the URL.
async fn block_index(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<usize, tide::Error> {
    if let Some(b) = bindings.get(":index") {
        b.value.as_index()
    } else if let Some(b) = bindings.get(":bkid") {
        b.value.as_bkid()
    } else if let Some(hash) = bindings.get(":hash") {
        query_service
            .get_block_id_by_hash(&hash.value.as_block_hash()?)
            .await
            .map_err(server_error)
    } else {
        // latest
        Ok(query_service.num_blocks().await.map_err(server_error)? - 1)
    }
}

async fn get_block(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let index = block_index(bindings, query_service).await?;

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

    Ok(tide::Response::from(js::block(
        &block,
        index,
        &state.commit(),
    )?))
}

async fn get_block_id(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let index = block_index(bindings, query_service).await?;
    Ok(tide::Response::from(js::bkid(index)?))
}

async fn get_block_hash(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &(impl QueryService + Sync),
) -> Result<tide::Response, tide::Error> {
    let index = block_index(bindings, query_service).await?;
    let block = query_service
        .get_block(index)
        .await
        .map_err(server_error)?
        .block;
    Ok(tide::Response::from(js::hash(block.hash().as_ref())?))
}

async fn get_transaction(
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
            js::tx_output(&comm, *uid, memo)
        }).collect::<Result<Vec<_>, tide::Error>>()?,
        "memos_signature": match sig {
            Some(sig) => Some(js::signature(sig)?),
            None => None,
        },
        "merkle_root": js::node_value(&tx.merkle_root())?,
    })))
}

async fn get_unspent_record(
    bindings: &HashMap<String, RouteBinding>,
    query_service: &impl QueryService,
) -> Result<tide::Response, tide::Error> {
    if bindings[":mempool"].value.as_boolean()? {
        return Err(tide::Error::from_str(
            StatusCode::NotImplemented,
            "mempool queries unimplemented",
        ));
    }

    let (block_id, tx_id) = bindings[":txid"].value.as_txid()?;
    let output_index = bindings[":output_index"].value.as_index()?;

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

    // Extract data about the requested output from the transaction.
    if output_index >= tx.output_len() {
        return Err(tide::Error::from_str(
            StatusCode::BadRequest,
            "invalid output index",
        ));
    }
    let comm = tx.output_commitments()[output_index];
    let uid = uids[tx_id][output_index];
    let memo = memos[tx_id]
        .as_ref()
        .map(|(memos, _sig)| &memos[output_index]);
    Ok(tide::Response::from(js::tx_output(&comm, uid, memo)?))
}

async fn subscribe(
    req: tide::Request<WebState>,
    bindings: &HashMap<String, RouteBinding>,
) -> Result<tide::Response, tide::Error> {
    let index = bindings[":index"].value.as_index()? as u64;
    Ok(sse::upgrade(req, move |req, sender| async move {
        let mut events = req.state().query_service.subscribe(index).await;
        while let Some(event) = events.next().await {
            match event {
                LedgerEvent::Commit(block, block_id, state_comm) => {
                    sender
                        .send(
                            "commit",
                            js::to_string(&js::block(&block, block_id as usize, &state_comm)?)?,
                            None,
                        )
                        .await?;
                }

                LedgerEvent::Reject(block, error) => {
                    use zerok_lib::ValidationError::*;
                    let error_msg = match error {
                        NullifierAlreadyExists { nullifier } => format!(
                            "the nullifier {} has already been spent",
                            js::to_string(&js::nullifier(&nullifier)?)?
                        ),
                        BadNullifierProof {} => String::from("bad nullifier proof"),
                        MissingNullifierProof {} => String::from("missing nullifier proof"),
                        ConflictingNullifiers {} => String::from("conflicting nullifiers"),
                        Failed {} => String::from("unknown validation failure"),
                        BadMerkleLength {} => String::from("bad merkle path length"),
                        BadMerkleLeaf {} => String::from("bad merkle path leaf"),
                        BadMerkleRoot {} => String::from("bad merkle root"),
                        BadMerklePath {} => String::from("bad merkle path"),
                        CryptoError { err } => format!("{}", err),
                        UnsupportedTransferSize {
                            num_inputs,
                            num_outputs,
                        } => format!(
                            "transfers with {} inputs and {} outputs are not supported",
                            num_inputs, num_outputs
                        ),
                        UnsupportedFreezeSize { num_inputs } => {
                            format!("freezes with {} inputs are not supported", num_inputs)
                        }
                    };

                    sender
                        .send(
                            "reject",
                            js::to_string(&json!({
                                "block": js::block_contents(&block)?,
                                "error": error_msg,
                            }))?,
                            None,
                        )
                        .await?
                }

                LedgerEvent::Memos(info) => {
                    sender
                        .send(
                            "memos",
                            serde_json::ser::to_string(
                                &info
                                    .into_iter()
                                    .map(|(memo, comm, uid, merkle_path)| {
                                        Ok(json!({
                                            "memo": js::memo(&memo)?,
                                            "commitment": js::record_comm(&comm)?,
                                            "uid": uid,
                                            "merkle_path": js::merkle_path(&merkle_path)?,
                                        }))
                                    })
                                    .collect::<Result<Vec<_>, tide::Error>>()?,
                            )?,
                            None,
                        )
                        .await?
                }
            }
        }
        Ok(())
    }))
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
    match key {
        ApiRouteKey::getblock => get_block(bindings, &req.state().query_service).await,
        ApiRouteKey::getblockcount => get_block_count(&req.state().query_service).await,
        ApiRouteKey::getblockhash => get_block_hash(bindings, &req.state().query_service).await,
        ApiRouteKey::getblockid => get_block_id(bindings, &req.state().query_service).await,
        ApiRouteKey::getinfo => get_info(&req.state().query_service).await,
        ApiRouteKey::getmempool => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::gettransaction => get_transaction(bindings, &req.state().query_service).await,
        ApiRouteKey::getunspentrecord => {
            get_unspent_record(bindings, &req.state().query_service).await
        }
        ApiRouteKey::getunspentrecordsetinfo => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::subscribe => subscribe(req, bindings).await,
    }
}
