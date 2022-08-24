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

use crate::{data_source::AvailabilityDataSource, query_data::RecordQueryData};
use clap::Args;
use derive_more::From;
use espresso_core::state::{BlockCommitment, TransactionCommitment};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::ReadState,
    RequestError, RequestParams, StatusCode,
};

#[derive(Args)]
pub struct Options {
    #[clap(long = "availability-api-path", env = "ESPRESSO_AVAILABILITY_API_PATH")]
    pub api_path: Option<PathBuf>,
}

#[derive(Clone, Debug, From, Snafu, Deserialize, Serialize)]
pub enum Error {
    Request {
        source: RequestError,
    },

    #[from(ignore)]
    #[snafu(display("the requested block hash {} does not exist", hash))]
    UnknownBlockHash {
        hash: BlockCommitment,
    },

    #[from(ignore)]
    #[snafu(display("the requested transaction hash {} does not exist", hash))]
    UnknownTransactionHash {
        hash: TransactionCommitment,
    },

    #[from(ignore)]
    #[snafu(display("the requested record UID {} does not exist", uid))]
    UnknownRecordUid {
        uid: u64,
    },

    #[from(ignore)]
    #[snafu(display("a block with the requested ID {} does not exist", block_id))]
    InvalidBlockId {
        block_id: u64,
    },

    #[from(ignore)]
    #[snafu(display(
        "block {} does not have a transaction with the requested ID {}",
        block_id,
        txn_id
    ))]
    InvalidTransactionId {
        block_id: u64,
        txn_id: u64,
    },

    #[from(ignore)]
    #[snafu(display(
        "transaction {}/{} does not have an output with the requested index {}",
        block_id,
        txn_id,
        output_index,
    ))]
    InvalidRecordId {
        block_id: u64,
        txn_id: u64,
        output_index: u64,
    },
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Request { .. } => StatusCode::BadRequest,
            Self::UnknownBlockHash { .. } => StatusCode::BadRequest,
            Self::UnknownTransactionHash { .. } => StatusCode::BadRequest,
            Self::UnknownRecordUid { .. } => StatusCode::BadRequest,
            Self::InvalidBlockId { .. } => StatusCode::BadRequest,
            Self::InvalidTransactionId { .. } => StatusCode::BadRequest,
            Self::InvalidRecordId { .. } => StatusCode::BadRequest,
        }
    }
}

/// Extract a block index from request parameters in a consistent way across endpoints.
///
/// There are 2 ways that a block can be specified:
/// * by its index (an `Integer` parameter named `:block_id`), in which case this function just
///   returns the index
/// * by its hash (a `TaggedBase64` parameter named `:hash`, usually prefixed by a literal `hash`
///   route segment) in which case we look up the hash in the hash-to-index table in `state`
fn block_index<State>(req: &RequestParams, state: State) -> Result<usize, Error>
where
    State: AvailabilityDataSource,
{
    if let Some(id) = req.opt_integer_param("block_id")? {
        Ok(id)
    } else {
        let hash = req.blob_param("hash")?;
        Ok(state
            .get_block_index_by_hash(hash)
            .context(UnknownBlockHashSnafu { hash })? as usize)
    }
}

pub fn define_api<State>(options: &Options) -> Result<Api<State, Error>, ApiError>
where
    State: 'static + Send + Sync + ReadState,
    for<'a> &'a <State as ReadState>::State: Send + Sync + AvailabilityDataSource,
{
    let mut api = match &options.api_path {
        Some(path) => Api::<State, Error>::from_file(path)?,
        None => {
            let toml = toml::from_str(include_str!("../api/api.toml")).map_err(|err| {
                ApiError::CannotReadToml {
                    reason: err.to_string(),
                }
            })?;
            Api::<State, Error>::new(toml)?
        }
    };
    api.with_version(env!("CARGO_PKG_VERSION").parse().unwrap())
        .get("getblock", |req, state| {
            async move {
                let id = block_index(&req, state)?;
                state
                    .get_nth_block_iter(0)
                    .as_ref()
                    .get(id as usize)
                    .context(InvalidBlockIdSnafu {
                        block_id: id as u64,
                    })
                    .cloned()
            }
            .boxed()
        })?
        .get("getstate", |req, state| {
            async move {
                let id = block_index(&req, state)?;
                state
                    .get_nth_state_iter(0)
                    .as_ref()
                    .get(id)
                    .context(InvalidBlockIdSnafu {
                        block_id: id as u64,
                    })
                    .cloned()
            }
            .boxed()
        })?
        .get("getstatecomm", |req, state| {
            async move {
                let id = block_index(&req, state)?;
                Ok(state
                    .get_nth_state_iter(0)
                    .as_ref()
                    .get(id)
                    .context(InvalidBlockIdSnafu {
                        block_id: id as u64,
                    })?
                    .commitment)
            }
            .boxed()
        })?
        .get("gettransaction", |req, state| {
            async move {
                let (block_id, txn_id) = if let Some(hash) = req.opt_blob_param("hash")? {
                    state
                        .get_txn_index_by_hash(hash)
                        .context(UnknownTransactionHashSnafu { hash })?
                } else {
                    (req.integer_param("block_id")?, req.integer_param("txn_id")?)
                };
                let blocks = state.get_nth_block_iter(0);
                let block = blocks
                    .as_ref()
                    .get(block_id as usize)
                    .context(InvalidBlockIdSnafu { block_id })?;
                block
                    .transaction(txn_id as usize)
                    .context(InvalidTransactionIdSnafu { block_id, txn_id })
            }
            .boxed()
        })?
        .get("getrecord", |req, state| {
            async move {
                let (block_id, txn_id, output_index) =
                    if let Some(uid) = req.opt_integer_param("uid")? {
                        state
                            .get_record_index_by_uid(uid)
                            .context(UnknownRecordUidSnafu { uid })?
                    } else {
                        (
                            req.integer_param("block_id")?,
                            req.integer_param("txn_id")?,
                            req.integer_param("output_index")?,
                        )
                    };
                let blocks = state.get_nth_block_iter(0);
                let block = blocks
                    .as_ref()
                    .get(block_id as usize)
                    .context(InvalidBlockIdSnafu { block_id })?;
                let commitment = *block
                    .raw_block
                    .block
                    .0
                    .get(txn_id as usize)
                    .context(InvalidTransactionIdSnafu { block_id, txn_id })?
                    .output_commitments()
                    .get(output_index as usize)
                    .context(InvalidRecordIdSnafu {
                        block_id,
                        txn_id,
                        output_index,
                    })?;
                let uid = block.records_from + output_index;
                Ok(RecordQueryData {
                    commitment,
                    uid,
                    block_id,
                    txn_id,
                    output_index,
                })
            }
            .boxed()
        })?;
    Ok(api)
}
