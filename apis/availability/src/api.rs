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
    data_source::AvailabilityDataSource,
    query_data::{BlockQueryData, RecordQueryData, StateQueryData},
};
use clap::Args;
use derive_more::From;
use espresso_core::state::{BlockCommitment, TransactionCommitment};
use futures::FutureExt;
use hotshot_types::data::QuorumCertificate;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::ReadState,
    RequestError, RequestParams, StatusCode,
};

#[derive(Args, Default)]
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

    #[from(ignore)]
    #[snafu(display("this server does not have block {}", block_id))]
    MissingBlock {
        block_id: u64,
    },

    #[from(ignore)]
    #[snafu(display("this server does not have the state from block {}", block_id))]
    MissingState {
        block_id: u64,
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
            Self::MissingBlock { .. } => StatusCode::NotFound,
            Self::MissingState { .. } => StatusCode::NotFound,
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
fn block_index<State>(req: &RequestParams, state: State) -> Result<u64, Error>
where
    State: AvailabilityDataSource,
{
    if let Some(id) = req.opt_integer_param("block_id")? {
        Ok(id)
    } else {
        let hash = req.blob_param("hash")?;
        Ok(state
            .get_block_index_by_hash(hash)
            .context(UnknownBlockHashSnafu { hash })?)
    }
}

fn get_block<State>(state: State, block_id: u64) -> Result<BlockQueryData, Error>
where
    State: AvailabilityDataSource,
{
    state
        .get_nth_block_iter(block_id as usize)
        .next()
        .context(InvalidBlockIdSnafu { block_id })?
        .context(MissingBlockSnafu { block_id })
}

fn get_state<State>(state: State, block_id: u64) -> Result<StateQueryData, Error>
where
    State: AvailabilityDataSource,
{
    state
        .get_nth_state_iter(block_id as usize)
        .next()
        .context(InvalidBlockIdSnafu { block_id })?
        .context(MissingStateSnafu { block_id })
}

fn get_qcert<State>(state: State, block_id: u64) -> Result<QuorumCertificate, Error>
where
    State: AvailabilityDataSource,
{
    state
        .get_nth_qcert_iter(block_id as usize)
        .next()
        .context(InvalidBlockIdSnafu { block_id })?
        .context(MissingStateSnafu { block_id })
}

fn get_blocks_summary<State>(
    state: State,
    block_id: u64,
    count: u64,
) -> Result<BlockQueryData, Error>
where
    State: AvailabilityDataSource,
{
    for id in (block_id - count + 1..block_id + 1).rev() {
        let block_data = get_block(state,block_id)?;
        let state_data = get_state(state,block_id)?;
        let qcert_data = get_qcert(state,block_id)?;
        // let size
        let txn_count = block_data.txn_hashes.len();
        // let proposer = 
        let time = state_data.state.prev_commit_time;
        let records_from = block_data.records_from;
        let record_count = block_data.record_count;
        let view_number = get_qcert.view_number;
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
                get_block(state, id)
            }
            .boxed()
        })?
        .get("getstate", |req, state| {
            async move {
                let id = block_index(&req, state)?;
                get_state(state, id)
            }
            .boxed()
        })?
        .get("getstatecomm", |req, state| {
            async move {
                let id = block_index(&req, state)?;
                Ok(get_state(state, id)?.commitment)
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
                let block = get_block(state, block_id)?;
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
                let block = get_block(state, block_id)?;
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
        })?
        .get("getblockssummary", |req, state| {
            async move {
                let (block_id, count) =
                    (req.integer_param("block_id")?, req.integer_param("count")?);
                get_blocks_summary(state, block_id, count)
            }
            .boxed()
        })?;
    Ok(api)
}
