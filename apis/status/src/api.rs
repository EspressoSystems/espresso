// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use crate::{data_source::StatusDataSource, query_data::*};
use clap::Args;
use derive_more::From;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::ReadState,
    RequestError, StatusCode,
};

#[derive(Args, Default)]
pub struct Options {
    #[arg(long = "status-api-path", env = "ESPRESSO_STATUS_API_PATH")]
    pub api_path: Option<PathBuf>,
}

#[derive(Clone, Debug, From, Snafu, Deserialize, Serialize)]
pub enum Error {
    Request { source: RequestError },
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Request { .. } => StatusCode::BadRequest,
        }
    }
}

pub fn define_api<State>(options: &Options) -> Result<Api<State, Error>, ApiError>
where
    State: 'static + Send + Sync + ReadState,
    <State as ReadState>::State: Sync + StatusDataSource,
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
        .get("list_peers", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(status.peer_list.clone())
            }
            .boxed()
        })?
        .get("latest_block_id", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(status.latest_block_id)
            }
            .boxed()
        })?
        .get("mempool_info", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(status.mempool_info.clone())
            }
            .boxed()
        })?
        .get("success_rate", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(status.decided_block_count as f64 / status.proposed_block_count as f64)
            }
            .boxed()
        })?
        .get("throughput", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(Throughput {
                    blocks_finalized: status.decided_block_count,
                    transactions_finalized: status.cumulative_txn_count,
                    bytes_finalized: status.cumulative_size,
                    time_operational: status.time_operational,
                })
            }
            .boxed()
        })?
        .get("location", |_, state| {
            async move {
                let location = state.get_location();
                Ok(location.clone())
            }
            .boxed()
        })?
        .get("records", |_, state| {
            async move {
                let status = state.get_validator_status();
                Ok(RecordSetInfo {
                    total: status.record_count,
                    spent: status.nullifier_count,
                    unspent: status.record_count - status.nullifier_count,
                })
            }
            .boxed()
        })?;
    Ok(api)
}
