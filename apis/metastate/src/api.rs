// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use crate::data_source::MetaStateDataSource;
use clap::Args;
use derive_more::From;
use espresso_core::state::SetMerkleProof;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::ReadState,
    RequestError, StatusCode,
};

#[derive(Args, Default)]
pub struct Options {
    #[arg(long = "metastate-api-path", env = "ESPRESSO_METASTATE_API_PATH")]
    pub api_path: Option<PathBuf>,
}

#[derive(Clone, Debug, From, Snafu, Deserialize, Serialize)]
pub enum Error {
    Request { source: RequestError },
    InvalidBlockId { block_id: u64 },
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Request { .. } => StatusCode::BadRequest,
            Self::InvalidBlockId { .. } => StatusCode::BadRequest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierCheck {
    pub spent: bool,
    pub proof: SetMerkleProof,
}

pub fn define_api<State>(options: &Options) -> Result<Api<State, Error>, ApiError>
where
    State: 'static + Send + Sync + ReadState,
    <State as ReadState>::State: Sync + MetaStateDataSource,
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
        .get("check_nullifier", |req, state| {
            async move {
                let block_id = req.integer_param("block_id")?;
                let nullifier = req.blob_param("nullifier")?;
                let (spent, proof) = state
                    .get_nullifier_proof_for(block_id, nullifier)
                    .context(InvalidBlockIdSnafu { block_id })?;
                Ok(NullifierCheck { spent, proof })
            }
            .boxed()
        })?;
    Ok(api)
}
