// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use crate::data_source::ValidatorDataSource;
use clap::Args;
use derive_more::From;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::{ReadState, WriteState},
    RequestError, StatusCode,
};

#[derive(Args, Default)]
pub struct Options {
    #[arg(long = "validator-api-path", env = "ESPRESSO_VALIDATOR_API_PATH")]
    pub api_path: Option<PathBuf>,
}

#[derive(Clone, Debug, From, Snafu, Deserialize, Serialize)]
pub enum Error {
    Request {
        source: RequestError,
    },

    #[from(ignore)]
    Submission {
        reason: String,
    },
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Request { .. } => StatusCode::BadRequest,
            Self::Submission { .. } => StatusCode::InternalServerError,
        }
    }
}

pub fn define_api<State>(options: &Options) -> Result<Api<State, Error>, ApiError>
where
    State: 'static + Send + Sync + WriteState,
    <State as ReadState>::State: Send + Sync + ValidatorDataSource,
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
        .post("submit", |req, state| {
            async move {
                let txn = req.body_auto()?;
                state.submit(txn).await.map_err(|source| Error::Submission {
                    reason: source.to_string(),
                })
            }
            .boxed()
        })?;
    Ok(api)
}
