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

use crate::data_source::CatchUpDataSource;
use clap::Args;
use derive_more::From;
use futures::{stream::iter, FutureExt, StreamExt, TryFutureExt};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::path::PathBuf;
use tide_disco::{
    api::{Api, ApiError},
    method::ReadState,
    RequestError, StatusCode,
};

#[derive(Args)]
pub struct Options {
    #[clap(long = "catchup-api-path", env = "ESPRESSO_CATCHUP_API_PATH")]
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
    for<'a> &'a <State as ReadState>::State: Send + Sync + CatchUpDataSource,
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
        .get("get_events_since", |req, state| {
            async move {
                let first = req.integer_param("first")?;
                if first >= state.len() {
                    return Ok(vec![]);
                }
                let iter = state.get_nth_event_iter(first);
                let count = req.integer_param("count")?;
                let events = iter.take(count);
                Ok(events.collect())
            }
            .boxed()
        })?
        .stream("subscribe_for_events", |req, state| {
            async move {
                let mut first = req.integer_param("first")?;
                let (prefix, receiver) = state
                    .read(|state| {
                        async move {
                            let prefix = if first >= state.len() {
                                vec![]
                            } else {
                                state.get_nth_event_iter(first).collect()
                            };
                            (prefix, state.subscribe())
                        }
                        .boxed()
                    })
                    .await;
                // We will yield all the events we already have buffered, then subscribe to future
                // events starting from there.
                first += prefix.len();
                Ok(iter(prefix)
                    .map(Ok)
                    .chain(receiver.filter_map(move |(i, e)| async move {
                        if i >= first {
                            Some(Ok(e))
                        } else {
                            None
                        }
                    })))
            }
            .try_flatten_stream()
            .boxed()
        })?;
    Ok(api)
}
