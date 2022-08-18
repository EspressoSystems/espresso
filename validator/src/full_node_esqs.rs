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

use crate::QueryData;
use async_std::sync::{Arc, RwLock};
use espresso_metastate_api::api::MetastateApiError;
use futures::Future;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Display;
use std::fs;
use std::io;
use std::path::PathBuf;
use structopt::StructOpt;
use tide_disco::{App, StatusCode};

#[derive(StructOpt)]
pub struct Options {
    #[structopt(
        long = "esqs-port",
        env = "ESPRESSO_ESQS_PORT",
        requires = "metastate-api-path"
    )]
    pub port: Option<u16>,

    #[structopt(long, env = "ESPRESSO_METASTATE_API_PATH")]
    pub metastate_api_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Snafu, Deserialize, Serialize)]
pub enum ApiError {
    Metastate { source: MetastateApiError },
    Internal { status: StatusCode, reason: String },
}

impl tide_disco::Error for ApiError {
    fn catch_all(status: StatusCode, reason: String) -> Self {
        Self::Internal { status, reason }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Metastate { source } => source.status(),
            Self::Internal { status, .. } => *status,
        }
    }
}

impl From<MetastateApiError> for ApiError {
    fn from(source: MetastateApiError) -> Self {
        Self::Metastate { source }
    }
}

pub fn init_server(
    opt: &Options,
    data_source: Arc<RwLock<QueryData>>,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let port = match opt.port {
        Some(port) => port,
        None => return Err(io_error("port not specified")),
    };

    let metastate_api_toml =
        toml::from_slice(&fs::read(opt.metastate_api_path.as_ref().unwrap())?)?;
    let metastate_api = espresso_metastate_api::define_api(metastate_api_toml).map_err(io_error)?;

    let mut app = App::<_, ApiError>::with_state(data_source);
    app.with_version(env!("CARGO_PKG_VERSION").parse().unwrap())
        .register_module("metastate", metastate_api)
        .map_err(io_error)?;

    Ok(async move {
        if let Err(err) = app.serve(format!("0.0.0.0:{}", port)).await {
            tracing::error!("EsQS exited due to {}", err);
            Err(err)
        } else {
            Ok(())
        }
    })
}

fn io_error<E: Display>(source: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, source.to_string())
}
