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
use clap::{Args, Subcommand};
use espresso_metastate_api::api as metastate;
use futures::Future;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Display;
use std::io;
use tide_disco::{App, StatusCode};

#[derive(Args)]
pub struct Options {
    #[clap(short, long, env = "ESPRESSO_ESQS_PORT")]
    pub port: u16,

    #[clap(flatten)]
    pub metastate: metastate::Options,
}

#[derive(Subcommand)]
pub enum Command {
    Esqs(Options),
}

#[derive(Clone, Debug, Snafu, Deserialize, Serialize)]
pub enum ApiError {
    Metastate { source: metastate::Error },
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

impl From<metastate::Error> for ApiError {
    fn from(source: metastate::Error) -> Self {
        Self::Metastate { source }
    }
}

pub fn init_server(
    command: &Command,
    data_source: Arc<RwLock<QueryData>>,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let Command::Esqs(opt) = command;
    let metastate_api = metastate::define_api(&opt.metastate).map_err(io_error)?;

    let mut app = App::<_, ApiError>::with_state(data_source);
    app.with_version(env!("CARGO_PKG_VERSION").parse().unwrap())
        .register_module("metastate", metastate_api)
        .map_err(io_error)?;

    let port = opt.port;
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
