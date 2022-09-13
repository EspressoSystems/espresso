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

use crate::{Consensus, QueryData, UpdateQueryDataSourceTypesBinder};
use async_std::{
    sync::{Arc, RwLock},
    task::{spawn, JoinHandle},
};
use clap::{Args, Subcommand};
use derive_more::From;
use espresso_availability_api::api as availability;
use espresso_catchup_api::api as catchup;
use espresso_core::state::ElaboratedBlock;
use espresso_metastate_api::api as metastate;
use espresso_status_api::api as status;
use espresso_validator_api::api as validator;
use futures::stream::{unfold, StreamExt};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Display;
use std::io;
use tide_disco::{http::Url, App, StatusCode};
use validator_node::update_query_data_source::UpdateQueryDataSource;

#[derive(Args)]
pub struct Options {
    #[clap(short, long, env = "ESPRESSO_ESQS_PORT")]
    pub port: u16,

    #[clap(flatten)]
    pub availability: availability::Options,

    #[clap(flatten)]
    pub catchup: catchup::Options,

    #[clap(flatten)]
    pub metastate: metastate::Options,

    #[clap(flatten)]
    pub status: status::Options,

    #[clap(flatten)]
    pub validator: validator::Options,
}

impl Options {
    pub fn with_port(port: u16) -> Self {
        Self {
            port,
            availability: Default::default(),
            catchup: Default::default(),
            metastate: Default::default(),
            status: Default::default(),
            validator: Default::default(),
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    Esqs(Options),
}

impl Command {
    pub fn with_port(port: u16) -> Self {
        Self::Esqs(Options::with_port(port))
    }
}

#[derive(Clone, Debug, From, Snafu, Deserialize, Serialize)]
pub enum ApiError {
    Availability {
        source: availability::Error,
    },
    CatchUp {
        source: catchup::Error,
    },
    Metastate {
        source: metastate::Error,
    },
    Status {
        source: status::Error,
    },
    Validator {
        source: validator::Error,
    },
    #[from(ignore)]
    Internal {
        status: StatusCode,
        reason: String,
    },
}

impl tide_disco::Error for ApiError {
    fn catch_all(status: StatusCode, reason: String) -> Self {
        Self::Internal { status, reason }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Availability { source } => source.status(),
            Self::CatchUp { source } => source.status(),
            Self::Metastate { source } => source.status(),
            Self::Status { source } => source.status(),
            Self::Validator { source } => source.status(),
            Self::Internal { status, .. } => *status,
        }
    }
}

pub struct EsQS {
    port: u16,
    _updater: Arc<RwLock<UpdateQueryDataSource<UpdateQueryDataSourceTypesBinder>>>,
    _server: JoinHandle<io::Result<()>>,
}

impl EsQS {
    pub fn new(
        command: &Command,
        data_source: Arc<RwLock<QueryData>>,
        consensus: Consensus,
        genesis: ElaboratedBlock,
    ) -> io::Result<Self> {
        let Command::Esqs(opt) = command;
        let availability_api = availability::define_api(&opt.availability).map_err(io_error)?;
        let catchup_api = catchup::define_api(&opt.catchup).map_err(io_error)?;
        let metastate_api = metastate::define_api(&opt.metastate).map_err(io_error)?;
        let status_api = status::define_api(&opt.status).map_err(io_error)?;
        let validator_api = validator::define_api(&opt.validator).map_err(io_error)?;

        let mut app = App::<_, ApiError>::with_state(data_source.clone());
        app.with_version(env!("CARGO_PKG_VERSION").parse().unwrap())
            .register_module("availability", availability_api)
            .map_err(io_error)?
            .register_module("catchup", catchup_api)
            .map_err(io_error)?
            .register_module("metastate", metastate_api)
            .map_err(io_error)?
            .register_module("status", status_api)
            .map_err(io_error)?
            .register_module("validator", validator_api)
            .map_err(io_error)?;

        let port = opt.port;
        let server = spawn(async move {
            if let Err(err) = app.serve(format!("0.0.0.0:{}", port)).await {
                tracing::error!("EsQS exited due to {}", err);
                Err(err)
            } else {
                Ok(())
            }
        });
        let events = unfold(consensus, |mut consensus| async move {
            match consensus.next_event().await {
                Ok(event) => Some((event.event, consensus)),
                Err(err) => panic!("unexpected error from HotShotHandle::next_event: {:?}", err),
            }
        })
        .boxed();
        let updater = UpdateQueryDataSource::new(
            events,
            data_source.clone(),
            data_source.clone(),
            data_source.clone(),
            data_source.clone(),
            data_source,
            genesis,
        );

        Ok(Self {
            port,
            _updater: updater,
            _server: server,
        })
    }

    pub fn url(&self) -> Url {
        format!("http://localhost:{}", self.port).parse().unwrap()
    }

    pub async fn kill(self) {
        // There is unfortunately no way to kill the EsQS, since it is a Tide thread. We just leak
        // the underlying thread.
    }
}

fn io_error<E: Display>(source: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, source.to_string())
}
