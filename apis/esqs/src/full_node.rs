// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

//! Full node query service
//!
//! An instantiation of a Tide Disco service containing all possible query service modules, assuming
//! all the relevant data is available locally. This service assumes it is running in the same
//! process as an Espresso/HotShot instance. It provides the following API modules:
//! * [availability]
//! * [catchup]
//! * [metastate]
//! * [status]
//! * [validator]

use crate::{
    full_node_data_source::QueryData,
    update_query_data_source::{UpdateQueryDataSource, UpdateQueryDataSourceTypes},
    ApiError,
};
use async_std::{
    sync::{Arc, RwLock},
    task::{spawn, JoinHandle},
};
use clap::{Args, Subcommand};
use espresso_availability_api::api as availability;
use espresso_catchup_api::api as catchup;
use espresso_metastate_api::api as metastate;
use espresso_status_api::api as status;
use espresso_validator_api::{api as validator, data_source::ValidatorDataSource};
use std::fmt::Display;
use std::io;
use tide_disco::{http::Url, App};

#[derive(Args)]
pub struct Options {
    #[arg(short, long, env = "ESPRESSO_ESQS_PORT")]
    pub port: u16,

    #[command(flatten)]
    pub availability: availability::Options,

    #[command(flatten)]
    pub catchup: catchup::Options,

    #[command(flatten)]
    pub metastate: metastate::Options,

    #[command(flatten)]
    pub status: status::Options,

    #[command(flatten)]
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

struct UpdateQueryDataSourceTypesBinder;

impl UpdateQueryDataSourceTypes for UpdateQueryDataSourceTypesBinder {
    type CU = QueryData;
    type AV = QueryData;
    type MS = QueryData;
    type ST = QueryData;
    type EH = QueryData;
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
        consensus: impl ValidatorDataSource + Send + Sync + 'static,
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
        let events = consensus.into_stream();
        let updater = UpdateQueryDataSource::new(
            events,
            data_source.clone(),
            data_source.clone(),
            data_source.clone(),
            data_source.clone(),
            data_source,
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
