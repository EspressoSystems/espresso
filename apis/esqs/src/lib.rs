// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use derive_more::From;
use espresso_availability_api::api as availability;
use espresso_catchup_api::api as catchup;
use espresso_metastate_api::api as metastate;
use espresso_status_api::api as status;
use espresso_validator_api::api as validator;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tide_disco::StatusCode;

pub mod full_node;
pub mod full_node_data_source;
pub mod update_query_data_source;

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
    #[snafu(display("error {}: {}", status, reason))]
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
