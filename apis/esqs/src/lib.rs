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
