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

use atomic_store::PersistenceError;
use jf_cap::keys::UserPubKey;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tide_disco::{RequestError, StatusCode};

#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(visibility(pub), module(error))]
pub enum FaucetError {
    #[snafu(display("bad request: {}", source))]
    Request { source: RequestError },

    #[snafu(display("error in faucet transfer: {}", msg))]
    Transfer { msg: String },

    #[snafu(display("internal server error: {}", msg))]
    Internal { msg: String, status: StatusCode },

    #[snafu(display("the queue is full with {} requests, try again later", max_len))]
    QueueFull { max_len: usize },

    #[snafu(display(
        "there is a pending request with key {}, you can only request once at a time",
        key
    ))]
    AlreadyInQueue { key: UserPubKey },

    #[snafu(display("error with persistent storage: {}", msg))]
    Persistence { msg: String },

    #[snafu(display("faucet service temporarily unavailable"))]
    Unavailable,
}

impl tide_disco::Error for FaucetError {
    fn catch_all(status: StatusCode, msg: String) -> Self {
        Self::Internal { status, msg }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Request { .. } => StatusCode::BadRequest,
            Self::Transfer { .. } => StatusCode::BadRequest,
            Self::Internal { status, .. } => *status,
            Self::AlreadyInQueue { .. } => StatusCode::TooManyRequests,
            Self::QueueFull { .. } => StatusCode::InternalServerError,
            Self::Persistence { .. } => StatusCode::InternalServerError,
            Self::Unavailable => StatusCode::ServiceUnavailable,
        }
    }
}

impl From<PersistenceError> for FaucetError {
    fn from(source: PersistenceError) -> Self {
        Self::Persistence {
            msg: source.to_string(),
        }
    }
}

impl From<RequestError> for FaucetError {
    fn from(source: RequestError) -> Self {
        Self::Request { source }
    }
}
