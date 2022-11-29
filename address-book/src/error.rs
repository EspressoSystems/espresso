// Copyright (c) 2022 Espresso Systems (espressosys.com)

use config::ConfigError;
use jf_cap::keys::UserAddress;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tide_disco::StatusCode;

#[derive(Clone, Debug, Deserialize, Serialize, Snafu)]
pub enum AddressBookError {
    Config {
        msg: String,
    },
    AddressNotFound {
        status: StatusCode,
        address: UserAddress,
    },
    DeserializationError {
        msg: String,
    },
    InvalidSignature {
        msg: String,
    },
    IoError,
    Other {
        status: StatusCode,
        msg: String,
    },
}

impl From<ConfigError> for AddressBookError {
    fn from(error: ConfigError) -> Self {
        Self::Config {
            msg: error.to_string(),
        }
    }
}

impl From<std::io::Error> for AddressBookError {
    fn from(error: std::io::Error) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
        }
    }
}

impl From<toml::de::Error> for AddressBookError {
    fn from(error: toml::de::Error) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
        }
    }
}

impl From<bincode::Error> for AddressBookError {
    fn from(error: bincode::Error) -> Self {
        AddressBookError::DeserializationError {
            msg: error.to_string(),
        }
    }
}

impl tide_disco::Error for AddressBookError {
    fn catch_all(status: StatusCode, msg: String) -> Self {
        Self::Other { status, msg }
    }
    fn status(&self) -> StatusCode {
        match self {
            Self::AddressNotFound {
                status: status_code,
                address: _,
            } => *status_code,
            Self::Other {
                status: status_code,
                msg: _,
            } => *status_code,
            Self::DeserializationError { .. } | Self::InvalidSignature { .. } => {
                StatusCode::BadRequest
            }
            _ => StatusCode::InternalServerError,
        }
    }
}

impl From<tide_disco::RequestError> for AddressBookError {
    fn from(error: tide_disco::RequestError) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
        }
    }
}
