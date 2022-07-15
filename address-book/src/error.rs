// COPYRIGHT100 (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.

use config::ConfigError;
use jf_cap::keys::UserAddress;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tide::StatusCode;

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
        status: StatusCode,
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

impl tide_disco::Error for AddressBookError {
    fn catch_all(status: StatusCode, msg: String) -> Self {
        AddressBookError::Other { status, msg }
    }
    fn status(&self) -> StatusCode {
        match self {
            AddressBookError::AddressNotFound {
                status: status_code,
                address: _,
            } => *status_code,
            AddressBookError::Other {
                status: status_code,
                msg: _,
            } => *status_code,
            _ => StatusCode::InternalServerError,
        }
    }
}

impl From<tide::Error> for AddressBookError {
    fn from(error: tide::Error) -> Self {
        AddressBookError::Config {
            msg: error.to_string(),
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
