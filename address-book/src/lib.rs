// Copyright (c) 2022 Espresso Systems (espressosys.com)
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

#![doc = include_str!("../README.md")]

use crate::store::Store;
use async_std::sync::{Arc, RwLock};
use async_std::task::sleep;
use config::ConfigError;
use futures::future::BoxFuture;
use futures::FutureExt;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::Signature;
use serde::{Deserialize, Serialize};
use serde_json;
use snafu::Snafu;
use std::{fs, time::Duration};
use tide::StatusCode;
use tide_disco::{Api, App, RequestParams};
use tracing::trace;

pub mod store;

#[cfg(not(windows))]
pub mod signal;

pub const DEFAULT_PORT: u16 = 50078u16;
const STARTUP_RETRIES: u32 = 255;

#[derive(Debug, Deserialize, Serialize)]
pub struct InsertPubKey {
    pub pub_key_bytes: Vec<u8>,
    pub sig: Signature,
}

#[derive(Clone)]
pub struct ServerState<T: Store> {
    pub store: Arc<T>,
}

pub fn address_book_port() -> u16 {
    match std::env::var("ESPRESSO_ADDRESS_BOOK_PORT") {
        Ok(port) => port.parse().unwrap(),
        Err(_) => DEFAULT_PORT,
    }
}

// TODO The Ok return doesn't match the expected type State yet
// the closure returns the user public key but doesn't generate this
// compiler error
// pub async fn request_pubkey<State: Store + 'static>(
//     p: RequestParams,
//     store: State,
// ) -> BoxFuture<'static, Result<State, AddressBookError>> {
//     let address = get_user_address(req_params)?;
//     // TODO convert to map_err expression
//     Box::pin(async move {
//         match (*server_state.store).load(&address) {
//             Ok(Some(pub_key)) => {
//                 let upk: UserPubKey = pub_key;
//                 trace!(
//                     "/request_pubkey address: {:?} -> pb_key: {:?}",
//                     &address,
//                     &upk
//                 );
//                 Ok(upk)
//             }
//             Ok(None) => {
//                 // Not sure if this should be an error. The key is
//                 // simply not present.
//                 trace!("/request_pubkey not found: {:?}", &address);
//                 Err(AddressBookError::AddressNotFound {
//                     status: StatusCode::NotFound,
//                     address,
//                 })
//             }
//             Err(_) => {
//                 // TODO Something went more wrong than address not found
//                 Err(AddressBookError::AddressNotFound {
//                     status: StatusCode::NotFound,
//                     address,
//                 })
//             }
//         }
//     })
// }

pub fn init_web_server<T: Store + 'static>(
    api_toml: String,
    store: T,
) -> Result<App<RwLock<ServerState<T>>, AddressBookError>, AddressBookError> {
    let server_state = ServerState {
        store: Arc::new(store),
    };

    let mut app = App::<_, AddressBookError>::with_state(RwLock::new(server_state));
    let mut api = Api::<RwLock<ServerState<T>>, AddressBookError>::new(toml::from_slice(
        &fs::read(api_toml)?,
    )?)
    .unwrap();

    api.post(
        "insert_pubkey",
        |req_params: RequestParams, server_state| {
            async move {
                let insert_request: InsertPubKey = serde_json::from_slice(&req_params.body_bytes())
                    .map_err(|_e| AddressBookError::Other {
                        status: StatusCode::BadRequest,
                        msg: "Unable to deseralize the insert request from the post data"
                            .to_string(),
                    })?;

                trace!("/insert_pubkey InsertPubKey: {:?}", &insert_request);

                let pub_key = verify_sig_and_get_pub_key(insert_request)?;
                (*server_state.store).save(&pub_key.address(), &pub_key)?;
                Ok(())
            }
            .boxed()
        },
    )
    .unwrap();
    api.post("request_pubkey", |req_params, server_state| {
        async move {
            let address = get_user_address(req_params)?;
            // TODO convert to map_err expression
            match (*server_state.store).load(&address) {
                Ok(Some(pub_key)) => {
                    let upk: UserPubKey = pub_key;
                    trace!(
                        "/request_pubkey address: {:?} -> pb_key: {:?}",
                        &address,
                        &upk
                    );
                    Ok(upk)
                }
                Ok(None) => {
                    // Not sure if this should be an error. The key is
                    // simply not present.
                    trace!("/request_pubkey not found: {:?}", &address);
                    Err(AddressBookError::AddressNotFound {
                        status: StatusCode::NotFound,
                        address,
                    })
                }
                Err(_) => {
                    // TODO Something went more wrong than address not found
                    Err(AddressBookError::AddressNotFound {
                        status: StatusCode::NotFound,
                        address,
                    })
                }
            }
        }
        .boxed()
    })
    .unwrap();
    api.get("request_peers", |_req_params, server_state| {
        async move {
            match (*server_state.store).list() {
                Ok(pk_list) => Ok(pk_list),
                Err(_) => Err(AddressBookError::IoError),
            }
        }
        .boxed()
    })
    .unwrap();

    app.register_module("", api).unwrap();

    Ok(app)
}

pub async fn wait_for_server(base_url: &str) {
    // Wait for the server to come up and start serving.
    let pause_ms = Duration::from_millis(100);
    for _ in 0..STARTUP_RETRIES {
        if surf::connect(base_url).send().await.is_ok() {
            return;
        }
        sleep(pause_ms).await;
    }
    panic!(
        "Address Book did not start in {:?} milliseconds",
        pause_ms * STARTUP_RETRIES
    );
}

/// Lookup a user public key from a signed public key address. Fail with
/// tide::StatusCode::BadRequest if key deserialization or the signature check
/// fail.
pub fn verify_sig_and_get_pub_key(
    insert_request: InsertPubKey,
) -> Result<UserPubKey, AddressBookError> {
    let pub_key: UserPubKey = bincode::deserialize(&insert_request.pub_key_bytes)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    pub_key
        .verify_sig(&insert_request.pub_key_bytes, &insert_request.sig)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    Ok(pub_key)
}

/// Insert or update the public key at the given address.
pub async fn insert_pubkey<T: Store>(
    mut req: tide::Request<ServerState<T>>,
) -> Result<tide::Response, AddressBookError> {
    let insert_request: InsertPubKey = net::server::request_body(&mut req).await?;
    let pub_key = verify_sig_and_get_pub_key(insert_request)?;
    req.state().store.save(&pub_key.address(), &pub_key)?;
    Ok(tide::Response::new(StatusCode::Ok))
}

/// Fetch the public key for the given address. If not found, return
/// StatusCode::NotFound.
pub async fn request_pubkey<T: Store>(
    mut req: tide::Request<ServerState<T>>,
) -> Result<tide::Response, tide::Error> {
    let address: UserAddress = net::server::request_body(&mut req).await?;
    match req.state().store.load(&address) {
        Ok(pub_key) => match pub_key {
            Some(value) => {
                let bytes = bincode::serialize(&value).unwrap();
                let response = tide::Response::builder(StatusCode::Ok)
                    .body(bytes)
                    .content_type(tide::http::mime::BYTE_STREAM)
                    .build();
                Ok(response)
            }
            _ => Ok(tide::Response::new(StatusCode::NotFound)),
        },
        Err(_) => Ok(tide::Response::new(StatusCode::InternalServerError)),
    }
}

/// Fetch all the public key bundles for all peers.
pub async fn request_peers<T: Store>(
    req: tide::Request<ServerState<T>>,
) -> Result<tide::Response, tide::Error> {
    match req.state().store.list() {
        Ok(pk_list) => {
            let bytes = bincode::serialize(&pk_list).unwrap();
            let response = tide::Response::builder(StatusCode::Ok)
                .body(bytes)
                .content_type(tide::http::mime::BYTE_STREAM)
                .build();
            Ok(response)
        }
        Err(_) => Ok(tide::Response::new(StatusCode::InternalServerError)),
    }
}

// TODO Maybe accept Vec<u8> instead.
// TODO Add information about deserializing POST data to the low-level error
pub fn get_user_address(req_params: RequestParams) -> Result<UserAddress, AddressBookError> {
    let address: UserAddress =
        bincode::deserialize(&req_params.body_bytes()).map_err(|e| AddressBookError::Other {
            status: StatusCode::BadRequest,
            msg: e.to_string(),
        })?;
    Ok(address)
}

//----

// TODO move all the error stuff to a separate file
#[derive(Clone, Debug, Deserialize, Serialize, Snafu)]
pub enum AddressBookError {
    Config {
        msg: String,
    },
    AddressNotFound {
        status: StatusCode,
        address: UserAddress,
    },
    DeserializationError,
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
