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

use crate::error::AddressBookError;
use crate::store::Store;
use async_std::sync::{Arc, RwLock};
use clap::Parser;
use futures::FutureExt;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::Signature;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use strum_macros::AsRefStr;
use tide::StatusCode;
use tide_disco::{Api, App, DiscoArgs, RequestParams};
use tracing::trace;

pub mod error;
pub mod store;

#[cfg(not(windows))]
pub mod signal;

/// Application name used for locating configuration files
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

pub type Result<T> = std::result::Result<T, AddressBookError>;

/// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(flatten)]
    pub disco_args: DiscoArgs,
    #[clap(long)]
    /// Storage path
    pub store_path: Option<PathBuf>,
}

/// Lookup keys for application-specific configuration settings
// Although we could use literal strings, this approach allows the compiler to catch typos.
#[derive(AsRefStr, Debug)]
#[allow(non_camel_case_types)]
pub enum AppKey {
    store_path,
}

/// Structure to supply parameters to web requests
#[derive(Debug, Deserialize, Serialize)]
pub struct InsertPubKey {
    pub pub_key_bytes: Vec<u8>,
    pub sig: Signature,
}

/// Web server state
#[derive(Clone)]
pub struct ServerState<T: Store> {
    pub store: Arc<T>,
}

pub fn eq_header_values(req_params: &RequestParams, h: &str, s: &str) -> bool {
    req_params.headers()[h]
        .to_string()
        .to_lowercase()
        .contains(s)
}

pub fn insert_pubkey<T: Store + 'static>(insert_request: InsertPubKey, store: &T) -> Result<()> {
    let pub_key = verify_sig_and_get_pub_key(insert_request)?;
    store.save(&pub_key.address(), &pub_key)?;
    Ok(())
}

/// Initialize the web server
///
/// Bind route handlers and documentation
pub fn init_web_server<T: Store + 'static>(
    api_toml: String,
    store: T,
) -> Result<App<RwLock<ServerState<T>>, AddressBookError>> {
    let server_state = ServerState {
        store: Arc::new(store),
    };
    let mut app = App::<_, AddressBookError>::with_state(RwLock::new(server_state));
    let mut api = Api::<RwLock<ServerState<T>>, AddressBookError>::new(toml::from_slice(
        &fs::read(api_toml)?,
    )?)
    .unwrap();

    // Insert or update the public key at the given address.
    api.post("insert_pubkey", |req_params, server_state| {
        async move {
            if eq_header_values(&req_params, "content-type", "application/json") {
                let insert_request: InsertPubKey = req_params.body_json()?;
                trace!("/insert_pubkey [json] InsertPubKey: {:?}", &insert_request);
                insert_pubkey(insert_request, &*server_state.store)?;
                Ok(())
            } else {
                Err(AddressBookError::Other {
                    status: StatusCode::UnsupportedMediaType,
                    msg: "Expecting content-type: application/json".to_string(),
                })
            }
        }
        .boxed()
    })
    .unwrap();

    // Fetch the public key for the given address. If not found, return
    // StatusCode::NotFound.
    api.post("request_pubkey", |req_params, server_state| {
        async move {
            if eq_header_values(&req_params, "content-type", "application/octet-stream") {
                let address: UserAddress =
                    bincode::deserialize(&req_params.body_bytes()).map_err(|e| {
                        AddressBookError::DeserializationError {
                            status: StatusCode::BadRequest,
                            msg: e.to_string(),
                        }
                    })?;
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
                        trace!("/request_pubkey not found: {:?}", &address);
                        Err(AddressBookError::AddressNotFound {
                            status: StatusCode::NotFound,
                            address,
                        })
                    }
                    Err(e) => Err(AddressBookError::Other {
                        status: StatusCode::InternalServerError,
                        msg: e.to_string(),
                    }),
                }
            } else {
                Err(AddressBookError::Other {
                    status: StatusCode::UnsupportedMediaType,
                    msg: "Expecting content-type: application/octet-stream".to_string(),
                })
            }
        }
        .boxed()
    })
    .unwrap();

    // Fetch all the public key bundles for all peers.
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

/// Lookup a user public key from a signed public key address. Fail with
/// tide::StatusCode::BadRequest if key deserialization or the signature check
/// fail.
pub fn verify_sig_and_get_pub_key(insert_request: InsertPubKey) -> Result<UserPubKey> {
    let pub_key: UserPubKey = bincode::deserialize(&insert_request.pub_key_bytes)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    pub_key
        .verify_sig(&insert_request.pub_key_bytes, &insert_request.sig)
        .map_err(|e| tide::Error::new(tide::StatusCode::BadRequest, e))?;
    Ok(pub_key)
}
