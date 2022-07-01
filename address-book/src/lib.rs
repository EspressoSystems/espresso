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

use async_std::sync::{Arc, RwLock};
use async_std::task::sleep;
use config::ConfigError;
use futures::FutureExt;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::Signature;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::env;
use std::path::PathBuf;
use std::{fs, time::Duration};
use tempdir::TempDir;
use tide::StatusCode;
use tide_disco::{Api, App, RequestParams};

#[cfg(not(windows))]
pub mod signal;

pub const DEFAULT_PORT: u16 = 50078u16;
const STARTUP_RETRIES: u32 = 255;

// TODO move persistence to a separate file
//----
pub trait Store: Clone + Send + Sync {
    fn save(&self, address: &UserAddress, pub_key: &UserPubKey) -> Result<(), std::io::Error>;
    fn load(&self, address: &UserAddress) -> Result<Option<UserPubKey>, std::io::Error>;
    fn list(&self) -> Result<Vec<UserPubKey>, std::io::Error>;
}

#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

/// Persistent file backed store.
/// Each (address, pub_key) pair is store in a single file inside `dir`.
impl FileStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, address: &UserAddress) -> PathBuf {
        let as_hex = hex::encode(bincode::serialize(&address).unwrap());
        self.dir.join(format!("{}.bin", as_hex))
    }

    fn tmp_path(&self, address: &UserAddress) -> PathBuf {
        let rand_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        self.path(address).with_extension(rand_string)
    }
}

impl Store for FileStore {
    fn save(&self, address: &UserAddress, pub_key: &UserPubKey) -> Result<(), std::io::Error> {
        let tmp_path = self.tmp_path(address);
        fs::write(
            &tmp_path,
            bincode::serialize(&pub_key).expect("Failed to serialize public key."),
        )?;
        fs::rename(&tmp_path, self.path(address))
    }
    fn load(&self, address: &UserAddress) -> Result<Option<UserPubKey>, std::io::Error> {
        let path = self.path(address);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(
                bincode::deserialize(&bytes).expect("Failed to deserialize public key."),
            )),
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => {
                    tracing::info!("Address {} not found.", address);
                    Ok(None)
                }
                _ => {
                    tracing::error!("Attempt to read path {:?} failed: {}", path, err);
                    Err(err)
                }
            },
        }
    }

    fn list(&self) -> Result<Vec<UserPubKey>, std::io::Error> {
        let paths = fs::read_dir(&self.dir)?;
        let mut keys = vec![];
        for path in paths {
            let p = path?;
            match fs::read(&p.path()) {
                Ok(bytes) => {
                    let pk = bincode::deserialize(&bytes);
                    match pk {
                        Ok(pub_key) => keys.push(pub_key),
                        Err(err) => tracing::error!(
                            "Attempt to deserialize path {:?} failed: {}",
                            p.path(),
                            err
                        ),
                    }
                }
                Err(err) => {
                    tracing::error!("Attempt to read path {:?} failed: {}", p.path(), err);
                    return Err(err);
                }
            }
        }
        Ok(keys)
    }
}

/// Non-persistent store. Suitable for testing only.
#[derive(Debug, Clone)]
pub struct TransientFileStore {
    store: FileStore,
}

impl Default for TransientFileStore {
    fn default() -> Self {
        Self {
            store: FileStore::new(
                TempDir::new("espresso-address-book")
                    .expect("Failed to create temporary directory.")
                    .into_path(),
            ),
        }
    }
}

impl Drop for TransientFileStore {
    fn drop(&mut self) {
        fs::remove_dir_all(self.store.dir.clone()).expect("Failed to remove store path.");
    }
}

impl Store for TransientFileStore {
    fn save(&self, address: &UserAddress, pub_key: &UserPubKey) -> Result<(), std::io::Error> {
        self.store.save(address, pub_key)
    }

    fn load(&self, address: &UserAddress) -> Result<Option<UserPubKey>, std::io::Error> {
        self.store.load(address)
    }
    fn list(&self) -> Result<Vec<UserPubKey>, std::io::Error> {
        self.store.list()
    }
}

pub fn address_book_temp_dir() -> TempDir {
    TempDir::new("espresso-address-book").expect("Failed to create temporary directory.")
}

pub fn espresso_data_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("./")))
        .join(".espresso")
        .join("espresso")
}

pub fn address_book_store_path() -> PathBuf {
    if let Ok(store_path) = std::env::var("ESPRESSO_ADDRESS_BOOK_STORE_PATH") {
        PathBuf::from(store_path)
    } else {
        espresso_data_path().join("address_book").join("store")
    }
}

//----

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

    api.post("insert_pubkey", |req_params, server_state| {
        async move {
            let insert_request: InsertPubKey = bincode::deserialize(&req_params.body_bytes())
                .map_err(|_e| AddressBookError::Other {
                    status: StatusCode::BadRequest,
                    msg: "Unable to deseralize the insert request from the post data".to_string(),
                })?;

            let pub_key = verify_sig_and_get_pub_key(insert_request)?;
            (*server_state.store).save(&pub_key.address(), &pub_key)?;
            Ok(())
        }
        .boxed()
    })
    .unwrap();
    api.post("request_pubkey", |req_params, server_state| {
        async move {
            let address = get_user_address(req_params)?;
            // TODO convert to map_err expression
            match (*server_state.store).load(&address) {
                Ok(pub_key) => Ok(pub_key),
                Err(_) => Err(AddressBookError::AddressNotFound {
                    status: StatusCode::NotFound,
                    address,
                }),
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

// TODO exponential backoff seems slightly less efficient than fixed-interval polling
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
    bincode::deserialize(&req_params.body_bytes()).map_err(|e| AddressBookError::Other {
        status: StatusCode::BadRequest,
        msg: e.to_string(),
    })?
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
