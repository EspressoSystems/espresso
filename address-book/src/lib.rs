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
#[warn(unused_imports)]
use async_std::task::{sleep, spawn, JoinHandle};
use config::ConfigError;
use jf_cap::keys::{UserAddress, UserPubKey};
use jf_cap::Signature;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, time::Duration};
use tempdir::TempDir;
use tide::{
    convert::json,
    http::headers::HeaderValue,
    security::{CorsMiddleware, Origin},
    StatusCode,
};
use tide_disco::RequestParams;

#[cfg(not(windows))]
pub mod signal;

pub const DEFAULT_PORT: u16 = 50078u16;
const ADDRESS_BOOK_STARTUP_RETRIES: usize = 8;

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

#[derive(Debug, Deserialize, Serialize)]
pub struct InsertPubKey {
    pub pub_key_bytes: Vec<u8>,
    pub sig: Signature,
}

#[derive(Clone)]
pub struct ServerState<T: Store> {
    pub store: Arc<T>,
}

pub fn address_book_temp_dir() -> TempDir {
    TempDir::new("espresso-address-book").expect("Failed to create temporary directory.")
}

pub fn address_book_port() -> u16 {
    match std::env::var("ESPRESSO_ADDRESS_BOOK_PORT") {
        Ok(port) => port.parse().unwrap(),
        Err(_) => DEFAULT_PORT,
    }
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

// pub async fn init_web_server<T: Store + 'static>(
//     port: u16,
//     store: T,
// ) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
//     let mut app = tide::with_state(ServerState {
//         store: Arc::new(store),
//     });
//     app.with(
//         CorsMiddleware::new()
//             .allow_methods("GET, POST".parse::<HeaderValue>().unwrap())
//             .allow_headers("*".parse::<HeaderValue>().unwrap())
//             .allow_origin(Origin::from("*"))
//             .allow_credentials(true),
//     );
//     app.at("/insert_pubkey").post(insert_pubkey);
//     app.at("/request_pubkey").post(request_pubkey);
//     app.at("/request_peers").get(request_peers);
//     app.at("/healthcheck").get(healthcheck);
//     let address = format!("0.0.0.0:{}", port);
//     Ok(spawn(app.listen(address)))
// }

pub async fn wait_for_server(port: u16) {
    // Wait for the server to come up and start serving.
    let mut backoff = Duration::from_millis(100);
    for _ in 0..ADDRESS_BOOK_STARTUP_RETRIES {
        if surf::connect(format!("http://localhost:{}", port))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        sleep(backoff).await;
        backoff *= 2;
    }
    panic!("Address Book did not start in {:?} milliseconds", backoff);
}

/// Lookup a user public key from a signed public key address. Fail with
/// tide::StatusCode::BadRequest if key deserialization or the signature check
/// fail.
fn verify_sig_and_get_pub_key(insert_request: InsertPubKey) -> Result<UserPubKey, tide::Error> {
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
) -> Result<tide::Response, tide::Error> {
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

pub fn get_user_address(req_params: RequestParams) -> Result<UserAddress, AddressBookError> {
    bincode::deserialize(&req_params.body_bytes()).map_err(|e| AddressBookError::Other {
        status: StatusCode::BadRequest,
        msg: "Unable to deseralize the user address from the post data".to_string(),
    })?
}

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
        unimplemented!();
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
