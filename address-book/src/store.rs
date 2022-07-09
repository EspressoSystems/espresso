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

use jf_cap::keys::{UserAddress, UserPubKey};
use rand::{distributions::Alphanumeric, Rng};
use std::env;
use std::fs;
use std::path::PathBuf;
use tempdir::TempDir;
use tide_disco::org_data_path;
use tracing::{error, trace};

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
                    trace!("Address {} not found.", address);
                    Ok(None)
                }
                _ => {
                    error!("Attempt to read path {:?} failed: {}", path, err);
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
                        Err(err) => {
                            error!("Attempt to deserialize path {:?} failed: {}", p.path(), err)
                        }
                    }
                }
                Err(err) => {
                    error!("Attempt to read path {:?} failed: {}", p.path(), err);
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

pub fn address_book_store_path() -> PathBuf {
    if let Ok(store_path) = std::env::var("ESPRESSO_ADDRESS_BOOK_STORE_PATH") {
        PathBuf::from(store_path)
    } else {
        org_data_path("espresso")
            .join(env!("CARGO_PKG_NAME"))
            .join("store")
    }
}
