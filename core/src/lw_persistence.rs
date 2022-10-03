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

use crate::state::ValidatorState;
use atomic_store::{
    load_store::BincodeLoadStore, AtomicStore, AtomicStoreLoader, PersistenceError, RollingLog,
};
use hotshot::{data::Leaf, types::EventType};

use async_std::task::{spawn, JoinHandle};
use core::fmt::Debug;
use futures::stream::{Stream, StreamExt};
use std::path::{Path, PathBuf};

#[must_use]
pub struct LWPersistence {
    atomic_store: AtomicStore,
    leaf_snapshot: RollingLog<BincodeLoadStore<Leaf<ValidatorState>>>,
}

const LEAF_STORAGE_COUNT: u32 = 1;

impl LWPersistence {
    pub fn new(store_path: &Path, key_tag: &str) -> Result<LWPersistence, PersistenceError> {
        let mut lw_store_path = PathBuf::from(store_path);
        lw_store_path.push("lw_validator");
        let mut loader = AtomicStoreLoader::create(&lw_store_path, key_tag)?;
        let snapshot_tag = format!("{}_state", key_tag);
        let mut leaf_snapshot =
            RollingLog::create(&mut loader, Default::default(), &snapshot_tag, 1024)?;
        leaf_snapshot.set_retained_entries(LEAF_STORAGE_COUNT);
        let atomic_store = AtomicStore::open(loader)?;
        Ok(LWPersistence {
            atomic_store,
            leaf_snapshot,
        })
    }

    pub fn load(store_path: &Path, key_tag: &str) -> Result<LWPersistence, PersistenceError> {
        let mut lw_store_path = PathBuf::from(store_path);
        lw_store_path.push("lw_validator");
        let mut loader = AtomicStoreLoader::load(&lw_store_path, key_tag)?;
        let snapshot_tag = format!("{}_state", key_tag);
        let mut leaf_snapshot =
            RollingLog::load(&mut loader, Default::default(), &snapshot_tag, 1024)?;
        leaf_snapshot.set_retained_entries(LEAF_STORAGE_COUNT);
        let atomic_store = AtomicStore::open(loader)?;
        Ok(LWPersistence {
            atomic_store,
            leaf_snapshot,
        })
    }

    pub fn load_latest_leaf(&self) -> Result<Leaf<ValidatorState>, PersistenceError> {
        self.leaf_snapshot.load_latest()
    }

    fn store_latest_leaf(&mut self, leaf: &Leaf<ValidatorState>) -> Result<(), PersistenceError> {
        self.leaf_snapshot.store_resource(leaf)?;
        self.leaf_snapshot.commit_version()?;
        if let Err(err) = self.leaf_snapshot.prune_file_entries() {
            // Pruning the file entries is an optimization, not a failure that should stop us from
            // committing. Log the error and move along.
            tracing::warn!("failed to prune file entries: {}", err);
        }
        self.atomic_store.commit_version()
    }

    pub fn launch(
        mut self,
        mut events: impl Stream<Item = EventType<ValidatorState>> + Unpin + Send + 'static,
    ) -> JoinHandle<()> {
        spawn(async move {
            while let Some(event) = events.next().await {
                if let EventType::Decide { leaf_chain } = event {
                    // Store the most recent leaf.
                    if let Some(leaf) = leaf_chain.last() {
                        if let Err(err) = self.store_latest_leaf(leaf) {
                            tracing::error!("failed to store latest leaf: {}", err);
                        }
                    }
                }
            }
        })
    }
}

impl Debug for LWPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LWPersistence").finish()
    }
}
