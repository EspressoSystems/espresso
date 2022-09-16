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

use crate::state::{ElaboratedBlock, ValidatorState};
use atomic_store::{
    load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader, PersistenceError,
};
use hotshot::traits::StatefulHandler;

use core::fmt::Debug;
use std::path::{Path, PathBuf};

pub struct LWPersistence {
    atomic_store: AtomicStore,
    state_snapshot: AppendLog<BincodeLoadStore<ValidatorState>>,
}

impl LWPersistence {
    pub fn new(store_path: &Path, key_tag: &str) -> Result<LWPersistence, PersistenceError> {
        let mut lw_store_path = PathBuf::from(store_path);
        lw_store_path.push("lw_validator");
        let mut loader = AtomicStoreLoader::create(&lw_store_path, key_tag)?;
        let snapshot_tag = format!("{}_state", key_tag);
        let state_snapshot =
            AppendLog::create(&mut loader, Default::default(), &snapshot_tag, 1024)?;
        let atomic_store = AtomicStore::open(loader)?;
        Ok(LWPersistence {
            atomic_store,
            state_snapshot,
        })
    }

    pub fn load(store_path: &Path, key_tag: &str) -> Result<LWPersistence, PersistenceError> {
        let mut lw_store_path = PathBuf::from(store_path);
        lw_store_path.push("lw_validator");
        let mut loader = AtomicStoreLoader::load(&lw_store_path, key_tag)?;
        let snapshot_tag = format!("{}_state", key_tag);
        let state_snapshot = AppendLog::load(&mut loader, Default::default(), &snapshot_tag, 1024)?;
        let atomic_store = AtomicStore::open(loader)?;
        Ok(LWPersistence {
            atomic_store,
            state_snapshot,
        })
    }

    pub fn store_latest_state(&mut self, _block: &ElaboratedBlock, state: &ValidatorState) {
        self.state_snapshot.store_resource(state).unwrap();
        self.state_snapshot.commit_version().unwrap();
        self.atomic_store.commit_version().unwrap();
    }

    pub fn load_latest_state(&self) -> Result<ValidatorState, PersistenceError> {
        self.state_snapshot.load_latest()
    }
}

impl Debug for LWPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LWPersistence").finish()
    }
}

impl StatefulHandler for LWPersistence {
    type Block = ElaboratedBlock;
    type State = ValidatorState;

    fn notify(&mut self, blocks: Vec<Self::Block>, states: Vec<Self::State>) {
        if blocks.is_empty() || states.is_empty() {
            return;
        }
        self.store_latest_state(&blocks[0], &states[0]);
    }
}
