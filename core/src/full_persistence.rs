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

use crate::{
    ledger::EspressoLedger,
    state::{ElaboratedBlock, SetMerkleTree, ValidatorState},
};
use atomic_store::{
    append_log::Iter, load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader,
    PersistenceError,
};
use core::fmt::Debug;
use jf_cap::{MerkleLeaf, MerkleTree};
use reef::traits::Transaction;
use seahorse::events::LedgerEvent;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resource {
    StateHistory,
    BlockHistory,
    RmtLeavesFull,
    NullifierSnapshots,
    BlockUids,
    Memos,
    Events,
}

pub struct FullPersistence {
    atomic_store: AtomicStore,
    state_history: AppendLog<BincodeLoadStore<ValidatorState>>,
    block_history: AppendLog<BincodeLoadStore<ElaboratedBlock>>,
    rmt_leaves_full: AppendLog<BincodeLoadStore<MerkleLeaf>>,
    // TODO: !nathan.yospe - replace with proof accumulators and background periodic roll-ups
    nullifier_snapshots: AppendLog<BincodeLoadStore<SetMerkleTree>>,
    // how long can memos remain unposted? We probably need a custom store for these after demo2
    // also, are txn uids not a sequential series? Could this be stored as a list of start/len pairs?
    block_uids: AppendLog<BincodeLoadStore<Vec<Vec<u64>>>>,
    events: AppendLog<BincodeLoadStore<LedgerEvent<EspressoLedger>>>,
}

impl FullPersistence {
    pub fn new(store_path: &Path, key_tag: &str) -> Result<FullPersistence, PersistenceError> {
        let mut full_store_path = PathBuf::from(store_path);
        full_store_path.push("query_data");
        let mut loader = AtomicStoreLoader::load(&full_store_path, key_tag)?;
        let state_tag = format!("{}_states", key_tag);
        let block_tag = format!("{}_blocks", key_tag);
        let full_rmt_tag = format!("{}_full_rmt", key_tag);
        let nullifier_set_tag = format!("{}_full_nullifier_snapshots", key_tag);
        let txn_uids_tag = format!("{}_txn_uids", key_tag);
        let events_tag = format!("{}_events", key_tag);
        let state_history = AppendLog::load(&mut loader, Default::default(), &state_tag, 1024)?;
        let block_history = AppendLog::load(&mut loader, Default::default(), &block_tag, 1024)?;
        let rmt_leaves_full =
            AppendLog::load(&mut loader, Default::default(), &full_rmt_tag, 1024)?;
        let nullifier_snapshots =
            AppendLog::load(&mut loader, Default::default(), &nullifier_set_tag, 1024)?;
        let block_uids = AppendLog::load(&mut loader, Default::default(), &txn_uids_tag, 1024)?;
        let events = AppendLog::load(&mut loader, Default::default(), &events_tag, 1024)?;
        let atomic_store = AtomicStore::open(loader)?;
        Ok(FullPersistence {
            atomic_store,
            state_history,
            block_history,
            rmt_leaves_full,
            nullifier_snapshots,
            block_uids,
            events,
        })
    }

    pub fn store_initial(
        &mut self,
        state: &ValidatorState,
        records: &MerkleTree,
        nullifiers: &SetMerkleTree,
    ) {
        use Resource::*;

        self.state_history.store_resource(state).unwrap();
        self.nullifier_snapshots.store_resource(nullifiers).unwrap();
        for uid in 0..records.num_leaves() {
            self.rmt_leaves_full
                .store_resource(&records.get_leaf(uid).expect_ok().unwrap().1.leaf)
                .unwrap();
        }

        self.commit(&[StateHistory, NullifierSnapshots, RmtLeavesFull]);
    }

    // clippy introduces a lint in 1.59.0 that incorrectly applies to this construction;
    // make that toolchain not break, without breaking earlier toolchains.
    #[allow(unknown_lints)]
    #[allow(clippy::init_numbered_fields)]
    pub fn store_for_commit(&mut self, block: &ElaboratedBlock, state: &ValidatorState) {
        self.state_history.store_resource(state).unwrap();
        self.block_history.store_resource(block).unwrap();
        for comm in block
            .block
            .0
            .iter()
            .flat_map(|txn| txn.output_commitments().into_iter())
        {
            self.rmt_leaves_full
                .store_resource(&MerkleLeaf {
                    0: comm.to_field_element(),
                })
                .unwrap();
        }
    }

    pub fn store_block_uids(&mut self, uids: &[Vec<u64>]) {
        self.block_uids.store_resource(&Vec::from(uids)).unwrap();
    }

    pub fn store_nullifier_set(&mut self, nullifiers: &SetMerkleTree) {
        self.nullifier_snapshots.store_resource(nullifiers).unwrap();
    }

    pub fn commit_accepted(&mut self) {
        use Resource::*;
        self.commit(&[
            StateHistory,
            BlockHistory,
            RmtLeavesFull,
            BlockUids,
            NullifierSnapshots,
            Memos,
        ]);
    }

    pub fn store_event(&mut self, event: &LedgerEvent<EspressoLedger>) {
        self.events.store_resource(event).unwrap();
    }

    pub fn commit_events(&mut self) {
        self.commit(&[Resource::Events]);
    }

    fn commit(&mut self, dirty: &[Resource]) {
        use Resource::*;
        if dirty.contains(&StateHistory) {
            self.state_history.commit_version().unwrap();
        } else {
            self.state_history.skip_version().unwrap();
        }
        if dirty.contains(&BlockHistory) {
            self.block_history.commit_version().unwrap();
        } else {
            self.block_history.skip_version().unwrap();
        }
        if dirty.contains(&RmtLeavesFull) {
            self.rmt_leaves_full.commit_version().unwrap();
        } else {
            self.rmt_leaves_full.skip_version().unwrap();
        }
        if dirty.contains(&BlockUids) {
            self.block_uids.commit_version().unwrap();
        } else {
            self.block_uids.skip_version().unwrap();
        }
        if dirty.contains(&NullifierSnapshots) {
            self.nullifier_snapshots.commit_version().unwrap();
        } else {
            self.nullifier_snapshots.skip_version().unwrap();
        }
        if dirty.contains(&Events) {
            self.events.commit_version().unwrap();
        } else {
            self.events.skip_version().unwrap();
        }
        self.atomic_store.commit_version().unwrap();
    }

    pub fn state_iter(&self) -> Iter<BincodeLoadStore<ValidatorState>> {
        self.state_history.iter()
    }

    pub fn block_iter(&self) -> Iter<BincodeLoadStore<ElaboratedBlock>> {
        self.block_history.iter()
    }

    pub fn rmt_leaf_iter(&self) -> Iter<BincodeLoadStore<MerkleLeaf>> {
        self.rmt_leaves_full.iter()
    }

    pub fn get_latest_nullifier_set(&self) -> Result<SetMerkleTree, PersistenceError> {
        self.nullifier_snapshots.load_latest()
    }

    pub fn nullifier_set_iter(&self) -> Iter<BincodeLoadStore<SetMerkleTree>> {
        self.nullifier_snapshots.iter()
    }

    pub fn block_uids_iter(&self) -> Iter<BincodeLoadStore<Vec<Vec<u64>>>> {
        self.block_uids.iter()
    }

    pub fn events_iter(&self) -> Iter<BincodeLoadStore<LedgerEvent<EspressoLedger>>> {
        self.events.iter()
    }
}

impl Debug for FullPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullPersistence").finish()
    }
}
