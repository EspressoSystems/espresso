use crate::{ElaboratedBlock, SetMerkleTree, ValidatorState};
use atomic_store::{
    load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader, PersistenceError,
    RollingLog,
};
use core::fmt::Debug;
use jf_txn::{
    keys::{UserAddress, UserPubKey},
    structs::ReceiverMemo,
    MerkleLeaf, Signature,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

type OptionalMemoMap = Option<(Vec<ReceiverMemo>, Signature)>;

pub struct FullPersistence {
    atomic_store: AtomicStore,
    state_history: AppendLog<BincodeLoadStore<ValidatorState>>,
    block_history: AppendLog<BincodeLoadStore<ElaboratedBlock>>,
    rmt_leaves_full: AppendLog<BincodeLoadStore<MerkleLeaf>>,
    // TODO: !nathan.yospe - replace with proof accumulators and background periodic roll-ups
    nullifier_snapshots: AppendLog<BincodeLoadStore<SetMerkleTree>>,
    // how long can memos remain unposted? We probably need a custom store for these after demo2
    // also, are txn_uids not a sequential series? Could this be stored as a start/len pair?
    txn_uids: AppendLog<BincodeLoadStore<Vec<u64>>>,
    memos: AppendLog<BincodeLoadStore<OptionalMemoMap>>,
    known_nodes: RollingLog<BincodeLoadStore<HashMap<UserAddress, UserPubKey>>>,
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
        let memos_tag = format!("{}_memos", key_tag);
        let known_nodes_tag = format!("{}_known_nodes", key_tag);
        let state_history = AppendLog::load(&mut loader, Default::default(), &state_tag, 1024)?;
        let block_history = AppendLog::load(&mut loader, Default::default(), &block_tag, 1024)?;
        let rmt_leaves_full =
            AppendLog::load(&mut loader, Default::default(), &full_rmt_tag, 1024)?;
        let nullifier_snapshots =
            AppendLog::load(&mut loader, Default::default(), &nullifier_set_tag, 1024)?;
        let txn_uids = AppendLog::load(&mut loader, Default::default(), &txn_uids_tag, 1024)?;
        let memos = AppendLog::load(&mut loader, Default::default(), &memos_tag, 1024)?;
        let known_nodes =
            RollingLog::load(&mut loader, Default::default(), &known_nodes_tag, 1024)?;
        let atomic_store = AtomicStore::open(loader)?;
        Ok(FullPersistence {
            atomic_store,
            state_history,
            block_history,
            rmt_leaves_full,
            nullifier_snapshots,
            txn_uids,
            memos,
            known_nodes,
        })
    }

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

    pub fn store_txn_uids(&mut self, uids: &[u64]) {
        self.txn_uids.store_resource(&Vec::from(uids)).unwrap();
    }

    pub fn store_nullifier_set(&mut self, nullifiers: &SetMerkleTree) {
        self.nullifier_snapshots.store_resource(nullifiers).unwrap();
    }

    // call when next outstanding by index shows up...
    pub fn store_memos(&mut self, memos: &Option<(Vec<ReceiverMemo>, Signature)>) {
        self.memos.store_resource(memos).unwrap();
    }
    pub fn update_known_nodes(&mut self, known_nodes: &HashMap<UserAddress, UserPubKey>) {
        self.known_nodes.store_resource(known_nodes).unwrap();
    }

    pub fn commit_accepted(&mut self, memos_updated: bool, known_nodes_updated: bool) {
        self.state_history.commit_version().unwrap();
        self.block_history.commit_version().unwrap();
        self.txn_uids.commit_version().unwrap();
        self.nullifier_snapshots.commit_version().unwrap();
        if memos_updated {
            self.memos.commit_version().unwrap();
        } else {
            self.memos.skip_version().unwrap();
        }
        if known_nodes_updated {
            self.known_nodes.commit_version().unwrap();
        } else {
            self.known_nodes.skip_version().unwrap();
        }
        self.atomic_store.commit_version().unwrap();
    }
}

impl Debug for FullPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullPersistence").finish()
    }
}
