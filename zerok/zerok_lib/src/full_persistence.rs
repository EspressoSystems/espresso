use crate::{ElaboratedBlock, SetMerkleTree, ValidatorState};
use atomic_store::{
    append_log::Iter, load_store::BincodeLoadStore, AppendLog, AtomicStore, AtomicStoreLoader,
    PersistenceError,
};
use core::fmt::Debug;
use jf_txn::{
    keys::{UserAddress, UserPubKey},
    structs::ReceiverMemo,
    MerkleLeaf, MerkleTree, Signature,
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
    // also, are txn uids not a sequential series? Could this be stored as a list of start/len pairs?
    block_uids: AppendLog<BincodeLoadStore<Vec<Vec<u64>>>>,
    memos: AppendLog<BincodeLoadStore<Vec<OptionalMemoMap>>>,
    // TODO: !jeb.bearer,nathan.yospe - turn this back into a RollingLog once we fix whatever is
    // wrong with RollingLog; we don't need to store old versions of the known_nodes map
    known_nodes: AppendLog<BincodeLoadStore<HashMap<UserAddress, UserPubKey>>>,
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
        let block_uids = AppendLog::load(&mut loader, Default::default(), &txn_uids_tag, 1024)?;
        let memos = AppendLog::load(&mut loader, Default::default(), &memos_tag, 1024)?;
        let known_nodes = AppendLog::load(&mut loader, Default::default(), &known_nodes_tag, 1024)?;
        let atomic_store = AtomicStore::open(loader)?;
        Ok(FullPersistence {
            atomic_store,
            state_history,
            block_history,
            rmt_leaves_full,
            nullifier_snapshots,
            block_uids,
            memos,
            known_nodes,
        })
    }

    pub fn store_initial(
        &mut self,
        state: &ValidatorState,
        records: &MerkleTree,
        nullifiers: &SetMerkleTree,
    ) {
        self.state_history.store_resource(state).unwrap();
        self.nullifier_snapshots.store_resource(nullifiers).unwrap();
        for uid in 0..records.num_leaves() {
            self.rmt_leaves_full
                .store_resource(&records.get_leaf(uid).expect_ok().unwrap().1.leaf)
                .unwrap();
        }
        self.known_nodes
            .store_resource(&HashMap::default())
            .unwrap();

        self.state_history.commit_version().unwrap();
        self.nullifier_snapshots.commit_version().unwrap();
        self.rmt_leaves_full.commit_version().unwrap();
        self.known_nodes.commit_version().unwrap();

        self.block_history.skip_version().unwrap();
        self.block_uids.skip_version().unwrap();
        self.memos.skip_version().unwrap();

        self.atomic_store.commit_version().unwrap();
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

    pub fn store_block_uids(&mut self, uids: &[Vec<u64>]) {
        self.block_uids.store_resource(&Vec::from(uids)).unwrap();
    }

    pub fn store_nullifier_set(&mut self, nullifiers: &SetMerkleTree) {
        self.nullifier_snapshots.store_resource(nullifiers).unwrap();
    }

    // call when next outstanding by index shows up...
    #[allow(clippy::ptr_arg)]
    pub fn store_memos(&mut self, memos: &Vec<OptionalMemoMap>) {
        self.memos.store_resource(memos).unwrap();
    }
    pub fn update_known_nodes(&mut self, known_nodes: &HashMap<UserAddress, UserPubKey>) {
        self.known_nodes.store_resource(known_nodes).unwrap();
    }

    pub fn commit_known_nodes(&mut self) {
        self.known_nodes.commit_version().unwrap();
        self.state_history.skip_version().unwrap();
        self.block_history.skip_version().unwrap();
        self.rmt_leaves_full.skip_version().unwrap();
        self.block_uids.skip_version().unwrap();
        self.nullifier_snapshots.skip_version().unwrap();
        self.memos.skip_version().unwrap();
        self.atomic_store.commit_version().unwrap();
    }

    pub fn commit_accepted(&mut self) {
        self.state_history.commit_version().unwrap();
        self.block_history.commit_version().unwrap();
        self.rmt_leaves_full.commit_version().unwrap();
        self.block_uids.commit_version().unwrap();
        self.nullifier_snapshots.commit_version().unwrap();
        self.memos.commit_version().unwrap();
        self.known_nodes.skip_version().unwrap();
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

    pub fn memos_iter(&self) -> Iter<BincodeLoadStore<Vec<OptionalMemoMap>>> {
        self.memos.iter()
    }

    pub fn get_latest_known_nodes(
        &self,
    ) -> Result<HashMap<UserAddress, UserPubKey>, PersistenceError> {
        self.known_nodes.load_latest()
    }
}

impl Debug for FullPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullPersistence").finish()
    }
}
