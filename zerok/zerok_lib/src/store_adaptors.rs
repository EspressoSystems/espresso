use atomic_store::load_store::ArkLoadStore;
use atomic_store::{AtomicStoreLoader, FixedAppendLog, RollingLog};
use jf_primitives::merkle_tree::LookupResult;
use jf_txn::{constants::BLS_SCALAR_REPR_BYTE_LEN, BaseField, MerklePath, MerkleTree, NodeValue};

use ark_serialize::*;

use std::fmt::Debug;

// #[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
// pub struct ElementProof {
//     pub pos: u64,
//     pub elem: BaseField,
//     pub proof: MerklePath,
// }

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct MerkleFrontier {
    pub height: u8,
    pub leaf_count: u64,
    pub frontier: Vec<NodeValue>,
}

#[derive(Debug)]
enum Logging {
    Full {
        leaf_log: FixedAppendLog<ArkLoadStore<BaseField>>,
        frontier_log: RollingLog<ArkLoadStore<MerkleFrontier>>,
    },
    FileOnly {
        leaf_log: FixedAppendLog<ArkLoadStore<BaseField>>,
        frontier_log: RollingLog<ArkLoadStore<MerkleFrontier>>,
    },
    // Sparse {
    //     cache_log: KeyValueLog<u64, ArkLoadStore<ElementProof>>,
    //     frontier_log: RollingLog<ArkLoadStore<MerkleFrontier>>,
    // },
    Pruned {
        frontier_log: RollingLog<ArkLoadStore<MerkleFrontier>>,
    },
}

// choosing to restrict this to the jf_txn::MerkleTree alias (e.g. MerkleTree<BaseField>) allows us
// to confidently assume a serialized size, specifically BLS_SCALAR_REPR_BYTE_LEN, which means we
// can use the generally preferable FixedAppendLog.
#[derive(Debug)]
pub struct PersistedMerkleTree {
    // a 3-ary merkle tree, optimized for ease of proof evaluation, not storage
    inner_tree: MerkleTree,
    logging: Logging,
}

// size of each filled file
const ONE_MEGABYTE: u64 = 1024u64 * 1024u64;
// number of element entries in each leaf_log file
const FILE_ENTRY_COUNT: u64 = ONE_MEGABYTE / BLS_SCALAR_REPR_BYTE_LEN as u64;

fn leaf_file_key(file_pattern: &str) -> String {
    format!("{}_values", file_pattern)
}
// fn cache_file_key(file_pattern: &str) -> String {
//     format!("{}_cache", file_pattern)
// }
fn frontier_file_key(file_pattern: &str) -> String {
    format!("{}_frontier", file_pattern)
}

#[allow(dead_code)]
impl PersistedMerkleTree {
    pub fn create_full(
        height: u8,
        loader: &mut AtomicStoreLoader,
        file_pattern: &str,
    ) -> Option<Self> {
        let leaf_file_pattern = leaf_file_key(file_pattern);
        let frontier_file_pattern = frontier_file_key(file_pattern);
        if let Some(inner_tree) = MerkleTree::new(height) {
            Some(PersistedMerkleTree {
                inner_tree,
                logging: Logging::Full {
                    leaf_log: FixedAppendLog::create(
                        loader,
                        &leaf_file_pattern,
                        BLS_SCALAR_REPR_BYTE_LEN as u64,
                        FILE_ENTRY_COUNT,
                    )
                    .ok()?,
                    frontier_log: RollingLog::create(loader, &frontier_file_pattern, ONE_MEGABYTE)
                        .ok()?,
                },
            })
        } else {
            None
        }
    }
    pub fn create_pruned(
        height: u8,
        loader: &mut AtomicStoreLoader,
        file_pattern: &str,
    ) -> Option<Self> {
        let frontier_file_pattern = frontier_file_key(file_pattern);
        if let Some(inner_tree) = MerkleTree::new(height) {
            Some(PersistedMerkleTree {
                inner_tree,
                logging: Logging::Pruned {
                    frontier_log: RollingLog::create(loader, &frontier_file_pattern, ONE_MEGABYTE)
                        .ok()?,
                },
            })
        } else {
            None
        }
    }
    pub fn create_fs_pruned(
        height: u8,
        loader: &mut AtomicStoreLoader,
        file_pattern: &str,
    ) -> Option<Self> {
        let leaf_file_pattern = leaf_file_key(file_pattern);
        let frontier_file_pattern = frontier_file_key(file_pattern);
        if let Some(inner_tree) = MerkleTree::new(height) {
            Some(PersistedMerkleTree {
                inner_tree,
                logging: Logging::FileOnly {
                    leaf_log: FixedAppendLog::create(
                        loader,
                        &leaf_file_pattern,
                        BLS_SCALAR_REPR_BYTE_LEN as u64,
                        FILE_ENTRY_COUNT,
                    )
                    .ok()?,
                    frontier_log: RollingLog::create(loader, &frontier_file_pattern, ONE_MEGABYTE)
                        .ok()?,
                },
            })
        } else {
            None
        }
    }
    // pub fn create_sparse(
    //     height: u8,
    //     loader: &mut AtomicStoreLoader,
    //     file_pattern: &str,
    // ) -> Option<Self> {
    //     let cache_file_pattern = cache_file_key(file_pattern);
    //     let frontier_file_pattern = frontier_file_key(file_pattern);
    //     if let Some(inner_tree) = MerkleTree::new(height) {
    //         Some(PersistedMerkleTree {
    //             inner_tree,
    //             logging: Logging::Sparse{
    //                 cache_log: KeyValueLog::create(loader, cache_file_pattern, ONE_MEGABYTE).ok()?,
    //                 frontier_log: RollingLog::create(loader, &frontier_file_pattern, ONE_MEGABYTE).ok()?,
    //             },
    //         })
    //     } else {
    //         None
    //     }
    // }

    pub fn load_full(
        height: u8,
        loader: &mut AtomicStoreLoader,
        file_pattern: &str,
    ) -> Option<Self> {
        let leaf_file_pattern = leaf_file_key(file_pattern);
        let frontier_file_pattern = frontier_file_key(file_pattern);
        let leaf_log = FixedAppendLog::<ArkLoadStore<BaseField>>::load(
            loader,
            &leaf_file_pattern,
            BLS_SCALAR_REPR_BYTE_LEN as u64,
            FILE_ENTRY_COUNT,
        )
        .ok()?;
        let frontier_log = RollingLog::<ArkLoadStore<MerkleFrontier>>::load(
            loader,
            &frontier_file_pattern,
            ONE_MEGABYTE,
        )
        .ok()?;
        if let Some(mut inner_tree) = MerkleTree::new(height) {
            for res in leaf_log.iter() {
                if res.is_err() {
                    return None;
                }
                inner_tree.push(res.unwrap());
            }
            let new_frontier = frontier_log.load_latest().ok()?;
            if inner_tree.get_root_value() == new_frontier.frontier[0] {
                Some(PersistedMerkleTree {
                    inner_tree,
                    logging: Logging::Full {
                        leaf_log,
                        frontier_log,
                    },
                })
            } else {
                None
            }
        } else {
            None
        }
    }
    // pub fn load_pruned(

    // ) -> Option<Self> {

    // }
    // pub fn load_spares(

    // ) -> Option<Self> {

    // }
    // pub fn load_fs_pruned(

    // ) -> Option<Self> {

    // }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> u64 {
        self.inner_tree.num_leaves()
    }

    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    pub fn push(&mut self, elem: BaseField) {
        match self.logging {
            Logging::Full {
                ref mut leaf_log, ..
            } => {
                let _ = leaf_log.store_resource(&elem);
            }
            Logging::FileOnly {
                ref mut leaf_log, ..
            } => {
                let _ = leaf_log.store_resource(&elem);
            }
            Logging::Pruned { .. } => {}
            // Logging::Sparse { .. } => { },
        }
        self.inner_tree.push(elem);
        match self.logging {
            Logging::Full {
                frontier_log: _, ..
            }
            | Logging::FileOnly {
                frontier_log: _, ..
            }
            | Logging::Pruned {
                frontier_log: _, ..
            } => {
                // let _ = frontier_log.store_resource(&MerkleFrontier { height: self.inner_tree.height(), num_leaves: self.inner_tree.num_leaves(), self.inner_tree.get_frontiers() });
            }
        }
    }

    /// Returns the leaf value given a position
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, None if the leaf position has been
    ///   forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<BaseField, MerklePath> {
        self.inner_tree.get_leaf(pos)
    }

    /// Verify an element is a leaf of a Merkle tree given the root of the tree
    /// an a path
    /// * `root_value` - value of the root of the tree
    /// * `elem` - element from which the leaf value is computed
    /// * `proof` - list of node siblings/positions from the leaf to the root
    /// * `returns` - Ok(()) if the verification succeeds, Err(computed_root)
    ///   otherwise
    pub fn check_proof(
        root_value: NodeValue,
        pos: u64,
        elem: BaseField,
        proof: &MerklePath,
    ) -> Result<(), Option<NodeValue>> {
        MerkleTree::check_proof(root_value, pos, elem, proof)
    }

    /// Obtain the root value of the Merkle tree
    pub fn get_root_value(&self) -> NodeValue {
        self.inner_tree.get_root_value()
    }

    pub fn commit_version(&mut self) {
        match self.logging {
            Logging::Full {
                ref mut leaf_log,
                ref mut frontier_log,
            } => {
                let _ = leaf_log.commit_version();
                let _ = frontier_log.commit_version();
            }
            Logging::FileOnly {
                ref mut leaf_log,
                ref mut frontier_log,
            } => {
                let _ = leaf_log.commit_version();
                let _ = frontier_log.commit_version();
            }
            Logging::Pruned {
                ref mut frontier_log,
            } => {
                let _ = frontier_log.commit_version();
            }
            // Logging::Sparse { .. } => { },
        }
    }

    pub fn skip_version(&mut self) {
        match self.logging {
            Logging::Full {
                ref mut leaf_log,
                ref mut frontier_log,
            } => {
                let _ = leaf_log.skip_version();
                let _ = frontier_log.skip_version();
            }
            Logging::FileOnly {
                ref mut leaf_log,
                ref mut frontier_log,
            } => {
                let _ = leaf_log.skip_version();
                let _ = frontier_log.skip_version();
            }
            Logging::Pruned {
                ref mut frontier_log,
            } => {
                let _ = frontier_log.skip_version();
            }
            // Logging::Sparse { .. } => { },
        }
    }
}
