use jf_primitives::merkle_tree::{LookupResult, MerklePath, MerkleTree, NodeValue};
use atomic_store::{AppendLog, AtomicStoreLoader};

use std::fmt::Debug;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FullMerkleTree<T>
where
    T: Into<NodeValue> + Clone + Copy + PartialEq + Eq + Debug,
{
    inner_tree: MerkleTree<T>,
    leaf_log: Arc<RwLock<AppendLog<T>>>,
}

impl<T> FullMerkleTree<T>
where
    T: Into<NodeValue> + Clone + Copy + PartialEq + Eq + Debug,
{
    pub fn create(height: u8, loader: &mut AtomicStoreLoader, file_pattern: &str, file_fill_size: u64) -> Option<Self> {
        if let Some(mut inner_tree) = MerkleTree::new(height) {
            let leaf_log = AppendLog::create(loader, file_pattern, file_fill_size).ok()?;
            Some(FullMerkleTree {
                inner_tree,
                leaf_log,
            })
        } else {
            None
        }
    }
    pub fn load(height: u8, loader: &mut AtomicStoreLoader, file_pattern: &str, file_fill_size: u64) -> Option<Self> {
        if let Some(mut inner_tree) = MerkleTree::new(height) {
            let leaf_log = AppendLog::load(loader, file_pattern, file_fill_size).ok()?;
            leaf_log.iter().map(|value| inner_tree.push(value));
            Some(FullMerkleTree {
                inner_tree,
                leaf_log,
            })
        } else {
            None
        }
    }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> u64 {
        self.inner_tree.num_leaves()
    }

    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    pub fn push(&mut self, elem: T) {
        self.inner_tree.push(elem.clone());
        self.leaf_log.store_resource(elem);
    }

    /// Returns the leaf value given a position
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, None if the leaf position has been
    ///   forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<T, MerklePath> {
        self.inner_tree.get_leaf(pos)
    }

    /// Obtain the root value of the Merkle tree
    pub fn get_root_value(&self) -> NodeValue {
        self.inner_tree.get_root_value()
    }

    pub fn commit_version(&mut self) {
        self.leaf_log.commit_version().ok_or_else(());
    }

    pub fn skip_version(&mut self) {
        self.leaf_log.skip_version().ok_or_else(());
    }
}
