use jf_primitives::merkle_tree::{LookupResult, MerklePath, MerkleTree, NodeValue};
use atomic_store::{AppendLog, AtomicStoreLoader};
use atomic_store::load_store::ArkLoadStore;

use ark_ff::fields::PrimeField;

use std::fmt::Debug;

#[derive(Debug)]
pub struct FullMerkleTree<F: PrimeField> {
    inner_tree: MerkleTree<F>,
    leaf_log: AppendLog<ArkLoadStore<F>>,
}

#[allow(dead_code)]
impl<F> FullMerkleTree<F>
where
    F: PrimeField,
{
    pub fn create(height: u8, loader: &mut AtomicStoreLoader, file_pattern: &str, file_fill_size: u64) -> Option<Self> {
        if let Some(inner_tree) = MerkleTree::new(height) {
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
            for res in leaf_log.iter() {
                if !res.is_ok() {
                    return None;
                }
                inner_tree.push(res.unwrap());
            }
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
    pub fn push(&mut self, elem: F) {
        let _ = self.leaf_log.store_resource(&elem);
        self.inner_tree.push(elem);
    }

    /// Returns the leaf value given a position
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, None if the leaf position has been
    ///   forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<F, MerklePath<F>> {
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
        root_value: NodeValue<F>,
        pos: u64,
        elem: F,
        proof: &MerklePath<F>,
    ) -> Result<(), Option<NodeValue<F>>> {
        MerkleTree::check_proof(root_value, pos, elem, proof)
    }

    /// Obtain the root value of the Merkle tree
    pub fn get_root_value(&self) -> NodeValue<F> {
        self.inner_tree.get_root_value()
    }

    pub fn commit_version(&mut self) {
        self.leaf_log.commit_version().unwrap_or(());
    }

    pub fn skip_version(&mut self) {
        self.leaf_log.skip_version().unwrap_or(());
    }
}
