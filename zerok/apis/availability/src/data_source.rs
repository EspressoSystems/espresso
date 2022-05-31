use crate::query_data::{BlockQueryData, StateQueryData};
use jf_cap::MerkleTree;
use zerok_lib::state::{BlockCommitment, ElaboratedTransactionHash};

/// Trait to be implemented on &'a DataSource for lifetime management purposes
pub trait AvailabilityDataSource {
    type BlockIterType: AsRef<[BlockQueryData]>;
    type StateIterType: AsRef<[StateQueryData]>;
    fn get_nth_block_iter(self, n: usize) -> Self::BlockIterType;
    fn get_nth_state_iter(self, n: usize) -> Self::StateIterType;
    fn get_block_index_by_hash(self, hash: BlockCommitment) -> Option<u64>;
    fn get_txn_index_by_hash(self, hash: ElaboratedTransactionHash) -> Option<(u64, u64)>;
    fn get_record_index_by_uid(self, uid: u64) -> Option<(u64, u64, u64)>; // None if OOB
                                                                           // it should be possible to implement this one in terms of the above,
                                                                           // leaving more compact and/or performant solutions as optional
    fn get_record_merkle_tree_at_block_index(self, n: usize) -> Option<MerkleTree>;
}
