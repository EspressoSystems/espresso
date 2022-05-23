use zerok_lib::state::{
    state_comm::LedgerStateCommitment, BlockCommitment, ElaboratedBlock, ElaboratedTransactionHash,
    ValidatorState,
};

pub struct BlockQueryData {
    pub raw_block: ElaboratedBlock,
    pub block_hash: BlockCommitment,
    pub block_id: u64,
    pub txn_hashes: Vec<ElaboratedTransactionHash>,
}

pub struct StateQueryData {
    pub state: ValidatorState,
    pub commitment: LedgerStateCommitment,
    pub block_id: u64,
    pub event_index: u64,
}
