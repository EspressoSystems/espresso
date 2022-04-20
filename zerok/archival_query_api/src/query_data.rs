use zerok_lib::state::{ BlockCommitment, ElaboratedBlock, ElaboratedTransactionHash, ValidatorState, state_comm::LedgerStateCommitment };

pub struct BlockQueryData {
    pub raw_block: ElaboratedBlock,
    pub block_hash: BlockCommitment,
    pub txn_hashes: Vec<ElaboratedTransactionHash>,
}

pub struct StateQueryData {
    pub state: ValidatorState,
    pub commitment: LedgerStateCommitment,
}
