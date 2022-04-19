use zerok_lib::state::{ BlockCommitment, ElaboratedBlock, ElaboratedTransactionHash, ValidatorState, state_comm::LedgerStateCommitment };

pub struct BlockQueryData {
    raw_block: ElaboratedBlock,
    block_hash: BlockCommitment,
    txn_hashes: Vec<ElaboratedTransactionHash>,
}

pub struct StateQueryData {
    state: ValidatorState,
    commitment: LedgerStateCommitment,
}
