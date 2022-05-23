use core::time::Duration;
use phaselock::{data::QuorumCertificate, PubKey, H_256};
use std::collections::HashMap;
use zerok_lib::state::{ElaboratedBlock, ValidatorState};

pub struct PeerInfo {
    pub peer_id: PubKey,
}

pub struct MempoolInfo {
    pub transaction_count: u64,
    pub output_count: u64,
    pub memory_footprint: u64,
}

pub struct ValidatorStatus {
    pub peer_list: Vec<PeerInfo>,
    // TBD; these are going to correspond to active views, possibly want to also retain recent views?
    // We may or may not want a seperate map of QuorumCertificates for `qc/:index` endpoint.
    pub pending_blocks: HashMap<u64, (ElaboratedBlock, ValidatorState, QuorumCertificate<H_256>)>,
    pub latest_block_id: u64, // id of latest block to reach DECIDE
    pub mempool_info: MempoolInfo,
    pub proposed_block_count: u64,
    pub decided_block_count: u64,
    pub abandoned_block_count: u64,
    pub time_operational: Duration,
}
