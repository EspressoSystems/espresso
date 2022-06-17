// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

use core::time::Duration;
use phaselock::{data::QuorumCertificate, PubKey, H_256};
use std::collections::HashMap;
use zerok_lib::state::{ElaboratedBlock, ValidatorState};

pub struct PeerInfo {
    pub peer_id: PubKey,
}

#[derive(Default)]
pub struct MempoolInfo {
    pub transaction_count: u64,
    pub output_count: u64,
    pub memory_footprint: u64,
}

#[derive(Default)]
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
