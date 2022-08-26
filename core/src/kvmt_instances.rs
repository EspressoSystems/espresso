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

use crate::state::{CommitableHash, CommitableHashTag, StakingKey};
use serde::{Deserialize, Serialize};

//Identifying tag for BlockToView KVMT
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) struct BlockToViewTag();
impl CommitableHashTag for BlockToViewTag {
    fn commitment_diversifier() -> &'static str {
        "Block number to View number tag"
    }
}

pub(crate) type BlockToViewCommittableHash = CommitableHash<u64, u64, BlockToViewTag>;

//Identifying tag for StakeKeyToStakeAmount KVMT
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) struct StakeKeyToStakeAmountTag();
impl CommitableHashTag for StakeKeyToStakeAmountTag {
    fn commitment_diversifier() -> &'static str {
        "Block number to View number tag"
    }
}

pub(crate) type StakeKeyToStakeAmountCommittableHash =
    CommitableHash<StakingKey, u64, StakeKeyToStakeAmountTag>;
