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

use espresso_core::state::SetMerkleProof;
use jf_cap::structs::Nullifier;

pub trait MetaStateDataSource {
    fn get_nullifier_proof_for(
        self,
        block_id: u64,
        nullifier: Nullifier,
    ) -> Option<(bool, SetMerkleProof)>;
}

pub trait UpdateMetaStateData {
    type Error;

    fn append_block_nullifiers(
        &mut self,
        block_id: u64,
        nullifiers: Vec<Nullifier>,
    ) -> Result<(), Self::Error>;
}
