// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use espresso_core::state::SetMerkleProof;
use jf_cap::structs::Nullifier;
use std::error::Error;
use std::fmt::Debug;

pub trait MetaStateDataSource {
    fn get_nullifier_proof_for(
        &self,
        block_id: u64,
        nullifier: Nullifier,
    ) -> Option<(bool, SetMerkleProof)>;
}

pub trait UpdateMetaStateData {
    type Error: Error + Debug;

    fn append_block_nullifiers(
        &mut self,
        block_id: u64,
        nullifiers: Vec<Nullifier>,
    ) -> Result<(), Self::Error>;
}
