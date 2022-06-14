use jf_cap::structs::Nullifier;
use zerok_lib::state::SetMerkleProof;

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
