use crate::{ElaboratedBlock, ValidatorState, ValidatorStatePersisted, VerifierKeySet, verif_crs_comm::VerifCRSCommitment};
use atomic_store::{
    AtomicStore,
    load_store::BincodeLoadStore,
    RollingLog
};
use jf_txn::MerkleLeafProof;
use phaselock::{traits::StatefulHandler, H_512};

use core::fmt::Debug;
use std::path::PathBuf;

pub struct LWPersistence {
    lw_store_path: PathBuf,
    key_tag: String,
    atomic_store: AtomicStore,
    state_snapshot: RollingLog<BincodeLoadStore<ValidatorStatePersisted>>,
    record_frontier_snapshot: RollingLog<BincodeLoadStore<MerkleLeafProof>>,
    verifier_key_set_latest: RollingLog<BincodeLoadStore<VerifierKeySet>>,
    verif_crs_commit: VerifCRSCommitment,
}

impl LWPersistence {
    pub fn new(_key_tag: &str) -> LWPersistence {
        LWPersistence {}
    }

    pub fn store_latest_state(&mut self, _block: &ElaboratedBlock, _state: &ValidatorState) {}
}

impl Debug for LWPersistence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LWPersistence").finish()
    }
}

impl StatefulHandler<H_512> for LWPersistence {
    type Block = ElaboratedBlock;
    type State = ValidatorState;

    fn notify(&mut self, blocks: Vec<Self::Block>, states: Vec<Self::State>) {
        if blocks.is_empty() || states.is_empty() {
            return;
        }
        self.store_latest_state(&blocks[0], &states[0]);
    }
}
