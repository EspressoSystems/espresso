use crate::{ElaboratedBlock, ValidatorState};
use phaselock::{traits::StatefulHandler, H_256};

use core::fmt::Debug;

pub struct LWPersistence {}

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

impl StatefulHandler<H_256> for LWPersistence {
    type Block = ElaboratedBlock;
    type State = ValidatorState;

    fn notify(&mut self, blocks: Vec<Self::Block>, states: Vec<Self::State>) {
        if blocks.is_empty() || states.is_empty() {
            return;
        }
        self.store_latest_state(&blocks[0], &states[0]);
    }
}
