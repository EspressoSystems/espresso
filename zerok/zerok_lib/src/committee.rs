use crate::ValidatorState;
use phaselock::{committee::DynamicCommittee, traits::Election, BlockHash, PrivKey, PubKey, H_256};
use std::collections::{hash_map::HashMap, HashSet};

use threshold_crypto as tc;

/// A structure for committee election.
pub struct Committee<const N: usize>(DynamicCommittee<ValidatorState, N>);

impl<const N: usize> Election<N> for Committee<N> {
    /// A table mapping public keys with their associated stake.
    type StakeTable = HashMap<PubKey, u64>;

    /// Constructed by `p * pow(2, 256)`, where `p` is the predetermined probablistic of a stake
    /// being selected. A stake will be selected iff `H(vrf_output | stake)` is smaller than the
    /// selection threshold.
    type SelectionThreshold = [u8; H_256];

    /// The state this election implementation is bound to.
    type State = ValidatorState;

    /// A membership proof.
    type VoteToken = tc::SignatureShare;

    /// A tuple of a validated vote token and the associated selected stake.
    type ValidatedVoteToken = (PubKey, tc::SignatureShare, HashSet<u64>);

    fn get_stake_table(&self, _state: &Self::State) -> Self::StakeTable {
        unimplemented!("TODO");
    }

    /// Determines the leader.
    fn get_leader(&self, table: &Self::StakeTable, view_number: u64) -> PubKey {
        self.0.get_leader(table, view_number)
    }

    /// Validates a vote token.
    fn get_votes(
        &self,
        table: &Self::StakeTable,
        selection_threshold: Self::SelectionThreshold,
        view_number: u64,
        pub_key: PubKey,
        token: Self::VoteToken,
        next_state: BlockHash<N>,
    ) -> Option<Self::ValidatedVoteToken> {
        self.0.get_votes(
            table,
            selection_threshold,
            view_number,
            pub_key,
            token,
            next_state,
        )
    }

    /// Returns the number of votes a validated token has.
    fn get_vote_count(&self, token: &Self::ValidatedVoteToken) -> u64 {
        self.0.get_vote_count(token)
    }

    /// Attempts to generate a vote token for self.
    ///
    /// Returns null if the stake data isn't found or the number of votes is zero.
    fn make_vote_token(
        &self,
        table: &Self::StakeTable,
        selection_threshold: Self::SelectionThreshold,
        view_number: u64,
        private_key: &PrivKey,
        next_state: BlockHash<N>,
    ) -> Option<Self::VoteToken> {
        self.0.make_vote_token(
            table,
            selection_threshold,
            view_number,
            private_key,
            next_state,
        )
    }
}
