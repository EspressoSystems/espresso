use phaselock::{
    committee::DynamicCommittee, data::StateHash, traits::Election, PrivKey, PubKey, H_256,
};
use std::collections::{hash_map::HashMap, HashSet};
use std::marker::PhantomData;

use threshold_crypto as tc;

/// A structure for committee election.
pub struct Committee<S, const N: usize> {
    /// A table mapping public keys with their associated stake.
    stake_table: HashMap<PubKey, u64>,

    /// Inner structure for committee election.
    _election: PhantomData<DynamicCommittee<S, N>>,

    /// State phantom.
    _state_phantom: PhantomData<S>,
}

impl<S, const N: usize> Committee<S, N> {
    /// Creates a new committee.
    pub fn new(stake_table: HashMap<PubKey, u64>) -> Self {
        Self {
            stake_table,
            _election: PhantomData,
            _state_phantom: PhantomData,
        }
    }
}

impl<S, const N: usize> Election<N> for Committee<S, N> {
    /// A table mapping public keys with their associated stake.
    type StakeTable = HashMap<PubKey, u64>;

    /// Constructed by `p * pow(2, 256)`, where `p` is the predetermined probability of a stake
    /// being selected. A stake will be selected iff `H(vrf_output | stake)` is smaller than the
    /// selection threshold.
    type SelectionThreshold = [u8; H_256];

    /// Arbitrary state type. It's not used since the stake table is stateless for now.
    type State = S;

    /// A membership proof.
    type VoteToken = tc::SignatureShare;

    /// A tuple of a validated vote token and the associated selected stake.
    type ValidatedVoteToken = (PubKey, tc::SignatureShare, HashSet<u64>);

    /// The stake table is stateless for now.
    fn get_stake_table(&self, _state: &Self::State) -> Self::StakeTable {
        self.stake_table.clone()
    }

    /// Determines the leader.
    fn get_leader(&self, table: &Self::StakeTable, view_number: u64) -> PubKey {
        DynamicCommittee::<S, N>::get_leader(table, view_number)
    }

    /// Validates a vote token.
    fn get_votes(
        &self,
        table: &Self::StakeTable,
        selection_threshold: Self::SelectionThreshold,
        view_number: u64,
        pub_key: PubKey,
        token: Self::VoteToken,
        next_state: StateHash<N>,
    ) -> Option<Self::ValidatedVoteToken> {
        DynamicCommittee::<S, N>::get_votes(
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
        DynamicCommittee::<S, N>::get_vote_count(token)
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
        next_state: StateHash<N>,
    ) -> Option<Self::VoteToken> {
        DynamicCommittee::<S, N>::make_vote_token(
            table,
            selection_threshold,
            view_number,
            private_key,
            next_state,
        )
    }
}
