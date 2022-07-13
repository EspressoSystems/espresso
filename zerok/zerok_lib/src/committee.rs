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

use hotshot::committee::DynamicCommittee;
use hotshot::data::{Stage, StateHash};
use hotshot::H_256;
use hotshot_types::data::ViewNumber;
use hotshot_types::traits::election::Election;
use hotshot_types::traits::signature_key::EncodedSignature;
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;

use crate::{PrivKey, PubKey};

/// A structure for committee election.
pub struct Committee<S, const N: usize> {
    /// A table mapping public keys with their associated stake.
    stake_table: BTreeMap<PubKey, u64>,

    /// Inner structure for committee election.
    _election: PhantomData<DynamicCommittee<S, N>>,

    /// State phantom.
    _state_phantom: PhantomData<S>,
}

impl<S, const N: usize> Committee<S, N> {
    /// Creates a new committee.
    pub fn new(stake_table: BTreeMap<PubKey, u64>) -> Self {
        Self {
            stake_table,
            _election: PhantomData,
            _state_phantom: PhantomData,
        }
    }
}

impl<S: Send + Sync + Default, const N: usize> Election<PubKey, N> for Committee<S, N> {
    /// A table mapping public keys with their associated stake.
    type StakeTable = BTreeMap<PubKey, u64>;

    /// Constructed by `p * pow(2, 256)`, where `p` is the predetermined probability of a stake
    /// being selected. A stake will be selected iff `H(vrf_output | stake)` is smaller than the
    /// selection threshold.
    type SelectionThreshold = [u8; H_256];

    /// Arbitrary state type. It's not used since the stake table is stateless for now.
    type State = S;

    /// A membership proof.
    type VoteToken = EncodedSignature;

    /// A tuple of a validated vote token and the associated selected stake.
    type ValidatedVoteToken = (PubKey, EncodedSignature, HashSet<u64>);

    /// The stake table is stateless for now.
    fn get_stake_table(&self, _state: &Self::State) -> Self::StakeTable {
        self.stake_table.clone()
    }

    /// Determines the leader.
    fn get_leader(
        &self,
        table: &Self::StakeTable,
        view_number: ViewNumber,
        _stage: Stage,
    ) -> PubKey {
        DynamicCommittee::<S, N>::get_leader(table, view_number)
    }

    /// Validates a vote token.
    fn get_votes(
        &self,
        table: &Self::StakeTable,
        selection_threshold: Self::SelectionThreshold,
        view_number: ViewNumber,
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
        view_number: ViewNumber,
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
