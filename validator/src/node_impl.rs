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

use core::fmt::Debug;
use core::marker::PhantomData;
use espresso_core::{
    committee::Committee,
    state::{LWPersistence, ValidatorState},
    PubKey,
};
use hotshot::{
    traits::{NetworkingImplementation, NodeImplementation, Storage},
    types::Message,
};

/// A lightweight node that handles validation for consensus, and nothing more.
pub trait PLNet:
    NetworkingImplementation<Message<ValidatorState, PubKey>, PubKey> + Clone + Debug + 'static
{
}

impl<
        T: NetworkingImplementation<Message<ValidatorState, PubKey>, PubKey> + Clone + Debug + 'static,
    > PLNet for T
{
}

pub trait PLStore: Storage<ValidatorState> + Clone + Send + Sync + 'static {}

impl<T: Storage<ValidatorState> + Clone + Send + Sync + 'static> PLStore for T {}

#[derive(Clone)]
pub struct ValidatorNodeImpl<NET: PLNet, STORE: PLStore> {
    net: PhantomData<NET>,
    store: PhantomData<STORE>,
}

impl<NET: PLNet, STORE: PLStore> Debug for ValidatorNodeImpl<NET, STORE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatorNodeImpl").finish()
    }
}

impl<NET: PLNet, STORE: PLStore> NodeImplementation for ValidatorNodeImpl<NET, STORE> {
    type State = ValidatorState;

    type Storage = STORE;

    type Networking = NET;

    type StatefulHandler = LWPersistence;

    type Election = Committee<ValidatorState>;

    type SignatureKey = PubKey;
}