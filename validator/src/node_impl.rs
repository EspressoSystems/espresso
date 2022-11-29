// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use core::fmt::Debug;
use core::marker::PhantomData;
use espresso_core::{
    stake_table::{Election, VrfParam},
    state::ValidatorState,
};
use hotshot::{
    traits::{election::vrf::VRFPubKey, NetworkingImplementation, NodeImplementation, Storage},
    types::Message,
};
use jf_primitives::signatures::BLSSignatureScheme;

pub type SignatureKey = VRFPubKey<BLSSignatureScheme<VrfParam>>;

/// A lightweight node that handles validation for consensus, and nothing more.
pub trait PLNet:
    NetworkingImplementation<Message<ValidatorState, SignatureKey>, SignatureKey>
    + Clone
    + Debug
    + 'static
{
}

impl<
        T: NetworkingImplementation<Message<ValidatorState, SignatureKey>, SignatureKey>
            + Clone
            + Debug
            + 'static,
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
    type StateType = ValidatorState;
    type Storage = STORE;
    type Networking = NET;
    type Election = Election;
    type SignatureKey = SignatureKey;
}
