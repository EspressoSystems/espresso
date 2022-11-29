// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use async_trait::async_trait;
use espresso_core::ledger::EspressoLedger;
use postage::broadcast::Receiver;
use seahorse::events::LedgerEvent;
use std::error::Error;
use std::fmt::Debug;

pub trait CatchUpDataSource {
    type EventIterType: Iterator<Item = Option<LedgerEvent<EspressoLedger>>>;

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
    fn subscribe(&self) -> Receiver<(usize, Option<LedgerEvent<EspressoLedger>>)>;
}

#[async_trait]
pub trait UpdateCatchUpData {
    type Error: Error + Debug;

    fn event_count(&self) -> usize;

    async fn append_events(
        &mut self,
        events: Vec<Option<LedgerEvent<EspressoLedger>>>,
    ) -> Result<(), Self::Error>;
}
