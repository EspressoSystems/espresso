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

use async_channel::Receiver;
use espresso_core::ledger::EspressoLedger;
use seahorse::events::LedgerEvent;
use std::error::Error;
use std::fmt::Debug;

pub trait CatchUpDataSource {
    type EventIterType: Iterator<Item = LedgerEvent<EspressoLedger>>;

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
    fn subscribe(&self) -> Receiver<(usize, LedgerEvent<EspressoLedger>)> {
        unimplemented!()
    }
}

pub trait UpdateCatchUpData {
    type Error: Error + Debug;

    fn event_count(&self) -> usize;

    fn append_events(
        &mut self,
        events: &mut Vec<LedgerEvent<EspressoLedger>>,
    ) -> Result<(), Self::Error>;
}
