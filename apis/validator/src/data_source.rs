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

use async_trait::async_trait;
use espresso_core::state::{ElaboratedBlock, ElaboratedTransaction, ValidatorState};
use futures::stream::{unfold, BoxStream, StreamExt};
use hotshot::{
    traits::NodeImplementation,
    types::{EventType, HotShotHandle},
    HotShotError, H_256,
};
use std::error::Error;
use std::fmt::Debug;

pub type ConsensusEvent = EventType<ElaboratedBlock, ValidatorState, H_256>;

#[async_trait]
pub trait ValidatorDataSource {
    type Error: Error + Debug;
    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), Self::Error>;
    async fn next_event(&mut self) -> Result<ConsensusEvent, Self::Error>;

    fn into_stream(self) -> BoxStream<'static, ConsensusEvent>
    where
        Self: 'static + Send + Sized,
    {
        unfold(self, |mut consensus| async move {
            match consensus.next_event().await {
                Ok(event) => Some((event, consensus)),
                Err(err) => panic!("unexpected error from HotShotHandle::next_event: {:?}", err),
            }
        })
        .boxed()
    }
}

#[async_trait]
impl<N> ValidatorDataSource for HotShotHandle<N, H_256>
where
    N: NodeImplementation<H_256, Block = ElaboratedBlock, State = ValidatorState>,
{
    type Error = HotShotError;

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), Self::Error> {
        self.submit_transaction(txn).await
    }

    async fn next_event(&mut self) -> Result<ConsensusEvent, Self::Error> {
        self.next_event().await.map(|e| e.event)
    }
}
