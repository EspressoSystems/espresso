// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use async_trait::async_trait;
use espresso_core::state::{ElaboratedTransaction, ValidatorState};
use futures::stream::{unfold, BoxStream, StreamExt};
use hotshot::{
    traits::NodeImplementation,
    types::{EventType, HotShotHandle},
    HotShotError,
};
use std::error::Error;
use std::fmt::Debug;

pub type ConsensusEvent = EventType<ValidatorState>;

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
impl<N> ValidatorDataSource for HotShotHandle<N>
where
    N: NodeImplementation<StateType = ValidatorState>,
{
    type Error = HotShotError;

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), Self::Error> {
        self.submit_transaction(txn).await
    }

    async fn next_event(&mut self) -> Result<ConsensusEvent, Self::Error> {
        self.next_event().await.map(|e| e.event)
    }
}
