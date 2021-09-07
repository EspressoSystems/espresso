use crate::{
    set_merkle_tree::*, ElaboratedBlock, ElaboratedTransaction, LedgerEvent, ValidationError,
    ValidatorState,
};
use async_executors::exec::AsyncStd;
use async_std::sync::{Arc, RwLock};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::RemoteHandle;
pub use futures::prelude::*;
pub use futures::stream::Stream;
use futures::task::SpawnExt;
use jf_txn::structs::Nullifier;
use phaselock::{
    error::PhaseLockError,
    event::Event as PhaseLockEvent,
    handle::{HandleError, PhaseLockHandle},
};
use std::collections::BTreeMap;
use std::pin::Pin;

type PhaseLockEventStream =
    Pin<Box<dyn Send + Stream<Item = PhaseLockEvent<ElaboratedBlock, ValidatorState>>>>;

#[async_trait]
pub trait Validator {
    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError>;
    async fn start_consensus(&self);
    async fn subscribe(&self) -> PhaseLockEventStream;
}

/// A lightweight node handles consensus, and nothing more.
pub type LightWeightNode = PhaseLockHandle<ElaboratedBlock, 64>;

#[async_trait]
impl Validator for LightWeightNode {
    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError> {
        self.submit_transaction(tx).await.map_err(|err| {
            if let HandleError::Transaction { source } = err {
                source
            } else {
                panic!(
                    "unexpected error from PhaseLockHandle::submit_transaction: {:?}",
                    err
                );
            }
        })
    }

    async fn start_consensus(&self) {
        self.start().await
    }

    async fn subscribe(&self) -> PhaseLockEventStream {
        // Convert from the Future-based setting of next_event() to an asynchronous stream setting
        // using `stream::unfold`.
        Box::pin(stream::unfold(self.clone(), |mut handle| async move {
            match handle.next_event().await {
                Ok(event) => Some((event, handle)),
                Err(HandleError::ShutDown) => None,
                Err(HandleError::Skipped { ammount }) => {
                    unimplemented!("handling for {:?} skipped events", ammount)
                }
                Err(err) => panic!(
                    "unexpected error from PhaseLockHandle::next_event: {:?}",
                    err
                ),
            }
        }))
    }
}

/// A QueryService accumulates the full state of the ledger, making it available for consumption by
/// network APIs and such.
#[async_trait]
pub trait QueryService {
    type EventStream: Stream<Item = LedgerEvent>;

    /// Get the `i`th committed block and the state at the time just before the block was committed.
    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock);

    /// Query whether a nullifier is in the nullifier set, and retrieve a proof of inclusion or
    /// exclusion.
    async fn nullifier_proof(&self, n: Nullifier) -> (bool, SetMerkleProof);

    /// Get an asynchronous stream which yields LedgerEvents when things happen on the ledger or
    /// the associated bulletin board.
    async fn subscribe(&self, i: u64) -> Self::EventStream;
}

struct FullState {
    validator: ValidatorState,
    nullifiers: SetMerkleTree,
    // All past states and state transitions of the ledger.
    history: Vec<(ValidatorState, ElaboratedBlock)>,
    // The last block which was proposed. This is currently used to correllate BadBlock and
    // InconsistentBlock errors from PhaseLock with the block that caused the error. In the future,
    // PhaseLock errors will contain the bad block (or some kind of reference to it, perhaps through
    // persistent storage) and this will not be necessary.
    proposed: ElaboratedBlock,
    // All past events, so that clients can subscribe to an event stream starting at a time in the
    // past.
    events: Vec<LedgerEvent>,
    // The send ends of all channels which are subscribed to events.
    subscribers: Vec<mpsc::UnboundedSender<LedgerEvent>>,
    // Clients which have subscribed to events starting at some time in the future, to be added to
    // `subscribers` when the time comes.
    pending_subscribers: BTreeMap<u64, Vec<mpsc::UnboundedSender<LedgerEvent>>>,
}

impl FullState {
    fn update(&mut self, event: PhaseLockEvent<ElaboratedBlock, ValidatorState>) {
        use phaselock::event::EventType::*;
        match event.event {
            Error { error } => {
                if matches!(
                    *error,
                    PhaseLockError::BadBlock { .. } | PhaseLockError::InconsistentBlock { .. }
                ) {
                    // If the error is due to a bad block, correllate it with the block that caused
                    // the error (`self.proposed` in our current hacky solution, but eventually
                    // saved somewhere in storage) and send the block through our mirror of the
                    // validator to get a helpful error.
                    let err = match self.validator.validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        self.proposed.block.clone(),
                        self.proposed.proofs.clone(),
                        true,
                    ) {
                        Err(err) => err,
                        Ok(_) => {
                            // Something weird happened: the validator reported a bad block, but our
                            // mirror of the ValidatorState accepts the block. It's unclear what
                            // this means, but we can report a generic error to the subscribers.
                            ValidationError::Failed {}
                        }
                    };
                    self.send_event(LedgerEvent::Reject(self.proposed.clone(), err));
                }

                // PhaseLock errors that don't relate to blocks being rejected (view timeouts,
                // network errors, etc.) do not correspond to LedgerEvents.
            }

            Propose { block } => {
                self.proposed = (*block).clone();
            }

            Decide { block, state } => {
                let prev_state = self.validator.clone();

                // A block has been committed. Update our mirror of the ValidatorState by applying
                // the new block, and generate a Commit event.
                if self
                    .validator
                    .validate_and_apply(
                        self.validator.prev_commit_time + 1,
                        block.block.clone(),
                        block.proofs.clone(),
                        true,
                    )
                    .is_err()
                    || self.validator.commit() != state.commit()
                {
                    // We update our ValidatorState for each block committed by the PhaseLock event
                    // source, so we shouldn't ever get out of sync.
                    panic!("state is out of sync with validator");
                } else {
                    // Add the results of this block to our state.
                    self.history.push((prev_state, (*block).clone()));
                    for txn in block.block.0.iter() {
                        for n in txn.nullifiers() {
                            self.nullifiers.insert(n);
                        }
                    }
                    // Notify subscribers of the new block.
                    self.send_event(LedgerEvent::Commit((*block).clone(), vec![]));
                }
            }

            _ => {}
        }
    }

    fn send_event(&mut self, event: LedgerEvent) {
        // Subscribers who asked for a subscription starting from the current time can now be added
        // to the list of active subscribers.
        let now = self.events.len() as u64;
        if let Some(new_subscribers) = self.pending_subscribers.remove(&now) {
            self.subscribers.extend(new_subscribers);
        }

        // Send the message to all active subscribers. Filter out subscribers where the send fails,
        // which means that the client has disconnected.
        self.subscribers = std::mem::take(&mut self.subscribers)
            .into_iter()
            .filter(|subscriber| subscriber.unbounded_send(event.clone()).is_ok())
            .collect();

        // Save the event so we can feed it to later subscribers who want to start from some time in
        // the past.
        self.events.push(event);
    }

    fn subscribe(&mut self, t: u64) -> Pin<Box<dyn Stream<Item = LedgerEvent>>> {
        let (sender, receiver) = mpsc::unbounded();
        if (t as usize) < self.events.len() {
            // If the start time is in the past, send the subscriber all saved events since the
            // start time and make them an active subscriber starting now.
            self.subscribers.push(sender);
            let past_events = self
                .events
                .iter()
                .skip(t as usize)
                .cloned()
                .collect::<Vec<_>>();
            Box::pin(stream::iter(past_events).chain(receiver))
        } else {
            // Otherwise, add the subscriber to the list of pending subscribers to start receiving
            // events at time `t`.
            self.pending_subscribers.entry(t).or_default().push(sender);
            Box::pin(receiver)
        }
    }
}

/// A QueryService that aggregates the full ledger state by observing consensus.
pub struct PhaseLockQueryService {
    state: Arc<RwLock<FullState>>,
    // When dropped, this handle will cancel and join the event handling task. It is not used
    // explicitly; it is merely stored with the rest of the struct for the auto-generated drop glue.
    _event_task: RemoteHandle<()>,
}

impl PhaseLockQueryService {
    pub async fn new<V: Validator>(
        v: &V,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        validator: ValidatorState,
        nullifiers: SetMerkleTree,
    ) -> Self {
        let event_source = v.subscribe().await;

        //todo !jeb.bearer If we are not starting from the genesis of the ledger, query the full
        // state at this point from another full node, like
        //  let state = other_node.full_state(validator.commit());
        // For now, just assume we are starting at the beginning:
        let history = Vec::new();
        let events = Vec::new();

        let state = Arc::new(RwLock::new(FullState {
            validator,
            nullifiers,
            history,
            proposed: ElaboratedBlock::default(),
            events,
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
        }));

        // Spawn event handling task.
        let task = {
            let state = state.clone();
            let mut event_source = Box::pin(event_source);
            AsyncStd::new()
                .spawn_with_handle(async move {
                    while let Some(event) = event_source.next().await {
                        state.write().await.update(event);
                    }
                })
                .unwrap()
        };

        Self {
            state,
            _event_task: task,
        }
    }
}

#[async_trait]
impl QueryService for PhaseLockQueryService {
    type EventStream = Pin<Box<dyn Stream<Item = LedgerEvent>>>;

    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock) {
        let state = self.state.read().await;
        state.history[i as usize].clone()
    }

    async fn nullifier_proof(&self, n: Nullifier) -> (bool, SetMerkleProof) {
        let state = self.state.read().await;
        state.nullifiers.contains(n).unwrap()
    }

    async fn subscribe(&self, i: u64) -> Self::EventStream {
        let mut state = self.state.write().await;
        state.subscribe(i)
    }
}

/// A full node is a QueryService running alongside a lightweight validator.
pub struct FullNode {
    validator: LightWeightNode,
    query_service: PhaseLockQueryService,
}

impl FullNode {
    pub async fn new(
        validator: LightWeightNode,

        // The current state of the network.
        //todo !jeb.bearer Query these parameters from another full node if we are not starting off
        // a fresh network.
        state: ValidatorState,
        nullifiers: SetMerkleTree,
    ) -> Self {
        let query_service = PhaseLockQueryService::new(&validator, state, nullifiers).await;
        Self {
            validator,
            query_service,
        }
    }

    fn as_validator(&self) -> &impl Validator {
        &self.validator
    }

    fn as_query_service(
        &self,
    ) -> &impl QueryService<EventStream = <Self as QueryService>::EventStream> {
        &self.query_service
    }
}

#[async_trait]
impl Validator for FullNode {
    async fn submit_transaction(&self, tx: ElaboratedTransaction) -> Result<(), PhaseLockError> {
        self.as_validator().submit_transaction(tx).await
    }

    async fn start_consensus(&self) {
        self.as_validator().start_consensus().await
    }

    async fn subscribe(&self) -> PhaseLockEventStream {
        self.as_validator().subscribe().await
    }
}

#[async_trait]
impl QueryService for FullNode {
    type EventStream = <PhaseLockQueryService as QueryService>::EventStream;

    async fn get_block(&self, i: u64) -> (ValidatorState, ElaboratedBlock) {
        self.as_query_service().get_block(i).await
    }

    async fn nullifier_proof(&self, n: Nullifier) -> (bool, SetMerkleProof) {
        self.as_query_service().nullifier_proof(n).await
    }

    async fn subscribe(&self, i: u64) -> Self::EventStream {
        self.as_query_service().subscribe(i).await
    }
}
