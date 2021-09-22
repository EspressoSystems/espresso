use super::{ClientConfigError, CryptoError, WalletBackend, WalletError, WalletState};
use crate::api;
use crate::key_set::SizedKey;
use crate::node;
use crate::{ElaboratedTransaction, ProverKeySet, MERKLE_HEIGHT};
use api::{middleware, BlockId, ClientError, TransactionId};
use async_executors::AsyncStd;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::RemoteHandle;
use futures::prelude::*;
use futures::task::{Context, Poll, SpawnExt};
use jf_txn::keys::{AuditorKeyPair, FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey};
use jf_txn::proof::UniversalParam;
use jf_txn::structs::ReceiverMemo;
use jf_txn::Signature;
use node::{LedgerEvent, LedgerSnapshot};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::Deserialize;
use snafu::ResultExt;
use std::convert::TryInto;
use std::pin::Pin;
pub use surf::Url;
use surf_sse::ClientExt;

pub struct NetworkBackend<'a> {
    univ_param: &'a UniversalParam,
    query_client: surf::Client,
    bulletin_client: surf::Client,
    validator_client: surf::Client,
}

impl<'a> NetworkBackend<'a> {
    pub fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        bulletin_url: Url,
        validator_url: Url,
    ) -> Result<Self, WalletError> {
        Ok(Self {
            query_client: Self::client(query_url)?,
            bulletin_client: Self::client(bulletin_url)?,
            validator_client: Self::client(validator_url)?,
            univ_param,
        })
    }

    fn client(base_url: Url) -> Result<surf::Client, WalletError> {
        let client: surf::Client = surf::Config::new()
            .set_base_url(base_url)
            .try_into()
            .context(ClientConfigError)?;
        Ok(client.with(middleware::parse_error_body))
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, WalletError> {
        let mut res = self
            .query_client
            .get(uri)
            .send()
            .await
            .context(ClientError)?;
        middleware::response_body(&mut res)
            .await
            .context(ClientError)
    }
}

#[async_trait]
impl<'a> WalletBackend<'a> for NetworkBackend<'a> {
    type EventStream = EventStream;

    async fn load(&self, _key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
        // todo !jeb.bearer We don't support storing yet, so this function currently just loads from
        // the initial state of the ledger using the /getsnapshot method of the query service. This
        // is equivalent to creating a new wallet.

        let mut rng = ChaChaRng::from_entropy();
        let LedgerSnapshot {
            state: validator,
            nullifiers,
        } = self.get("getsnapshot/0").await?;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.univ_param;
        let proving_keys =
            ProverKeySet {
                mint: jf_txn::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                    .context(CryptoError)?
                    .0,
                freeze: validator
                    .verif_crs
                    .freeze
                    .iter()
                    .map(|k| {
                        Ok(jf_txn::proof::freeze::preprocess(
                            univ_param,
                            k.num_inputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0)
                    })
                    .collect::<Result<_, _>>()?,
                xfr: validator
                    .verif_crs
                    .xfr
                    .iter()
                    .map(|k| {
                        Ok(jf_txn::proof::transfer::preprocess(
                            univ_param,
                            k.num_inputs(),
                            k.num_outputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0)
                    })
                    .collect::<Result<_, _>>()?,
            };

        Ok(WalletState {
            validator,
            proving_keys,
            nullifiers,
            now: 0,
            records: Default::default(),
            defined_assets: Default::default(),
            pending_txns: Default::default(),
            expiring_txns: Default::default(),
            auditable_assets: Default::default(),
            auditor_key_pair: AuditorKeyPair::generate(&mut rng),
            freezer_key_pair: FreezerKeyPair::generate(&mut rng),
            rng,
        })
    }

    async fn store(
        &mut self,
        _key_pair: &UserKeyPair,
        _state: &WalletState,
    ) -> Result<(), WalletError> {
        //todo !jeb.bearer implement
        Ok(())
    }

    async fn subscribe(&self, starting_at: u64) -> Self::EventStream {
        EventStream::new(&self.query_client, starting_at)
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        self.get(format!("getuser/{}", api::UserAddress(address.clone())))
            .await
    }

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
        self.validator_client
            .post("submit")
            .body_json(&txn)
            .context(ClientError)?
            .recv_bytes()
            .await
            .context(ClientError)?;
        Ok(())
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        signature: Signature,
    ) -> Result<(), WalletError> {
        self.bulletin_client
            .post(format!(
                "memos/{}",
                TransactionId(BlockId(block_id as usize), txn_id as usize)
            ))
            .body_json(&api::PostMemos { memos, signature })
            .context(ClientError)?
            .recv_bytes()
            .await
            .context(ClientError)?;
        Ok(())
    }
}

// surf_sse::EventSource is annoyingly not Send (which is required of WalletBackend::EventStream) so
// we need to dedicate a thread to pulling events out of the event source and sending the events
// themselves to the consumer thread over a channel.
//
// This struct facilitates that strategy. It ties a handle for the dedicated thread to the receiver,
// so that the dedicated event handling task will be cancelled and cleaned up if and when the
// receiver is dropped.
//
// Because we need to implement Stream for this type in terms of its field `receiver`, and because
// Stream::poll_next takes a Pin<&mut Self>, we use structural pinning to project a
// Pin<&mutEventStream> into a Pin<&mut UnboundedReceiver>, which is the type that actually
// implements Stream. See the projection function EventStream::receiver() for details.
pub struct EventStream {
    receiver: mpsc::UnboundedReceiver<LedgerEvent>,
    _producer: RemoteHandle<()>,
}

impl EventStream {
    fn new(client: &surf::Client, starting_at: u64) -> Self {
        let (sender, receiver) = mpsc::unbounded();

        let task = {
            let client = client.clone();
            AsyncStd::new()
                .spawn_with_handle(async move {
                    let mut stream = Box::pin(
                        client
                            .connect_event_source(
                                Url::parse(format!("subscribe/{}", starting_at).as_str()).unwrap(),
                            )
                            // EventSource emits an error whenever it is transiently disconnected from
                            // the server, but it reconnects automatically, so we can ignore Err
                            // variants and just take the Ok results.
                            .filter_map(|res| async {
                                res.ok().and_then(|event| {
                                    serde_json::from_str(event.data.as_str()).ok()
                                })
                            }),
                    );
                    while let Some(event) = async_std::task::block_on(stream.next()) {
                        if sender.unbounded_send(event).is_err() {
                            // If we failed to send a message, it means the receiver has been dropped,
                            // so there's no need to send any further messages.
                            break;
                        }
                    }
                })
                .unwrap()
        };

        Self {
            receiver,
            _producer: task,
        }
    }

    fn receiver(self: Pin<&mut Self>) -> Pin<&mut mpsc::UnboundedReceiver<LedgerEvent>> {
        // This projection function implements structural pinning for the `receiver` field:
        // `receiver` is pinned whenever `self` is. This makes it possible to impelement
        // Stream::poll_next (which takes a Pin<&mut Self>) in terms of Self::receiver.
        //
        // See https://doc.rust-lang.org/std/pin/index.html#pinning-is-structural-for-field for the
        // list of requirements that a structurally pinned type must follow for the following unsafe
        // block to be sound.
        unsafe { self.map_unchecked_mut(|stream| &mut stream.receiver) }
    }
}

impl Stream for EventStream {
    type Item = LedgerEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver().poll_next(cx)
    }
}
