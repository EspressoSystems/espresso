use super::{ClientConfigError, CryptoError, WalletBackend, WalletError, WalletState};
use crate::api;
use crate::key_set::SizedKey;
use crate::node;
use crate::set_merkle_tree::{set_hash, SetMerkleProof};
use crate::{ElaboratedTransaction, ProverKeySet, MERKLE_HEIGHT};
use api::{middleware, BlockId, ClientError, FromError, TransactionId};
use async_trait::async_trait;
use futures::prelude::*;
use futures_timer::Delay;
use http_types::content::{Accept, MediaTypeProposal};
use http_types::{headers, mime};
use jf_txn::keys::{AuditorKeyPair, FreezerKeyPair, UserAddress, UserKeyPair, UserPubKey};
use jf_txn::proof::UniversalParam;
use jf_txn::structs::{Nullifier, ReceiverMemo};
use jf_txn::Signature;
use node::{LedgerEvent, LedgerSnapshot};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use std::time::Duration;
pub use surf::Url;

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
            .content_type(mime::JSON)
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
    type EventStream = node::EventStream<LedgerEvent>;

    async fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
        // todo !jeb.bearer We don't support storing yet, so this function currently just loads from
        // the initial state of the ledger using the /getsnapshot method of the query service. This
        // is equivalent to creating a new wallet.

        let mut rng = ChaChaRng::from_entropy();
        let LedgerSnapshot {
            state: validator,
            nullifiers,
        } = self.get("getsnapshot/0/true").await?;

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

        // Publish the address of the new wallet.
        self.bulletin_client
            .post("/users")
            .content_type(mime::JSON)
            .body_json(&key_pair.pub_key())
            .context(ClientError)?
            .send()
            .await
            .context(ClientError)?;

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
        let client = self.query_client.clone();
        let url = format!("/subscribe/{}", starting_at);
        let res = client.get(url.clone()).send().await.unwrap();
        let state = SSEState {
            client,
            url,
            retry_time: Duration::from_secs(3),
            last_id: None,
            stream: sse_codec::decode_stream(res),
        };

        Box::pin(futures::stream::unfold(state, |mut state| async move {
            // Retry on errors until we get a message or the end of the stream.
            loop {
                match state.stream.next().await {
                    Some(Ok(sse_codec::Event::Retry { retry })) => {
                        // A retry message instructs us to set the retry duration, but we have
                        // nothing to yield, so we continue waiting for another message.
                        state.retry_time = Duration::from_millis(retry);
                    }
                    Some(Ok(sse_codec::Event::Message { data, id, .. })) => {
                        if let Some(id) = id {
                            // Mark our place in the stream in case we have to reconnect.
                            state.last_id = Some(id);
                        }
                        if let Ok(event) = serde_json::from_str(&data) {
                            // Yield the event.
                            return Some((event, state));
                        } else {
                            // Got invalid data from the server. Treat this as an error and
                            // reconnect. This may be a good point to try to fail over to another
                            // query service.
                            state.reconnect().await;
                        }
                    }
                    Some(Err(_)) => {
                        // On errors, we wait for the duration of the retry time and then
                        // reestablish the connection.
                        state.reconnect().await;
                    }
                    None => {
                        // End of stream.
                        return None;
                    }
                }
            }
        }))
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        self.get(format!("getuser/{}", api::UserAddress(address.clone())))
            .await
    }

    async fn prove_nullifier_unspent(
        &self,
        root: set_hash::Hash,
        nullifier: Nullifier,
    ) -> Result<SetMerkleProof, WalletError> {
        let api::NullifierProof { proof, spent, .. } = self
            .get(format!("/getnullifier/{}/{}", root, nullifier))
            .await?;
        if spent {
            Err(WalletError::NullifierAlreadyPublished { nullifier })
        } else {
            Ok(proof)
        }
    }

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
        self.validator_client
            .post("submit")
            .body_json(&txn)
            .context(ClientError)?
            .send()
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
            .send()
            .await
            .context(ClientError)?;
        Ok(())
    }
}

struct SSEState {
    client: surf::Client,
    url: String,
    retry_time: Duration,
    last_id: Option<String>,
    stream: sse_codec::DecodeStream<surf::Response>,
}

impl SSEState {
    async fn reconnect(&mut self) {
        loop {
            Delay::new(self.retry_time).await;
            let mut req = self.client.get(self.url.clone());
            if let Some(id) = &self.last_id {
                req = req.header("Last-Event-Id", id);
            }
            if let Ok(res) = req.send().await {
                self.stream = sse_codec::decode_stream(res);
                break;
            }
        }
    }
}
