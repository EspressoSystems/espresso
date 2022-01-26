use crate::{
    api,
    api::{ClientError, CommittedTransaction, SpectrumError},
    ledger::SpectrumLedger,
    node,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{ElaboratedTransaction, MERKLE_HEIGHT},
};
use api::{client::*, BlockId, TransactionId};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use async_tungstenite::async_std::connect_async;
use async_tungstenite::tungstenite::Message;
use futures::future::ready;
use futures::prelude::*;
use jf_aap::keys::{UserAddress, UserPubKey};
use jf_aap::proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey, UniversalParam};
use jf_aap::structs::{Nullifier, ReceiverMemo};
use jf_aap::Signature;
use key_set::{ProverKeySet, SizedKey};
use node::LedgerSnapshot;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    hd::KeyTree,
    loader::WalletLoader,
    persistence::AtomicWalletStorage,
    txn_builder::TransactionState,
    BincodeError, ClientConfigError, CryptoError, WalletBackend, WalletError, WalletState,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use std::pin::Pin;
use surf::http::content::{Accept, MediaTypeProposal};
use surf::http::{headers, mime};
pub use surf::Url;

pub struct NetworkBackend<'a, Meta: Serialize + DeserializeOwned> {
    univ_param: &'a UniversalParam,
    query_client: surf::Client,
    bulletin_client: surf::Client,
    validator_client: surf::Client,
    storage: Arc<Mutex<AtomicWalletStorage<'a, SpectrumLedger, Meta>>>,
    key_stream: KeyTree,
}

impl<'a, Meta: Send + Serialize + DeserializeOwned> NetworkBackend<'a, Meta> {
    pub fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        bulletin_url: Url,
        validator_url: Url,
        loader: &mut impl WalletLoader<SpectrumLedger, Meta = Meta>,
    ) -> Result<Self, WalletError<SpectrumLedger>> {
        let storage = AtomicWalletStorage::new(loader, 1024)?;
        Ok(Self {
            query_client: Self::client(query_url)?,
            bulletin_client: Self::client(bulletin_url)?,
            validator_client: Self::client(validator_url)?,
            univ_param,
            key_stream: storage.key_stream(),
            storage: Arc::new(Mutex::new(storage)),
        })
    }

    fn client(base_url: Url) -> Result<surf::Client, WalletError<SpectrumLedger>> {
        let client: surf::Client = surf::Config::new()
            .set_base_url(base_url)
            .try_into()
            .context(ClientConfigError)?;
        Ok(client.with(parse_error_body::<SpectrumError>))
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, WalletError<SpectrumLedger>> {
        let mut res = self
            .query_client
            .get(uri)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, WalletError<SpectrumLedger>>(ClientError)?;
        response_body(&mut res).await.context(ClientError)
    }

    async fn post<T: Serialize>(
        client: &surf::Client,
        uri: impl AsRef<str>,
        body: &T,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        client
            .post(uri)
            .body_bytes(bincode::serialize(body).context(BincodeError)?)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, WalletError<SpectrumLedger>>(ClientError)?;
        Ok(())
    }

    fn accept_header() -> Accept {
        let mut accept = Accept::new();
        // Signal that we would prefer a byte stream using the efficient bincode serialization,
        // but failing that we will take any format the server supports.
        //
        // MediaTypeProposal::new() only fails if the weight is outside the range [0, 1]. Since we
        // are using literal values for the weights, unwrap() is appropriate.
        accept.push(MediaTypeProposal::new(mime::BYTE_STREAM, Some(1.0)).unwrap());
        accept.set_wildcard(true);
        accept
    }
}

#[async_trait]
impl<'a, Meta: Send + Serialize + DeserializeOwned> WalletBackend<'a, SpectrumLedger>
    for NetworkBackend<'a, Meta>
{
    type EventStream = node::EventStream<(LedgerEvent<SpectrumLedger>, EventSource)>;
    type Storage = AtomicWalletStorage<'a, SpectrumLedger, Meta>;

    async fn create(
        &mut self,
    ) -> Result<WalletState<'a, SpectrumLedger>, WalletError<SpectrumLedger>> {
        let LedgerSnapshot {
            state: validator,
            nullifiers,
            records,
            ..
        } = self.get("getsnapshot/0/true").await?;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.univ_param;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_aap::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoError)?
                .0,
            freeze: validator
                .verif_crs
                .freeze
                .iter()
                .map(|k| {
                    Ok::<FreezeProvingKey, WalletError<SpectrumLedger>>(
                        jf_aap::proof::freeze::preprocess(
                            univ_param,
                            k.num_inputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
            xfr: validator
                .verif_crs
                .xfr
                .iter()
                .map(|k| {
                    Ok::<TransferProvingKey, WalletError<SpectrumLedger>>(
                        jf_aap::proof::transfer::preprocess(
                            univ_param,
                            k.num_inputs(),
                            k.num_outputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoError)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
        });

        // `records` should be _almost_ completely sparse. However, even a fully pruned Merkle tree
        // contains the last leaf appended, but as a new wallet, we don't care about _any_ of the
        // leaves, so make a note to forget the last one once more leaves have been appended.
        let merkle_leaf_to_forget = if records.0.num_leaves() > 0 {
            Some(records.0.num_leaves() - 1)
        } else {
            None
        };

        let state = WalletState {
            proving_keys,
            txn_state: TransactionState {
                validator,

                nullifiers,
                record_mt: records.0,
                merkle_leaf_to_forget,
                now: Default::default(),
                records: Default::default(),

                transactions: Default::default(),
            },
            key_scans: Default::default(),
            key_state: Default::default(),
            auditable_assets: Default::default(),
            audit_keys: Default::default(),
            freeze_keys: Default::default(),
            user_keys: Default::default(),
            defined_assets: Default::default(),
        };
        self.storage().await.create(&state).await?;

        Ok(state)
    }

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    fn key_stream(&self) -> KeyTree {
        self.key_stream.clone()
    }

    async fn subscribe(&self, from: EventIndex, to: Option<EventIndex>) -> Self::EventStream {
        // In the current setup, all events come from a single source, which we call the query
        // service even though it has the responsibilties of query service and bulletin board. In
        // the future, these should be split into different services and treated as different event
        // sources.
        let from = from.index(EventSource::QueryService);
        let to = to.map(|to| to.index(EventSource::QueryService));

        let mut url = self
            .query_client
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .join(&format!("subscribe/{}", from))
            .unwrap();
        url.set_scheme("ws").unwrap();

        //todo !jeb.bearer handle connection failures.
        // This should only fail if the server is incorrect or down, so we should handle by retrying
        // or failing over to a different server.
        let all_events = connect_async(url)
            .await
            .expect("failed to connect to server")
            .0;
        let chosen_events: Pin<Box<dyn Stream<Item = _> + Send>> = if let Some(to) = to {
            Box::pin(all_events.take(to - from))
        } else {
            Box::pin(all_events)
        };

        Box::pin(
            chosen_events
                //todo !jeb.bearer handle stream errors
                // If there is an error in the stream, or the server sends us invalid data, we
                // should retry or fail over to a different server.
                .filter_map(|msg| {
                    let item = match msg {
                        Ok(Message::Binary(bytes)) => bincode::deserialize(&bytes).ok(),
                        Ok(Message::Text(json)) => serde_json::from_str(&json).ok(),
                        _ => None,
                    }
                    .map(|event| (event, EventSource::QueryService));
                    ready(item)
                }),
        )
    }

    async fn get_public_key(
        &self,
        address: &UserAddress,
    ) -> Result<UserPubKey, WalletError<SpectrumLedger>> {
        self.get(format!("getuser/{}", api::UserAddress(address.clone())))
            .await
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError<SpectrumLedger>> {
        if let Some(ret) = set.contains(nullifier) {
            Ok(ret)
        } else {
            let api::NullifierProof { proof, spent, .. } = self
                .get(format!("/getnullifier/{}/{}", set.hash(), nullifier))
                .await?;
            set.remember(nullifier, proof.clone()).unwrap();
            Ok((spent, proof))
        }
    }

    async fn get_transaction(
        &self,
        txn_id: u64,
        block_id: u64,
    ) -> Result<ElaboratedTransaction, WalletError<SpectrumLedger>> {
        let txn_id = TransactionId(BlockId(block_id as usize), txn_id as usize);
        let CommittedTransaction { data, proofs, .. } =
            self.get(format!("/gettransaction/{}", txn_id)).await?;
        Ok(ElaboratedTransaction { txn: data, proofs })
    }

    async fn register_user_key(
        &mut self,
        pub_key: &UserPubKey,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        Self::post(&self.bulletin_client, "/users", pub_key).await
    }

    async fn submit(
        &mut self,
        txn: ElaboratedTransaction,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        Self::post(&self.validator_client, "/submit", &txn).await
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        signature: Signature,
    ) -> Result<(), WalletError<SpectrumLedger>> {
        let txid = TransactionId(BlockId(block_id as usize), txn_id as usize);
        let body = api::PostMemos { memos, signature };
        Self::post(&self.bulletin_client, format!("/memos/{}", txid), &body).await
    }
}
