use crate::{
    api,
    api::{ClientError, EspressoError},
    ledger::EspressoLedger,
    node,
    set_merkle_tree::{SetMerkleProof, SetMerkleTree},
    state::{ElaboratedTransaction, MERKLE_HEIGHT},
};
use address_book::InsertPubKey;
use api::client::*;
use async_std::{
    sync::{Arc, Mutex, MutexGuard},
    task::sleep,
};
use async_trait::async_trait;
use async_tungstenite::async_std::connect_async;
use async_tungstenite::tungstenite::Message;
use futures::future::ready;
use futures::prelude::*;
use jf_cap::keys::{UserAddress, UserKeyPair, UserPubKey};
use jf_cap::proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey, UniversalParam};
use jf_cap::structs::Nullifier;
use jf_cap::MerkleTree;
use key_set::{ProverKeySet, SizedKey};
use net::{BlockId, TransactionId};
use node::{LedgerSnapshot, LedgerSummary};
use seahorse::txn_builder::PendingTransaction;
use seahorse::txn_builder::TransactionInfo;
use seahorse::{
    events::{EventIndex, EventSource, LedgerEvent},
    hd::KeyTree,
    loader::KeystoreLoader,
    persistence::AtomicKeystoreStorage,
    txn_builder::TransactionState,
    BincodeSnafu, ClientConfigSnafu, CryptoSnafu, KeystoreBackend, KeystoreError, KeystoreState,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use std::pin::Pin;
use std::time::Duration;
use surf::http::content::{Accept, MediaTypeProposal};
use surf::http::{headers, mime};
pub use surf::Url;

pub struct NetworkBackend<'a, Meta: PartialEq + Serialize + DeserializeOwned + Clone> {
    univ_param: &'a UniversalParam,
    query_client: surf::Client,
    address_book_client: surf::Client,
    validator_client: surf::Client,
    storage: Arc<Mutex<AtomicKeystoreStorage<'a, EspressoLedger, Meta>>>,
    key_stream: KeyTree,
}

impl<'a, Meta: Clone + PartialEq + Send + Serialize + DeserializeOwned> NetworkBackend<'a, Meta> {
    pub async fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        address_book_url: Url,
        validator_url: Url,
        loader: &mut impl KeystoreLoader<EspressoLedger, Meta = Meta>,
    ) -> Result<NetworkBackend<'a, Meta>, KeystoreError<EspressoLedger>> {
        let storage = AtomicKeystoreStorage::new(loader, 1024)?;
        let backend = Self {
            query_client: Self::client(query_url)?,
            address_book_client: Self::client(address_book_url)?,
            validator_client: Self::client(validator_url)?,
            univ_param,
            key_stream: storage.key_stream(),
            storage: Arc::new(Mutex::new(storage)),
        };
        backend.wait_for_esqs().await?;
        Ok(backend)
    }

    fn client(base_url: Url) -> Result<surf::Client, KeystoreError<EspressoLedger>> {
        let client: surf::Client = surf::Config::new()
            .set_base_url(base_url)
            .try_into()
            .context(ClientConfigSnafu)?;
        Ok(client.with(parse_error_body::<EspressoError>))
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, KeystoreError<EspressoLedger>> {
        let mut res = self
            .query_client
            .get(uri)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, KeystoreError<EspressoLedger>>(ClientError)?;
        response_body(&mut res).await.context(ClientError)
    }

    async fn post<T: Serialize>(
        client: &surf::Client,
        uri: impl AsRef<str>,
        body: &T,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        client
            .post(uri)
            .body_bytes(bincode::serialize(body).context(BincodeSnafu)?)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, KeystoreError<EspressoLedger>>(ClientError)?;
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

    async fn wait_for_esqs(&self) -> Result<(), KeystoreError<EspressoLedger>> {
        let mut backoff = Duration::from_millis(500);
        for _ in 0..8 {
            // We use a direct `surf::connect` instead of
            // `self.query_client.connect` because the client middleware isn't
            // set up to handle connect requests, only API requests.
            if surf::connect(
                &self
                    .query_client
                    .config()
                    .base_url
                    .as_ref()
                    .expect("esqs config has no base url"),
            )
            .send()
            .await
            .is_ok()
            {
                return Ok(());
            }
            tracing::warn!("unable to connect to EsQS; sleeping for {:?}", backoff);
            sleep(backoff).await;
            backoff *= 2;
        }

        let msg = format!("failed to connect to EQS after {:?}", backoff);
        tracing::error!("{}", msg);
        Err(KeystoreError::Failed { msg })
    }
}

#[async_trait]
impl<'a, Meta: PartialEq + Clone + Send + Serialize + DeserializeOwned>
    KeystoreBackend<'a, EspressoLedger> for NetworkBackend<'a, Meta>
{
    type EventStream = node::EventStream<(LedgerEvent<EspressoLedger>, EventSource)>;
    type Storage = AtomicKeystoreStorage<'a, EspressoLedger, Meta>;

    async fn create(
        &mut self,
    ) -> Result<KeystoreState<'a, EspressoLedger>, KeystoreError<EspressoLedger>> {
        let LedgerSummary {
            num_blocks,
            num_events,
            ..
        } = self.get("getinfo").await?;

        let LedgerSnapshot {
            state: validator,
            nullifiers,
            records,
            ..
        } = self
            .get(&format!("getsnapshot/{}/true", num_blocks))
            .await?;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.univ_param;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_cap::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoSnafu)?
                .0,
            freeze: validator
                .verif_crs
                .freeze
                .iter()
                .map(|k| {
                    Ok::<FreezeProvingKey, KeystoreError<EspressoLedger>>(
                        jf_cap::proof::freeze::preprocess(
                            univ_param,
                            k.num_inputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoSnafu)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
            xfr: validator
                .verif_crs
                .xfr
                .iter()
                .map(|k| {
                    Ok::<TransferProvingKey, KeystoreError<EspressoLedger>>(
                        jf_cap::proof::transfer::preprocess(
                            univ_param,
                            k.num_inputs(),
                            k.num_outputs(),
                            MERKLE_HEIGHT,
                        )
                        .context(CryptoSnafu)?
                        .0,
                    )
                })
                .collect::<Result<_, _>>()?,
        });

        // `records` should be _almost_ completely sparse. However, even a fully pruned Merkle tree
        // contains the last leaf appended, but as a new keystore, we don't care about _any_ of the
        // leaves, so make a note to forget the last one once more leaves have been appended.
        let merkle_leaf_to_forget = if records.0.num_leaves() > 0 {
            Some(records.0.num_leaves() - 1)
        } else {
            None
        };

        let state = KeystoreState {
            proving_keys,
            txn_state: TransactionState {
                validator,

                nullifiers,
                record_mt: records.0,
                merkle_leaf_to_forget,
                now: EventIndex::from_source(EventSource::QueryService, num_events),
                records: Default::default(),

                transactions: Default::default(),
            },
            key_state: Default::default(),
            assets: Default::default(),
            viewing_accounts: Default::default(),
            freezing_accounts: Default::default(),
            sending_accounts: Default::default(),
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
        // All events come from a single source, the EsQS, which aggregates blocks and memos.
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
    ) -> Result<UserPubKey, KeystoreError<EspressoLedger>> {
        let mut res = self
            .address_book_client
            .post("request_pubkey")
            .content_type(mime::JSON)
            .body_json(address)
            .unwrap()
            .send()
            .await
            .context::<_, KeystoreError<EspressoLedger>>(ClientError)?;
        response_body(&mut res).await.context(ClientError)
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), KeystoreError<EspressoLedger>> {
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

    async fn register_user_key(
        &mut self,
        key_pair: &UserKeyPair,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        let pub_key_bytes = bincode::serialize(&key_pair.pub_key()).unwrap();
        let sig = key_pair.sign(&pub_key_bytes);
        let json_request = InsertPubKey { pub_key_bytes, sig };
        dbg!(&self.address_book_client.config().base_url);
        match self
            .address_book_client
            .post("insert_pubkey")
            .content_type(mime::JSON)
            .body_json(&json_request)
            .unwrap()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(KeystoreError::Failed {
                msg: format!("error inserting public key: {}", err),
            }),
        }
    }

    async fn submit(
        &mut self,
        txn: ElaboratedTransaction,
        // TODO: do something with this?
        _txn_info: TransactionInfo<EspressoLedger>,
    ) -> Result<(), KeystoreError<EspressoLedger>> {
        Self::post(&self.validator_client, "/submit", &txn).await
    }

    async fn finalize(
        &mut self,
        txn: PendingTransaction<EspressoLedger>,
        txid: Option<(u64, u64)>,
    ) {
        // -> Result<(), KeystoreError<EspressoLedger>>

        if let Some(txid) = txid {
            let body = api::PostMemos {
                memos: txn
                    .info
                    .memos
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .unwrap(),
                signature: txn.info.sig,
            };
            let txid = TransactionId(BlockId(txid.0 as usize), txid.1 as usize);
            // TODO: fix the trait so we don't need this unwrap
            // TODO: include memos in transactions so we don't have to do this
            Self::post(&self.query_client, format!("/memos/{}", txid), &body)
                .await
                .unwrap()
        }
    }

    async fn get_initial_scan_state(
        &self,
        _from: EventIndex,
    ) -> Result<(MerkleTree, EventIndex), KeystoreError<EspressoLedger>> {
        // TODO: how should this initialize?
        let LedgerSnapshot { records, .. } = self.get("getsnapshot/0/true").await?;
        Ok((records.0, Default::default()))
    }
}
