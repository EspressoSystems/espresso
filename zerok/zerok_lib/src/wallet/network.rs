use super::persistence::{AtomicWalletStorage, WalletLoader};
use super::{
    ClientConfigError, CryptoError, WalletBackend, WalletError, WalletImmutableKeySet, WalletState,
};
use crate::api;
use crate::ledger::AAPLedger;
use crate::set_merkle_tree::{SetMerkleProof, SetMerkleTree};
use crate::state::key_set::SizedKey;
use crate::state::{ElaboratedTransaction, ProverKeySet, MERKLE_HEIGHT};
use crate::txn_builder::TransactionState;
use crate::{node, node::MerkleTreeWithArbitrary};
use api::{client::*, BlockId, ClientError, CommittedTransaction, FromError, TransactionId};
use async_std::sync::{Arc, Mutex, MutexGuard};
use async_trait::async_trait;
use async_tungstenite::async_std::connect_async;
use async_tungstenite::tungstenite::Message;
use futures::future::ready;
use futures::prelude::*;
use jf_txn::keys::{UserAddress, UserKeyPair, UserPubKey};
use jf_txn::proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey, UniversalParam};
use jf_txn::structs::{Nullifier, ReceiverMemo};
use jf_txn::Signature;
use node::{LedgerEvent, LedgerSnapshot};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt;
use std::convert::TryInto;
use surf::http::content::{Accept, MediaTypeProposal};
use surf::http::{headers, mime};
pub use surf::Url;

pub struct NetworkBackend<'a, Meta: Serialize + DeserializeOwned> {
    univ_param: &'a UniversalParam,
    query_client: surf::Client,
    bulletin_client: surf::Client,
    validator_client: surf::Client,
    storage: Arc<Mutex<AtomicWalletStorage<'a, AAPLedger, Meta>>>,
    key_pair: Option<UserKeyPair>,
}

impl<'a, Meta: Send + Serialize + DeserializeOwned> NetworkBackend<'a, Meta> {
    pub fn new(
        univ_param: &'a UniversalParam,
        query_url: Url,
        bulletin_url: Url,
        validator_url: Url,
        loader: &mut impl WalletLoader<Meta = Meta>,
    ) -> Result<Self, WalletError> {
        Ok(Self {
            query_client: Self::client(query_url)?,
            bulletin_client: Self::client(bulletin_url)?,
            validator_client: Self::client(validator_url)?,
            univ_param,
            storage: Arc::new(Mutex::new(AtomicWalletStorage::new(loader)?)),
            key_pair: loader.key_pair(),
        })
    }

    fn client(base_url: Url) -> Result<surf::Client, WalletError> {
        let client: surf::Client = surf::Config::new()
            .set_base_url(base_url)
            .try_into()
            .context(ClientConfigError)?;
        Ok(client.with(parse_error_body))
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        uri: impl AsRef<str>,
    ) -> Result<T, WalletError> {
        let mut res = self
            .query_client
            .get(uri)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, WalletError>(ClientError)?;
        response_body(&mut res).await.context(ClientError)
    }

    async fn post<T: Serialize>(
        client: &surf::Client,
        uri: impl AsRef<str>,
        body: &T,
    ) -> Result<(), WalletError> {
        client
            .post(uri)
            .body_bytes(bincode::serialize(body).map_err(WalletError::from_api_error)?)
            .header(headers::ACCEPT, Self::accept_header())
            .send()
            .await
            .context::<_, WalletError>(ClientError)?;
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
impl<'a, Meta: Send + Serialize + DeserializeOwned> WalletBackend<'a, AAPLedger>
    for NetworkBackend<'a, Meta>
{
    type EventStream = node::EventStream<LedgerEvent>;
    type Storage = AtomicWalletStorage<'a, AAPLedger, Meta>;

    async fn create(&mut self) -> Result<WalletState<'a>, WalletError> {
        let mut rng = ChaChaRng::from_entropy();
        let LedgerSnapshot {
            state: validator,
            nullifiers,
            records,
            ..
        } = self.get("getsnapshot/0/true").await?;

        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = self.univ_param;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_txn::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoError)?
                .0,
            freeze: validator
                .verif_crs
                .freeze
                .iter()
                .map(|k| {
                    Ok::<FreezeProvingKey, WalletError>(
                        jf_txn::proof::freeze::preprocess(
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
                    Ok::<TransferProvingKey, WalletError>(
                        jf_txn::proof::transfer::preprocess(
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
            immutable_keys: Arc::new(WalletImmutableKeySet {
                key_pair: self
                    .key_pair
                    .clone()
                    .unwrap_or_else(|| UserKeyPair::generate(&mut rng)),
            }),
            txn_state: TransactionState {
                validator,

                nullifiers,
                record_mt: MerkleTreeWithArbitrary(records.0),
                merkle_leaf_to_forget,
                now: 0,
                records: Default::default(),

                transactions: Default::default(),
            },
            auditable_assets: Default::default(),
            audit_keys: Default::default(),
            freeze_keys: Default::default(),
            defined_assets: Default::default(),
        };
        self.storage().await.create(&state).await?;

        // Publish the address of the new wallet.
        Self::post(
            &self.bulletin_client,
            "/users",
            &state.immutable_keys.key_pair.pub_key(),
        )
        .await?;

        Ok(state)
    }

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn subscribe(&self, starting_at: u64) -> Self::EventStream {
        let mut url = self
            .query_client
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .join(&format!("subscribe/{}", starting_at))
            .unwrap();
        url.set_scheme("ws").unwrap();

        //todo !jeb.bearer handle connection failures.
        // This should only fail if the server is incorrect or down, so we should handle by retrying
        // or failing over to a different server.
        Box::pin(
            connect_async(url)
                .await
                .expect("failed to connect to server")
                .0
                //todo !jeb.bearer handle stream errors
                // If there is an error in the stream, or the server sends us invalid data, we
                // should retry or fail over to a different server.
                .filter_map(|msg| {
                    ready(match msg {
                        Ok(Message::Binary(bytes)) => bincode::deserialize(&bytes).ok(),
                        Ok(Message::Text(json)) => serde_json::from_str(&json).ok(),
                        _ => None,
                    })
                }),
        )
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        self.get(format!("getuser/{}", api::UserAddress(address.clone())))
            .await
    }

    async fn get_nullifier_proof(
        &self,
        set: &mut SetMerkleTree,
        nullifier: Nullifier,
    ) -> Result<(bool, SetMerkleProof), WalletError> {
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
    ) -> Result<ElaboratedTransaction, WalletError> {
        let txn_id = TransactionId(BlockId(block_id as usize), txn_id as usize);
        let CommittedTransaction { data, proofs, .. } =
            self.get(format!("/gettransaction/{}", txn_id)).await?;
        Ok(ElaboratedTransaction { txn: data, proofs })
    }

    async fn submit(&mut self, txn: ElaboratedTransaction) -> Result<(), WalletError> {
        Self::post(&self.validator_client, "/submit", &txn).await
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        signature: Signature,
    ) -> Result<(), WalletError> {
        let txid = TransactionId(BlockId(block_id as usize), txn_id as usize);
        let body = api::PostMemos { memos, signature };
        Self::post(&self.bulletin_client, format!("/memos/{}", txid), &body).await
    }
}
