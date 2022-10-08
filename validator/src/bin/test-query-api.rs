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

// Integration test for network query API.
//
// Spin up a query server, and then run
//      cargo run --bin test_query_api -- --host $HOST --port $PORT
// If the command line options --host and --port are not specified, they default to localhost and
// 50000, respectively.
//
// The test is written to validate any conforming query API implementation for any network. It does
// not make assumptions about the ledger state but instead uses the query API to discover things
// about the ledger and then checks that the rest of the API is consistent with those results.
//
// This test works well with the multi-machine demo, which populuates a ledger with some non-trivial
// state and serves a query API. Be sure to use the `esqs` command to at least one of the nodes, and
// then run this test, pointing it at the URL of one of the full nodes.

use ark_serialize::CanonicalSerialize;
use async_std::future::timeout;
use async_tungstenite::async_std::connect_async;
use clap::Parser;
use commit::Committable;
use espresso_availability_api::query_data::*;
use espresso_core::{ledger::EspressoLedger, state::BlockCommitment};
use espresso_esqs::ApiError;
use espresso_metastate_api::api::NullifierCheck;
use futures::prelude::*;
use hotshot_types::data::ViewNumber;
use itertools::izip;
use reef::traits::Transaction;
use seahorse::{events::LedgerEvent, hd::KeyTree, loader::KeystoreLoader, KeySnafu, KeystoreError};
use serde::Deserialize;
use snafu::ResultExt;
use std::fmt::Display;
use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;
use surf_disco::Url;
use tempdir::TempDir;
use tracing::{event, Level};

#[derive(Parser)]
struct Args {
    /// Hostname or IP address of the query server.
    #[arg(short = 'H', long = "--host", default_value = "localhost")]
    host: String,

    /// Port number of the query service.
    #[arg(short = 'P', long = "--port", default_value = "50000")]
    port: u16,
}

fn url_with_scheme(opt: &Args, scheme: impl Display, route: impl Display) -> Url {
    Url::parse(format!("{}://{}:{}{}", scheme, opt.host, opt.port, route).as_str()).unwrap()
}

fn url(opt: &Args, route: impl Display) -> Url {
    url_with_scheme(opt, "http", route)
}

async fn get<T: for<'de> Deserialize<'de>, S: Display>(opt: &Args, route: S) -> T {
    let url = url(opt, route);
    event!(Level::INFO, "GET {}", url);
    surf_disco::get::<T, ApiError>(url).send().await.unwrap()
}

async fn validate_committed_block(
    opt: &Args,
    block: &BlockQueryData,
    summary: &BlockSummaryQueryData,
    ix: u64,
    num_blocks: u64,
) {
    // Check well-formedness of the data.
    assert_eq!(ix, block.block_id);
    assert!(ix < num_blocks);
    assert_eq!(
        block.block_hash,
        BlockCommitment(block.raw_block.block.commit()),
    );

    // Check that we get the same block if we query by other methods.
    assert_eq!(
        *block,
        get(
            opt,
            format!("/availability/getblock/hash/{}", block.block_hash)
        )
        .await
    );

    // Check the output state of this block.
    let state: StateQueryData =
        get(opt, format!("/availability/getstate/{}", block.block_id)).await;
    assert_eq!(state.block_id, ix);

    // Check the block's transactions.
    let mut uid = block.records_from;
    for (i, hash) in block.txn_hashes.iter().enumerate() {
        // Check that the transaction listed in the block is the same transaction we would get if we
        // queried directly.
        let txn: TransactionQueryData =
            get(opt, format!("/availability/gettransaction/hash/{}", hash)).await;
        assert_eq!(
            txn,
            get(opt, format!("/availability/gettransaction/{}/{}", ix, i)).await
        );
        assert_eq!(txn.block_id, ix);
        assert_eq!(txn.txn_id, i as u64);
        assert_eq!(txn.transaction_hash, *hash);

        // Check inputs.
        for n in txn.raw_transaction.input_nullifiers() {
            let check: NullifierCheck =
                get(opt, format!("/metastate/check_nullifier/{}/{}", ix, n)).await;
            assert!(check.spent);
            assert_eq!(
                check
                    .proof
                    .check(n, &state.state.nullifiers_root())
                    .unwrap(),
                check.spent
            );
        }

        // Check outputs.
        for (j, (output, uid)) in izip!(txn.raw_transaction.output_commitments(), uid..).enumerate()
        {
            // Check that we get the same record if we query for the output directly.
            let utxo: RecordQueryData =
                get(opt, format!("/availability/getrecord/{}/{}/{}", ix, i, j)).await;
            assert_eq!(
                utxo,
                get(opt, format!("/availability/getrecord/uid/{}", uid)).await
            );
            assert_eq!(output, utxo.commitment);
            assert_eq!(utxo.uid, uid);
            assert_eq!(utxo.block_id, ix);
            assert_eq!(utxo.txn_id, i as u64);
            assert_eq!(utxo.output_index, j as u64);
        }
        uid += txn.raw_transaction.output_len() as u64;
    }
    assert_eq!(uid, block.records_from + block.record_count);

    // Check the block summary.
    assert_eq!(summary.size, block.raw_block.serialized_size());
    assert_eq!(summary.txn_count, block.txn_hashes.len());
    assert_eq!(summary.records_from, block.records_from);
    assert_eq!(summary.record_count, block.record_count);
    let view_number: ViewNumber = get(opt, format!("/availability/getviewnumber/{}", ix)).await;
    assert_eq!(summary.view_number, *view_number.deref());
}

struct UnencryptedKeystoreLoader {
    dir: TempDir,
}

impl KeystoreLoader<EspressoLedger> for UnencryptedKeystoreLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.dir.path().into()
    }

    fn create(&mut self) -> Result<(Self::Meta, KeyTree), KeystoreError<EspressoLedger>> {
        let key = KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)?;
        Ok(((), key))
    }

    fn load(&mut self, _meta: &mut Self::Meta) -> Result<KeyTree, KeystoreError<EspressoLedger>> {
        KeyTree::from_password_and_salt(&[], &[0; 32]).context(KeySnafu)
    }
}

async fn test(opt: &Args) {
    let num_blocks = get::<u64, _>(opt, "/status/latest_block_id").await + 1;

    assert_eq!(
        get::<Option<String>, _>(opt, "/status/location").await,
        Some("My location".to_string())
    );

    // Get the block summaries.
    let block_summaries: Vec<BlockSummaryQueryData> = get(
        opt,
        format!(
            "/availability/getblocksummary/{}/{}",
            num_blocks - 1,
            num_blocks
        ),
    )
    .await;
    assert_eq!(block_summaries.len() as u64, num_blocks);

    // Check that we can query the 0th block and the last block.
    for ix in [0, num_blocks - 1].iter() {
        let block = get(opt, format!("/availability/getblock/{}", *ix)).await;
        validate_committed_block(
            opt,
            &block,
            &block_summaries[(num_blocks - 1 - *ix) as usize],
            *ix,
            num_blocks,
        )
        .await;
    }

    // Check the event stream. The event stream is technically never-ending; once we have received
    // all the events that have been generated, the stream will block until a new event is
    // generated, which may never happen. So, we will pull events out of the stream until we hit a 5
    // second delay between events, at which point we will consider the stream to have reached a
    // steady-state.
    let mut events1 = vec![];
    let mut stream1 = connect_async(url_with_scheme(
        opt,
        "ws",
        "/catchup/subscribe_for_events/0",
    ))
    .await
    .unwrap()
    .0;
    while let Ok(Some(event)) = timeout(Duration::from_secs(5), stream1.next()).await {
        events1.push(event.unwrap());
    }
    // We should have gotten some events.
    assert!(!events1.is_empty());

    // Subscribe again at a different offset so we can check consistency between streams starting at
    // different times.
    let events2 = connect_async(url_with_scheme(
        opt,
        "ws",
        "/catchup/subscribe_for_events/1",
    ))
    .await
    .unwrap()
    .0
    .take(events1.len() - 1)
    .try_collect::<Vec<_>>()
    .await
    .unwrap();
    assert_eq!(&events1[1..], &events2);

    // Check validity of the individual events. The events are just serialized LedgerEvents, not an
    // API-specific type, so as long as they deserialize properly they should be fine.
    for event in events1.into_iter() {
        serde_json::from_str::<LedgerEvent<EspressoLedger>>(event.to_text().unwrap()).unwrap();
    }
}

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    test(&Args::parse()).await
}

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use super::*;
    use espresso_client::{network::NetworkBackend, Keystore};
    use espresso_core::universal_params::UNIVERSAL_PARAM;
    use espresso_validator::testing::minimal_test_network;
    use jf_cap::{keys::UserKeyPair, structs::AssetCode};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use tracing_test::traced_test;

    #[cfg(feature = "slow-tests")]
    #[async_std::test]
    #[traced_test]
    async fn test_query_api() {
        let mut rng = ChaChaRng::from_seed([1; 32]);
        let faucet_key_pair = UserKeyPair::generate(&mut rng);
        let network = minimal_test_network(&mut rng, faucet_key_pair.pub_key()).await;

        // Create two wallets and transfer from one to the other, to populate the ledger.
        let mut loader1 = UnencryptedKeystoreLoader {
            dir: TempDir::new("test_query_api").unwrap(),
        };
        let mut keystore1 = Keystore::new(
            NetworkBackend::new(
                &UNIVERSAL_PARAM,
                network.query_api.clone(),
                network.address_book_api.clone(),
                network.submit_api.clone(),
            )
            .await
            .unwrap(),
            &mut loader1,
        )
        .await
        .unwrap();
        let mut loader2 = UnencryptedKeystoreLoader {
            dir: TempDir::new("test_query_api").unwrap(),
        };
        let mut keystore2 = Keystore::new(
            NetworkBackend::new(
                &UNIVERSAL_PARAM,
                network.query_api.clone(),
                network.address_book_api.clone(),
                network.submit_api.clone(),
            )
            .await
            .unwrap(),
            &mut loader2,
        )
        .await
        .unwrap();
        keystore1
            .add_sending_account(
                faucet_key_pair.clone(),
                "faucet account".into(),
                Default::default(),
            )
            .await
            .unwrap();
        keystore1
            .await_key_scan(&faucet_key_pair.address())
            .await
            .unwrap();
        let receiver = keystore2
            .generate_sending_account("receiver account".into(), None)
            .await
            .unwrap();
        let receipt = keystore1
            .transfer(None, &AssetCode::native(), &[(receiver, 100)], 1)
            .await
            .unwrap();
        keystore1.await_transaction(&receipt).await.unwrap();

        test(&Args {
            host: "localhost".into(),
            port: network.query_api.port().unwrap(),
        })
        .await
    }
}
