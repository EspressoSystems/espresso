// Integration test for network query API.
//
// Spin up a query server, and then run
//      cargo run --bin test_query_api -- --host $HOST --port $PORT
// If the command line options --host and --port are not specified, they default to localhost and
// 50000, respectively.
//
// The test is written to validate any conforming query API implementation for any network. It does
// not make assumptions about the ledger state but instead uses the query API to discover things
// about the ledger and then checks that the rest of the API is consistent with those results. It
// does require that the network is in a steady-state while the test is running; that is, new
// transactions are not being submitted.
//
// This test works well with the multi-machine demo, which populuates a ledger with some non-trivial
// state and serves a query API. To use with the demo, run the demo to completion following the
// instructions in examples/multi_machine/README.md. Be sure to use the `--full` flag to at least
// one of the nodes, because a full node is required to host the query service. After the demo has
// completed all rounds, leave at least one of the full node processes running, and then run this
// test, pointing it at the URL of one of the full nodes.

use async_std::future::timeout;
use futures::prelude::*;
use itertools::izip;
use phaselock::BlockContents;
use serde::Deserialize;
use std::fmt::Display;
use std::time::Duration;
use structopt::StructOpt;
use strum::AsStaticRef;
use surf_sse::{EventSource, Url};
use tracing::{event, Level};
use zerok_lib::api::*;
use zerok_lib::node::{LedgerEvent, LedgerSummary};
use zerok_lib::ElaboratedBlock;

#[derive(StructOpt)]
struct Args {
    /// Hostname or IP address of the query server.
    #[structopt(short = "-H", long = "--host", default_value = "localhost")]
    host: String,

    /// Port number of the query service.
    #[structopt(short = "-P", long = "--port", default_value = "50000")]
    port: u64,
}

fn url(route: impl Display) -> Url {
    let Args { host, port } = Args::from_args();
    Url::parse(format!("http://{}:{}{}", host, port, route).as_str()).unwrap()
}

async fn get<T: for<'de> Deserialize<'de>, S: Display>(route: S) -> T {
    let url = url(route);
    event!(Level::INFO, "GET {}", url);
    serde_json::from_value(surf::get(url).recv_json().await.unwrap()).unwrap()
}

async fn validate_committed_block(
    block: &CommittedBlock,
    ix: usize,
    num_blocks: usize,
    num_records: usize,
) {
    // Check well-formedness of the data.
    assert_eq!(ix, block.index);
    assert!(block.index < num_blocks);
    assert_eq!(block.index, block.id.0);
    assert_eq!(block.hash, Hash::from(ElaboratedBlock::from(block).hash()));

    // Check that we get the same block if we query by other methods.
    assert_eq!(*block, get(format!("/getblock/{}", block.id)).await);
    assert_eq!(*block, get(format!("/getblock/hash/{}", block.hash)).await);
    if ix == num_blocks - 1 {
        assert_eq!(*block, get("/getblock/latest").await);
    }

    // Check the other block-related queries.
    assert_eq!(
        block.id,
        get(format!("/getblockid/index/{}", block.index)).await
    );
    assert_eq!(
        block.id,
        get(format!("/getblockid/hash/{}", block.hash)).await
    );
    assert_eq!(block.hash, get(format!("/getblockhash/{}", block.id)).await);
    assert_eq!(
        block.hash,
        get(format!("/getblockhash/index/{}", block.index)).await
    );

    // Check the block's transactions.
    for tx in &block.transactions {
        // Check that the transaction listed in the block is the same transaction we would get if we
        // queried directly.
        assert_eq!(*tx, get(format!("/gettransaction/{}", tx.id)).await);

        // Check uids.
        assert_eq!(tx.output_uids.len(), tx.data.output_len());
        for uid in &tx.output_uids {
            assert!((*uid as usize) < num_records);
        }

        // Check memos.
        let memos = match (&tx.output_memos, &tx.memos_signature) {
            (Some(memos), Some(sig)) => {
                assert_eq!(memos.len(), tx.data.output_len());
                tx.data.verify_receiver_memos_signature(memos, sig).unwrap();
                memos.iter().cloned().map(Some).collect()
            }
            (None, None) => vec![None; tx.data.output_len()],
            (Some(_), None) => panic!("memos are provided without a signature"),
            (None, Some(_)) => panic!("signature is provied without memos"),
        };

        // Check outputs.
        for (i, (output, uid, memo)) in
            izip!(tx.data.output_commitments(), &tx.output_uids, memos).enumerate()
        {
            // Check that we get the same record if we query for the output directly.
            let utxo: UnspentRecord =
                get(format!("/getunspentrecord/{}/{}/{}", tx.id, i, false)).await;
            assert_eq!(output, utxo.commitment);
            assert_eq!(*uid, utxo.uid);
            assert_eq!(memo, utxo.memo);
        }
    }
}

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let summary: LedgerSummary = get("/getinfo").await;
    let num_blocks = summary.num_blocks;
    let num_records = summary.num_records;

    // Check that querying for pieces of the summary directly gives results consistent with the
    // whole summary.
    assert_eq!(num_blocks, get::<usize, _>("/getblockcount").await);

    // Check that we can query the 0th block and the last block.
    for ix in [0, num_blocks - 1].iter() {
        let block = get(format!("/getblock/index/{}", *ix)).await;
        validate_committed_block(&block, *ix, num_blocks, num_records).await;
    }

    // Check the event stream. The event stream is technically never-ending; once we have received
    // all the events that have been generated, the stream will block until a new event is
    // generated, which may never happen. So, we will pull events out of the stream until we hit a 5
    // second delay between events, at which point we will consider the stream to have reached a
    // steady-state.
    let mut events1 = vec![];
    let mut stream1 = EventSource::new(url("/subscribe/0"));
    while let Ok(Some(event)) = timeout(Duration::from_secs(5), stream1.next()).await {
        events1.push(event.unwrap());
    }
    // We should have gotten some events.
    assert!(!events1.is_empty());

    //Subscribe again at a different offset so we can check consistency between streams starting at
    // different times.
    let events2 = EventSource::new(url("/subscribe/1"))
        .take(events1.len() - 1)
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(&events1[1..], &events2);

    // Check validity of the individual events. The events are just serialized LedgerEvents, not an
    // API-specific type, so as long as they deserialize properly they should be fine.
    for event in events1.into_iter() {
        let ledger_event: LedgerEvent = serde_json::from_str(event.data.as_str()).unwrap();
        assert_eq!(event.event, ledger_event.as_static());
    }
}
