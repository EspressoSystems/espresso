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

use serde_json::Value;
use std::fmt::Display;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    /// Hostname or IP address of the query server.
    #[structopt(short = "-H", long = "--host", default_value = "localhost")]
    host: String,

    /// Port number of the query service.
    #[structopt(short = "-P", long = "--port", default_value = "50000")]
    port: u64,
}

async fn get(route: impl Display) -> Value {
    let Args { host, port } = Args::from_args();
    surf::get(format!("http://{}:{}{}", host, port, route))
        .recv_json()
        .await
        .unwrap()
}

#[async_std::main]
async fn main() {
    let summary = get("/getinfo").await;
    let num_blocks = summary["num_blocks"].as_u64().unwrap();
    let _num_records = summary["num_records"].as_u64().unwrap();

    // Check that querying for pieces of the summary directly gives results consistent with the
    // whole summary.
    assert_eq!(num_blocks, get("/getblockcount").await.as_u64().unwrap());

    // Check that we can query the 0th block and the last block.
    for ix in [0, num_blocks - 1] {
        let block = get(format!("/getblock/index/{}", ix)).await;

        // Check well-formedness of the data.
        let id = block["id"].as_str().unwrap();
        let hash = block["hash"].as_str().unwrap();
        let state_comm = block["state_commitment"].as_str().unwrap();
        assert!(id.starts_with("BK~"));
        assert!(hash.starts_with("HASH~"));
        assert!(state_comm.starts_with("HASH~"));
        assert_eq!(ix, block["index"].as_u64().unwrap());

        // Check that we get the same block if we query by other methods.
        assert_eq!(block, get(format!("/getblock/{}", id)).await);
        assert_eq!(block, get(format!("/getblock/hash/{}", hash)).await);
        if ix == num_blocks - 1 {
            assert_eq!(block, get("/getblock/latest").await);
        }

        // Check the other block-related queries.
        assert_eq!(
            id,
            get(format!("/getblockid/index/{}", ix))
                .await
                .as_str()
                .unwrap()
        );
        assert_eq!(
            id,
            get(format!("/getblockid/hash/{}", hash))
                .await
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hash,
            get(format!("/getblockhash/{}", id)).await.as_str().unwrap()
        );
        assert_eq!(
            hash,
            get(format!("/getblockhash/index/{}", ix))
                .await
                .as_str()
                .unwrap()
        );
        // Check the block's transactions.
        for tx in block["transaction_data"].as_array().unwrap() {
            let tx_id = tx["id"].as_str().unwrap();
            let tx = get(format!("/gettransaction/{}", tx_id)).await;

            // Check well-formedness of the data.
            let ty = tx["type"].as_str().unwrap();
            let _fee = tx["fee"].as_u64().unwrap();
            let sig = &tx["memos_signature"];
            let merkle_root = tx["merkle_root"].as_str().unwrap();
            assert_eq!(tx_id, tx["id"].as_str().unwrap());
            match ty {
                "transfer" | "mint" | "freeze" => {}
                _ => panic!("invalid transaction type {}", ty),
            }
            assert!(sig.is_null() || sig.as_str().unwrap().starts_with("SIG~"));
            assert!(merkle_root.starts_with("HASH~"));

            // Check inputs.
            for input in tx["inputs"].as_array().unwrap() {
                assert!(input.as_str().unwrap().starts_with("NUL~"));
            }

            // Check outputs.
            for (i, output) in tx["outputs"].as_array().unwrap().iter().enumerate() {
                // Check well-formedness of the data.
                let comm = output["commitment"].as_str().unwrap();
                let _uid = output["uid"].as_u64().unwrap();
                let memo = &output["memo"];
                assert!(comm.starts_with("REC~"));
                assert!(memo.is_null() || memo.as_str().unwrap().starts_with("MEMO~"));
                // Check that we get the same record if we query for the output directly.
                assert_eq!(
                    *output,
                    get(format!("/getunspentrecord/{}/{}/{}", tx_id, i, false)).await
                );
            }
        }
    }
}
