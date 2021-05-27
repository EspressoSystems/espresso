// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use structopt::StructOpt;
use tracing::info;

const VALIDATOR_COUNT: u8 = 4;

type Transaction = u32;

#[derive(StructOpt)]
/// Translucence Ledger Demo 1
///
/// Submits a number of transactions to consensus validation and
/// records successful transactions to the ledger
pub struct Args {
    #[structopt(verbatim_doc_comment, long, short = "c", default_value = "1")]
    pub transaction_count: u8,
}

fn load_crs() {
    info!("Loading common reference string");
}

fn build_transaction(specification: Transaction) -> Transaction {
    info!("Building transaction");
    specification
}

fn submit_transaction(tx: Sender<bool>, transaction: Transaction) {
    info!("Submitting transaction to {} validators", VALIDATOR_COUNT);
    for id in 0..VALIDATOR_COUNT {
        propose_transaction(id, tx.clone(), transaction);
    }
}

fn propose_transaction(id: u8, tx: Sender<bool>, transaction: Transaction) {
    info!(
        "Proposing transaction value: {} to validator {}",
        transaction, &id
    );
    thread::spawn(move || {
        info!("  Validator {} received {}", id, &transaction);
        let validity = validate_transaction(transaction);
        tx.send(validity).expect("send failed");
    });
}

fn validate_transaction(_transaction: Transaction) -> bool {
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time is such a pain")
        .as_micros();
    // Occasionally reject the transaction so failure handling can be observed.
    now % 10 != 0
}

fn consense(rx: Receiver<bool>) -> bool {
    info!("Consensing");

    let mut unanimous = true;
    for _ in 0..VALIDATOR_COUNT {
        let next = rx.recv().unwrap();
        info!("  Validity is {}", &next);
        if !&next {
            unanimous = false;
        }
    }

    unanimous
}

fn log_transaction(transaction: Transaction) {
    info!("Recording transaction value: {}", transaction);
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::from_args();

    load_crs();

    for i in 0..args.transaction_count {
        info!("⬤  TRANSACTION {}", i);
        let transaction = build_transaction(i as Transaction + 42);
        let (tx, rx) = channel();
        submit_transaction(tx, transaction);
        if consense(rx) {
            info!("Consensus was achieved");
            log_transaction(transaction);
        } else {
            info!("Consensus was not achieved");
            info!("Rejecting transaction");
        }
    }
}
