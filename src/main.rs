// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use std::fmt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use structopt::StructOpt;
use tagged_base64::TaggedBase64;
use tracing::info;

type UserId = u32;
type AssetId = u32;
type TransactionId = u32;

#[derive(Clone)]
struct Transfer {
    owner: UserId,
    recipient: UserId,
    asset: AssetId,
    amount: u32,
}

#[derive(Clone)]
struct Transaction {
    id: TransactionId,
    transfer: Transfer,
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tb64 = TaggedBase64::new("TX", &self.id.to_le_bytes());
        write!(f, "{}", tb64.unwrap())
    }
}

#[derive(StructOpt)]
/// Translucence Ledger Demo 1
///
/// Submits a number of transactions to consensus validation and
/// records successful transactions to the ledger
pub struct Args {
    /// Number of transactions to
    ///   process
    #[structopt(verbatim_doc_comment, long, short = "t", default_value = "1")]
    pub transaction_count: u8,
    /// Number of
    ///   validators
    #[structopt(verbatim_doc_comment, long, short = "a", default_value = "3")]
    pub validator_count: u8,
}

fn get_validator_count() -> u8 {
    Args::from_args().validator_count
}

fn load_crs() {
    info!("Loading common reference string");
}

fn build_transaction(specification: Transaction) -> Transaction {
    info!("Building transaction");
    specification
}

fn submit_transaction(tx: Sender<bool>, transaction: Transaction) {
    info!(
        "Submitting transaction to {} validators",
        get_validator_count()
    );
    for id in 0..get_validator_count() {
        propose_transaction(id, tx.clone(), transaction.clone());
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
    for _ in 0..get_validator_count() {
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
        let txn = Transaction {
            id: i as TransactionId + 42,
            transfer: Transfer {
                owner: 100,
                recipient: 200,
                asset: 1000,
                amount: 5,
            },
        };
        let transaction = build_transaction(txn);
        let (tx, rx) = channel();
        submit_transaction(tx, transaction.clone());
        if consense(rx) {
            info!("Consensus was achieved");
            log_transaction(transaction);
        } else {
            info!("Consensus was not achieved");
            info!("Rejecting transaction");
        }
    }
}
