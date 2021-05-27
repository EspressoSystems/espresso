use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::SystemTime;

const VALIDATOR_COUNT: u8 = 4;

type Transaction = u32;

fn load_crs() {
    println!("Loading common reference string");
}

fn build_transaction(specification: Transaction) -> Transaction {
    println!("Building transaction");
    specification
}

fn submit_transaction(tx: Sender<bool>, transaction: Transaction) {
    println!("Submitting transaction to {} validators", VALIDATOR_COUNT);
    for id in 0..VALIDATOR_COUNT {
        propose_transaction(id, tx.clone(), transaction);
    }
}

fn propose_transaction(id: u8, tx: Sender<bool>, transaction: Transaction) {
    println!(
        "Proposing transaction value: {} to validator {}",
        transaction, &id
    );
    thread::spawn(move || {
        println!("  Validator {} received {}", id, &transaction);
        let validity = validate_transaction(transaction);
        tx.send(validity).unwrap();
    });
}

fn validate_transaction(_transaction: Transaction) -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time is such a pain")
        .as_micros();
    // Occasionally reject the transaction so failure handling can be observed.
    now % 10 != 0
}

fn consense(rx: Receiver<bool>) -> bool {
    println!("Consensing");

    let mut unanimous = true;

    for _ in 0..VALIDATOR_COUNT {
        let next = rx.recv().unwrap();
        println!("  Validity is {}", &next);
        if !&next {
            unanimous = false;
        }
    }

    unanimous
}

fn log_transaction(transaction: Transaction) {
    println!("Recording transaction value: {}", transaction);
}

fn main() {
    load_crs();

    for i in 0..2 {
        let transaction = build_transaction(i + 42);
        let (tx, rx) = channel();
        submit_transaction(tx, transaction);
        if consense(rx) {
            println!("Consensus was achieved");
            log_transaction(transaction);
        } else {
            println!("Consensus was not achieved");
            println!("Rejecting transaction");
        }
    }
}
