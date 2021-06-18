// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use hotstuff::networking::w_network::WNetwork;
use hotstuff::{BlockContents, HotStuff, HotStuffConfig, PubKey};
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
//use snafu::{ensure, OptionExt, Snafu};
use snafu::Snafu;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::SystemTime;
use tagged_base64::TaggedBase64;
use threshold_crypto as tc;

const VALIDATOR_COUNT: u8 = 4;

type BlockHash = u32;
type Transaction = u32;
type State = u32;

/// A block of transactions
#[derive(PartialEq, Eq, Default, Hash, Serialize, Deserialize, Clone, Debug)]
pub struct TransactionBlock {
    /// Block state commitment
    pub previous_hash: BlockHash,
    /// Transaction vector
    pub tx: Vec<Transaction>,
}

impl BlockContents for TransactionBlock {
    type State = State;
    type Transaction = Transaction;
    type Error = LedgerError;

    fn add_transaction(
        &self,
        _: &<Self as BlockContents>::State,
        _: &<Self as BlockContents>::Transaction,
    ) -> Result<Self, <Self as BlockContents>::Error> {
        todo!()
    }
    fn validate_block(&self, _: &<Self as BlockContents>::State) -> bool {
        // TODO !corbett check something
        true
    }
    fn append_to(
        &self,
        block: &<Self as BlockContents>::State,
    ) -> Result<<Self as BlockContents>::State, <Self as BlockContents>::Error> {
        let result = block.clone();
        Ok(result)
    }
    fn next_block(_self: &Self::State) -> Self {
        Self::default()
    }
    fn hash(&self) -> [u8; 32] {
        // TODO !corbett hash something
        [0; 32]
    }
    fn hash_transaction(_: &<Self as BlockContents>::Transaction) -> [u8; 32] {
        // TODO !corbett hash something
        [0; 32]
    }
}

/// Top-level error
#[derive(Snafu, Debug)]
pub enum LedgerError {
    /// Something went wrong
    SomethingWrong,
}

fn load_ignition_keys() {
    println!("Loading cryptographic ignition keys");
}

/// Generates the `SecretKeySet` for this BFT instance
pub fn gen_keys(threshold: usize) -> tc::SecretKeySet {
    tc::SecretKeySet::random(threshold, &mut rand::thread_rng())
}

/// Turns a `PublicKeySet` into a set of `HotStuff` `PubKey`s
pub fn set_to_keys(total: usize) -> Vec<PubKey> {
    (0..total).map(|x| PubKey::random(x as u64)).collect()
}

/// Attempts to create a network connection with a random port
pub async fn try_network<
    T: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug + 'static,
>(
    key: PubKey,
) -> (WNetwork<T>, u16) {
    // TODO: Actually attempt to open the port and find a new one if it doens't work
    let port = rand::thread_rng().gen_range(2000, 5000);
    (
        WNetwork::new_from_strings(key, vec![], port, None)
            .await
            .expect("Failed to create network"),
        port,
    )
}

async fn start_consensus() -> HotStuff<TransactionBlock> {
    let genesis = TransactionBlock {
        previous_hash: 0,
        tx: Vec::new(),
    };
    let total: usize = 5;
    let threshold: usize = 3;
    let keys = gen_keys(threshold - 1);
    let node_number: usize = 0;
    let pub_key = PubKey::random(node_number as u64);
    let config = HotStuffConfig {
        total_nodes: total as u32,
        thershold: threshold as u32,
        max_transactions: 100,
        known_nodes: set_to_keys(total),
    };
    let (networking, _port) = try_network(pub_key.clone()).await;
    let hotstuff = HotStuff::new(
        genesis,
        &keys,
        node_number as u64,
        config,
        0,
        networking.clone(),
    );
    hotstuff
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
        let tag = TaggedBase64::new("TX", &transaction.to_be_bytes()).expect("Shouldn't happen");
        println!("  Validator {} received {}, tx: {}", id, &transaction, tag);
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
    load_ignition_keys();
    let _hotstuff = start_consensus();

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
