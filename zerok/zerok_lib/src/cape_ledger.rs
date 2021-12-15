use crate::{
    cape_state::*,
    ledger::{traits::*, AAPTransactionKind},
    node::{LedgerEvent, QueryServiceError},
    state::{key_set::SizedKey, ProverKeySet, ValidationError, VerifierKeySet, MERKLE_HEIGHT},
    txn_builder::TransactionState,
    universal_params::UNIVERSAL_PARAM,
    util::commit::{Commitment, Committable, RawCommitmentBuilder},
    wallet::{
        persistence::{AtomicWalletStorage, WalletLoader},
        CryptoError, WalletBackend, WalletError, WalletImmutableKeySet, WalletState,
    },
};
use async_std::sync::{Mutex, MutexGuard};
use async_trait::async_trait;
use futures::{
    channel::mpsc,
    prelude::*,
    stream::{iter, Stream},
};
use generic_array::GenericArray;
use itertools::izip;
use jf_txn::{
    keys::{UserAddress, UserKeyPair, UserPubKey},
    proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    structs::{Nullifier, ReceiverMemo, RecordCommitment, RecordOpening},
    MerklePath, MerkleTree, Signature, TransactionNote,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use snafu::ResultExt;
use std::collections::{BTreeMap, HashMap};
use std::iter::repeat;
use std::pin::Pin;
use std::sync::Arc;

// A representation of an unauthenticated sparse set of nullifiers (it is "authenticated" by
// querying the ultimate source of truth, the CAPE smart contract). The HashMap maps any nullifier
// to one of 3 states:
//  * Some(true): definitely in the set
//  * Some(false): definitely not in the set
//  * None: outside the sparse domain of this set, query a full node for a definitive answer
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CapeNullifierSet(HashMap<Nullifier, bool>);

impl NullifierSet for CapeNullifierSet {
    type Proof = ();

    fn multi_insert(&mut self, nullifiers: &[(Nullifier, Self::Proof)]) -> Result<(), Self::Proof> {
        for (n, _) in nullifiers {
            self.0.insert(*n, true);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum_macros::Display)]
pub enum CapeTransactionKind {
    AAP(AAPTransactionKind),
    Burn,
    Wrap,
}

impl TransactionKind for CapeTransactionKind {
    fn send() -> Self {
        Self::AAP(AAPTransactionKind::send())
    }

    fn receive() -> Self {
        Self::AAP(AAPTransactionKind::receive())
    }

    fn mint() -> Self {
        Self::AAP(AAPTransactionKind::mint())
    }

    fn freeze() -> Self {
        Self::AAP(AAPTransactionKind::freeze())
    }

    fn unfreeze() -> Self {
        Self::AAP(AAPTransactionKind::unfreeze())
    }

    fn unknown() -> Self {
        Self::AAP(AAPTransactionKind::unknown())
    }
}

// CapeTransition models all of the objects which can transition a CAPE ledger. This includes
// transactions, submitted from users to the validator via the relayer, as well as ERC20 wrap
// operations, which are submitted directly to the contract but whose outputs end up being included
// in the next committed block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CapeTransition {
    Transaction(CapeTransaction),
    Wrap(Box<RecordOpening>),
}

impl Committable for CapeTransition {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CapeTransition")
            .var_size_bytes(&bincode::serialize(self).unwrap())
            .finalize()
    }
}

impl Transaction for CapeTransition {
    type NullifierSet = CapeNullifierSet;
    type Hash = ();
    type Kind = CapeTransactionKind;

    fn aap(note: TransactionNote, _proofs: Vec<()>) -> Self {
        Self::Transaction(CapeTransaction::AAP(note))
    }

    fn as_aap(&self) -> Option<TransactionNote> {
        match self {
            Self::Transaction(CapeTransaction::AAP(note)) => Some(note.clone()),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) =>
            // What to do in this case? Currently, this function is only used for auditing, so
            // it probably makes sense to treat burns as transfers so we get thet most
            // information possible out of auditing. But in general it may not be great to
            // identify burns and transfers.
            {
                Some(TransactionNote::Transfer(xfr.clone()))
            }
            _ => None,
        }
    }

    fn proven_nullifiers(&self) -> Vec<(Nullifier, ())> {
        let nullifiers = match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => txn.nullifiers(),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) => xfr.inputs_nullifiers.clone(),
            Self::Wrap(..) => Vec::new(),
        };
        nullifiers.into_iter().zip(repeat(())).collect()
    }

    fn output_commitments(&self) -> Vec<RecordCommitment> {
        match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => txn.output_commitments(),
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) => xfr.output_commitments.clone(),
            Self::Wrap(ro) => vec![RecordCommitment::from(&**ro)],
        }
    }

    fn hash(&self) {}

    fn kind(&self) -> CapeTransactionKind {
        match self {
            Self::Transaction(CapeTransaction::AAP(txn)) => match txn {
                TransactionNote::Transfer(..) => CapeTransactionKind::send(),
                TransactionNote::Mint(..) => CapeTransactionKind::mint(),
                TransactionNote::Freeze(..) => CapeTransactionKind::freeze(),
            },
            Self::Transaction(CapeTransaction::Burn { .. }) => CapeTransactionKind::Burn,
            Self::Wrap(..) => CapeTransactionKind::Wrap,
        }
    }

    fn set_proofs(&mut self, _proofs: Vec<()>) {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapeBlock(Vec<CapeTransition>);

impl Committable for CapeBlock {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CapeBlock")
            .array_field(
                "txns",
                &self.0.iter().map(|x| x.commit()).collect::<Vec<_>>(),
            )
            .finalize()
    }
}

impl Block for CapeBlock {
    type Transaction = CapeTransition;

    fn new(txns: Vec<CapeTransition>) -> Self {
        Self(txns)
    }

    fn txns(&self) -> Vec<CapeTransition> {
        self.0.clone()
    }
}

// In CAPE, we don't do local lightweight validation to check the results of queries. We trust the
// results of Ethereum query services, and our local validator stores just enough information to
// satisfy the Validator interface required by the wallet. Thus, the CAPE integration for the
// Validator interface is actually more Truster than Validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapeTruster {
    // The current timestamp. The only requirement is that this is a monotonically increasing value,
    // but in this implementation it tracks the number of blocks committed.
    now: u64,
    // Number of records, for generating new UIDs.
    num_records: u64,
    // Current state commitment. This is a commitment to every block which has been committed, as
    // well as to the initial (now, num_records) state for good measure.
    commitment: GenericArray<u8, <Keccak256 as Digest>::OutputSize>,
}

impl CapeTruster {
    #[allow(dead_code)]
    fn new(now: u64, num_records: u64) -> Self {
        Self {
            now,
            num_records,
            commitment: Keccak256::new()
                .chain("initial".as_bytes())
                .chain(now.to_le_bytes())
                .chain(num_records.to_le_bytes())
                .finalize(),
        }
    }
}

impl Validator for CapeTruster {
    type StateCommitment = GenericArray<u8, <Keccak256 as Digest>::OutputSize>;
    type Block = CapeBlock;

    fn now(&self) -> u64 {
        self.now
    }

    fn commit(&self) -> Self::StateCommitment {
        self.commitment
    }

    fn validate_and_apply(&mut self, block: Self::Block) -> Result<Vec<u64>, ValidationError> {
        // We don't actually do validation here, since in this implementation we trust the query
        // service to provide only valid blocks. Instead, just compute a new commitment (by chaining
        // the new block onto the current commitment hash, with a domain separator tag).
        self.commitment = Keccak256::new()
            .chain("block".as_bytes())
            .chain(&self.commitment)
            .chain(&block.commit())
            .finalize();
        self.now += 1;

        // Compute the unique IDs of the output records of this block. The IDs for each block are
        // a consecutive range of integers starting at the previous number of records.
        let mut uids = vec![];
        let mut uid = self.num_records;
        for txn in block.0 {
            for _ in 0..txn.output_len() {
                uids.push(uid);
                uid += 1;
            }
        }
        self.num_records = uid;

        Ok(uids)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CapeLedger;

impl Ledger for CapeLedger {
    type Validator = CapeTruster;
}

struct CommittedTransaction {
    txn: CapeTransition,
    uids: Vec<u64>,
    #[allow(clippy::type_complexity)]
    memos: Option<(
        Vec<(ReceiverMemo, RecordCommitment, u64, MerklePath)>,
        Signature,
    )>,
}

// A mock implementation of the WalletBackend trait which maintains the full state of a CAPE ledger
// locally.
pub struct LocalCapeLedger {
    contract: CapeContractState,

    // Mock EQS and peripheral services
    records: MerkleTree,
    events: Vec<LedgerEvent<CapeLedger>>,
    subscribers: Vec<mpsc::UnboundedSender<LedgerEvent<CapeLedger>>>,
    // Clients which have subscribed to events starting at some time in the future, to be added to
    // `subscribers` when the time comes.
    pending_subscribers: BTreeMap<u64, Vec<mpsc::UnboundedSender<LedgerEvent<CapeLedger>>>>,
    txns: HashMap<(u64, u64), CommittedTransaction>,
    address_map: HashMap<UserAddress, UserPubKey>,
}

impl LocalCapeLedger {
    pub fn new(verif_crs: VerifierKeySet) -> Self {
        Self {
            contract: CapeContractState::new(verif_crs, MerkleTree::new(MERKLE_HEIGHT).unwrap()),
            records: MerkleTree::new(MERKLE_HEIGHT).unwrap(),
            events: Default::default(),
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
            txns: Default::default(),
            address_map: Default::default(),
        }
    }

    fn send_event(&mut self, event: LedgerEvent<CapeLedger>) {
        // Subscribers who asked for a subscription starting from the current time can now be added
        // to the list of active subscribers.
        let now = self.events.len() as u64;
        if let Some(new_subscribers) = self.pending_subscribers.remove(&now) {
            self.subscribers.extend(new_subscribers);
        }

        // Send the message to all active subscribers. Filter out subscribers where the send fails,
        // which means that the client has disconnected.
        self.subscribers = std::mem::take(&mut self.subscribers)
            .into_iter()
            .filter(|subscriber| subscriber.unbounded_send(event.clone()).is_ok())
            .collect();

        // Save the event so we can feed it to later subscribers who want to start from some time in
        // the past.
        self.events.push(event);
    }
}

pub struct LocalCapeBackend<'a, Meta: Serialize + DeserializeOwned> {
    storage: Arc<Mutex<AtomicWalletStorage<'a, CapeLedger, Meta>>>,
    key_pair: Option<UserKeyPair>,
    network: Arc<Mutex<LocalCapeLedger>>,
}

impl<'a, Meta: Serialize + DeserializeOwned + Send> LocalCapeBackend<'a, Meta> {
    pub fn new(
        network: Arc<Mutex<LocalCapeLedger>>,
        loader: &mut impl WalletLoader<Meta = Meta>,
    ) -> Result<Self, WalletError> {
        Ok(Self {
            storage: Arc::new(Mutex::new(AtomicWalletStorage::new(loader)?)),
            key_pair: loader.key_pair(),
            network,
        })
    }
}

#[async_trait]
impl<'a, Meta: Serialize + DeserializeOwned + Send> WalletBackend<'a, CapeLedger>
    for LocalCapeBackend<'a, Meta>
{
    type EventStream = Pin<Box<dyn Stream<Item = LedgerEvent<CapeLedger>> + Send>>;
    type Storage = AtomicWalletStorage<'a, CapeLedger, Meta>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(&mut self) -> Result<WalletState<'a, CapeLedger>, WalletError> {
        let mut rng = ChaChaRng::from_entropy();
        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = &*UNIVERSAL_PARAM;
        let mut network = self.network.lock().await;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_txn::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoError)?
                .0,
            freeze: network
                .contract
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
            xfr: network
                .contract
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
        let records = MerkleTree::restore_from_frontier(
            network.contract.ledger.record_merkle_commitment,
            &network.contract.ledger.record_merkle_frontier,
        )
        .unwrap();
        let merkle_leaf_to_forget = if records.num_leaves() > 0 {
            Some(records.num_leaves() - 1)
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
                validator: CapeTruster::new(
                    network.contract.ledger.state_number,
                    records.num_leaves(),
                ),
                nullifiers: Default::default(),
                // Completely sparse nullifier set
                record_mt: records,
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

        // Publish the address of the new wallet.
        network.address_map.insert(
            state.immutable_keys.key_pair.address(),
            state.immutable_keys.key_pair.pub_key(),
        );

        drop(network);
        self.storage().await.create(&state).await?;

        Ok(state)
    }

    async fn subscribe(&self, t: u64) -> Self::EventStream {
        let (sender, receiver) = mpsc::unbounded();
        let mut network = self.network.lock().await;
        if (t as usize) < network.events.len() {
            // If the start time is in the past, send the subscriber all saved events since the
            // start time and make them an active subscriber starting now.
            network.subscribers.push(sender);
            let past_events = network
                .events
                .iter()
                .skip(t as usize)
                .cloned()
                .collect::<Vec<_>>();
            Box::pin(iter(past_events).chain(receiver))
        } else {
            // Otherwise, add the subscriber to the list of pending subscribers to start receiving
            // events at time `t`.
            network
                .pending_subscribers
                .entry(t)
                .or_default()
                .push(sender);
            Box::pin(receiver)
        }
    }

    async fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
        Ok(self
            .network
            .lock()
            .await
            .address_map
            .get(address)
            .ok_or(QueryServiceError::InvalidAddress {})?
            .clone())
    }

    async fn get_nullifier_proof(
        &self,
        nullifiers: &mut CapeNullifierSet,
        nullifier: Nullifier,
    ) -> Result<(bool, ()), WalletError> {
        // Try to look up the nullifier in our "local" cache. If it is not there, query the contract
        // and cache it.
        match nullifiers.0.get(&nullifier) {
            Some(ret) => Ok((*ret, ())),
            None => {
                let ret = self
                    .network
                    .lock()
                    .await
                    .contract
                    .nullifiers
                    .contains(&nullifier);
                nullifiers.0.insert(nullifier, ret);
                Ok((ret, ()))
            }
        }
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<CapeTransition, WalletError> {
        Ok(self
            .network
            .lock()
            .await
            .txns
            .get(&(block_id, txn_id))
            .ok_or(QueryServiceError::InvalidTxnId {})?
            .txn
            .clone())
    }

    async fn submit(&mut self, _txn: CapeTransition) -> Result<(), WalletError> {
        unimplemented!()
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError> {
        let network = &mut *self.network.lock().await;
        let txn = match network.txns.get_mut(&(block_id, txn_id)) {
            Some(txn) => txn,
            None => return Err(QueryServiceError::InvalidTxnId {}.into()),
        };
        if txn.memos.is_some() {
            return Err(QueryServiceError::MemosAlreadyPosted {}.into());
        }
        // Validate the new memos.
        match &txn.txn {
            CapeTransition::Transaction(CapeTransaction::AAP(note)) => {
                if note.verify_receiver_memos_signature(&memos, &sig).is_err() {
                    return Err(QueryServiceError::InvalidSignature {}.into());
                }
            }
            _ => {
                // Wrap/burn transactions don't get memos.
                return Err(QueryServiceError::InvalidTxnId {}.into());
            }
        }
        if memos.len() != txn.txn.output_len() {
            return Err(QueryServiceError::WrongNumberOfMemos {
                expected: txn.txn.output_len(),
            }
            .into());
        }

        // Authenticate the validity of the records corresponding to the memos.
        let merkle_tree = &network.records;
        let merkle_paths = txn
            .uids
            .iter()
            .map(|uid| merkle_tree.get_leaf(*uid).expect_ok().unwrap().1.path)
            .collect::<Vec<_>>();

        // Store and broadcast the new memos.
        let memos = izip!(
            memos,
            txn.txn.output_commitments(),
            txn.uids.iter().cloned(),
            merkle_paths
        )
        .collect::<Vec<_>>();
        txn.memos = Some((memos.clone(), sig));
        let event = LedgerEvent::Memos {
            outputs: memos,
            transaction: Some((block_id as u64, txn_id as u64)),
        };
        network.send_event(event);

        Ok(())
    }
}
