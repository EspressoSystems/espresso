use crate::{
    api::FromError,
    cape_state::*,
    ledger::{
        open_aap_audit_memo, open_xfr_audit_memo, traits::*, AAPTransactionKind, AuditError,
        AuditMemoOpening,
    },
    node::{LedgerEvent, QueryServiceError},
    state::{key_set::SizedKey, ProverKeySet, ValidationError, VerifierKeySet, MERKLE_HEIGHT},
    txn_builder::{TransactionError, TransactionReceipt, TransactionState},
    universal_params::UNIVERSAL_PARAM,
    util::commit::{Commitment, Committable, RawCommitmentBuilder},
    wallet::{
        hd::KeyTree, loader::WalletLoader, persistence::AtomicWalletStorage, CryptoError, Wallet,
        WalletBackend, WalletError, WalletState,
    },
};
use async_std::sync::{Mutex, MutexGuard};
use async_trait::async_trait;
use futures::{
    channel::mpsc,
    prelude::*,
    stream::{iter, Stream},
};
use itertools::izip;
use jf_aap::{
    keys::{AuditorKeyPair, AuditorPubKey, UserAddress, UserPubKey},
    proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier,
        ReceiverMemo, RecordCommitment, RecordOpening,
    },
    MerklePath, MerkleTree, Signature, TransactionNote,
};
use rand_chacha::ChaChaRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    Wrap {
        erc20_code: Erc20Code,
        src_addr: EthereumAddr,
        ro: Box<RecordOpening>,
    },
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

    fn open_audit_memo(
        &self,
        assets: &HashMap<AssetCode, AssetDefinition>,
        keys: &HashMap<AuditorPubKey, AuditorKeyPair>,
    ) -> Result<AuditMemoOpening, AuditError> {
        match self {
            Self::Transaction(CapeTransaction::AAP(note)) => {
                open_aap_audit_memo(assets, keys, note)
            }
            Self::Transaction(CapeTransaction::Burn { xfr, .. }) => {
                open_xfr_audit_memo(assets, keys, xfr)
            }
            _ => Err(AuditError::NoAuditMemos),
        }
    }

    fn proven_nullifiers(&self) -> Vec<(Nullifier, ())> {
        let nullifiers = match self {
            Self::Transaction(txn) => txn.nullifiers(),
            Self::Wrap { .. } => Vec::new(),
        };
        nullifiers.into_iter().zip(repeat(())).collect()
    }

    fn output_commitments(&self) -> Vec<RecordCommitment> {
        match self {
            Self::Transaction(txn) => txn.commitments(),
            Self::Wrap { ro, .. } => vec![RecordCommitment::from(&**ro)],
        }
    }

    fn output_openings(&self) -> Vec<Option<RecordOpening>> {
        match self {
            Self::Wrap { ro, .. } => vec![Some((**ro).clone())],
            _ => vec![None; self.output_len()],
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
            Self::Wrap { .. } => CapeTransactionKind::Wrap,
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
}

impl CapeTruster {
    #[allow(dead_code)]
    fn new(now: u64, num_records: u64) -> Self {
        Self { now, num_records }
    }
}

impl Validator for CapeTruster {
    type StateCommitment = u64;
    type Block = CapeBlock;

    fn now(&self) -> u64 {
        self.now
    }

    fn commit(&self) -> Self::StateCommitment {
        // Our commitment is just the block height of the ledger. Since we are trusting a query
        // service anyways, this can be used to determine a unique ledger state by querying for the
        // state of the ledger at this block index.
        self.now
    }

    fn validate_and_apply(&mut self, block: Self::Block) -> Result<Vec<u64>, ValidationError> {
        // We don't actually do validation here, since in this implementation we trust the query
        // service to provide only valid blocks. Instead, just compute the UIDs of the new records
        // assuming the block successfully validates.
        let mut uids = vec![];
        let mut uid = self.num_records;
        for txn in block.0 {
            for _ in 0..txn.output_len() {
                uids.push(uid);
                uid += 1;
            }
        }
        self.num_records = uid;
        self.now += 1;

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
    block_height: u64,
    records: MerkleTree,
    // When an ERC20 deposit is finalized during a block submission, the contract emits an event
    // containing only the commitment of the new record. Therefore, to correllate these events with
    // the other information needed to reconstruct a CapeTransition::Wrap, the query service needs
    // to monitor the contracts Erc20Deposited events and keep track of the deposits which are
    // pending finalization.
    pending_erc20_deposits:
        HashMap<RecordCommitment, (Erc20Code, EthereumAddr, Box<RecordOpening>)>,
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
            block_height: 0,
            records: MerkleTree::new(MERKLE_HEIGHT).unwrap(),
            pending_erc20_deposits: Default::default(),
            events: Default::default(),
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
            txns: Default::default(),
            address_map: Default::default(),
        }
    }

    pub fn register_erc20(
        &mut self,
        asset_def: AssetDefinition,
        erc20_code: Erc20Code,
        sponsor_addr: EthereumAddr,
    ) -> Result<(), CapeValidationError> {
        self.submit_operations(vec![CapeOperation::RegisterErc20 {
            asset_def: Box::new(asset_def),
            erc20_code,
            sponsor_addr,
        }])
    }

    pub fn wrap_erc20(
        &mut self,
        erc20_code: Erc20Code,
        src_addr: EthereumAddr,
        ro: RecordOpening,
    ) -> Result<(), CapeValidationError> {
        self.submit_operations(vec![CapeOperation::WrapErc20 {
            erc20_code,
            src_addr,
            ro: Box::new(ro),
        }])
    }

    fn submit_operations(&mut self, ops: Vec<CapeOperation>) -> Result<(), CapeValidationError> {
        let (new_state, effects) = self.contract.submit_operations(ops)?;
        let mut events = vec![];
        for effect in effects {
            if let CapeEthEffect::Emit(event) = effect {
                events.push(event);
            } else {
                //todo Simulate and validate the other ETH effects. If any effects fail, the
                // whole transaction must be considered reverted with no visible effects.
            }
        }

        // Simulate the EQS processing the events emitted by the contract, updating its state, and
        // broadcasting processed events to subscribers.
        for event in events {
            self.handle_event(event);
        }
        self.contract = new_state;

        Ok(())
    }

    fn handle_event(&mut self, event: CapeEvent) {
        match event {
            CapeEvent::BlockCommitted { wraps, txns } => {
                for comm in &wraps {
                    self.records.push(comm.to_field_element());
                }
                for txn in &txns {
                    for comm in txn.commitments() {
                        self.records.push(comm.to_field_element());
                    }
                }

                // Wrap each transaction and wrap event into a CapeTransition, build a
                // CapeBlock, and broadcast it to subscribers.
                let block = CapeBlock::new(
                    wraps
                        .into_iter()
                        .map(|comm| {
                            // Look up the auxiliary information associated with this deposit which
                            // we saved when we processed the deposit event. This lookup cannot
                            // fail, because the contract only finalizes a Wrap operation after it
                            // has already processed the deposit, which involves emitting an
                            // Erc20Deposited event.
                            let (erc20_code, src_addr, ro) =
                                self.pending_erc20_deposits.remove(&comm).unwrap();
                            CapeTransition::Wrap {
                                erc20_code,
                                src_addr,
                                ro,
                            }
                        })
                        .chain(txns.into_iter().map(CapeTransition::Transaction))
                        .collect(),
                );
                self.send_event(LedgerEvent::Commit {
                    block,
                    block_id: self.block_height,
                    state_comm: self.block_height,
                });
                self.block_height += 1;
            }

            CapeEvent::Erc20Deposited {
                erc20_code,
                src_addr,
                ro,
            } => {
                self.pending_erc20_deposits
                    .insert(RecordCommitment::from(&*ro), (erc20_code, src_addr, ro));
            }
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
    network: Arc<Mutex<LocalCapeLedger>>,
    key_stream: KeyTree,
}

impl<'a, Meta: Serialize + DeserializeOwned + Send> LocalCapeBackend<'a, Meta> {
    pub fn new(
        network: Arc<Mutex<LocalCapeLedger>>,
        loader: &mut impl WalletLoader<Meta = Meta>,
    ) -> Result<Self, WalletError> {
        let storage = AtomicWalletStorage::new(loader)?;
        Ok(Self {
            key_stream: storage.key_stream(),
            storage: Arc::new(Mutex::new(storage)),
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
        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = &*UNIVERSAL_PARAM;
        let network = self.network.lock().await;
        let proving_keys = Arc::new(ProverKeySet {
            mint: jf_aap::proof::mint::preprocess(univ_param, MERKLE_HEIGHT)
                .context(CryptoError)?
                .0,
            freeze: network
                .contract
                .verif_crs
                .freeze
                .iter()
                .map(|k| {
                    Ok::<FreezeProvingKey, WalletError>(
                        jf_aap::proof::freeze::preprocess(
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
                        jf_aap::proof::transfer::preprocess(
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
            txn_state: TransactionState {
                validator: CapeTruster::new(network.block_height, records.num_leaves()),
                nullifiers: Default::default(),
                // Completely sparse nullifier set
                record_mt: records,
                merkle_leaf_to_forget,
                now: 0,
                records: Default::default(),

                transactions: Default::default(),
            },
            key_scans: Default::default(),
            key_state: Default::default(),
            auditable_assets: Default::default(),
            audit_keys: Default::default(),
            freeze_keys: Default::default(),
            user_keys: Default::default(),
            defined_assets: Default::default(),
        };

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

    async fn register_user_key(&mut self, pub_key: &UserPubKey) -> Result<(), WalletError> {
        self.network
            .lock()
            .await
            .address_map
            .insert(pub_key.address(), pub_key.clone());
        Ok(())
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

    fn key_stream(&self) -> KeyTree {
        self.key_stream.clone()
    }

    async fn submit(&mut self, txn: CapeTransition) -> Result<(), WalletError> {
        let mut network = self.network.lock().await;

        // Convert the submitted transaction to a CapeOperation.
        //todo Buffer submitted transactions into non-trivial blocks.
        let op = match txn {
            CapeTransition::Transaction(txn) => CapeOperation::SubmitBlock(vec![txn]),
            CapeTransition::Wrap {
                erc20_code,
                src_addr,
                ro,
            } => CapeOperation::WrapErc20 {
                erc20_code,
                src_addr,
                ro,
            },
        };

        network
            .submit_operations(vec![op])
            .map_err(cape_to_wallet_err)
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

// Wrapper around a generic wallet adding CAPE-specific wallet functions.
pub struct LocalCapeWallet<'a, Meta: Serialize + DeserializeOwned + Send> {
    wallet: Wallet<'a, LocalCapeBackend<'a, Meta>, CapeLedger>,
    // For actions submitted directly to the contract, such as sponsor and wrap.
    network: Arc<Mutex<LocalCapeLedger>>,
    rng: ChaChaRng,
}

impl<'a, Meta: 'a + Serialize + DeserializeOwned + Send> LocalCapeWallet<'a, Meta> {
    pub async fn sponsor(
        &mut self,
        erc20_code: Erc20Code,
        sponsor_addr: EthereumAddr,
        aap_asset_desc: &[u8],
        aap_asset_policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let seed = AssetCodeSeed::generate(&mut self.rng);
        //todo Include CAPE-specific domain separator in AssetCode derivation, once Jellyfish adds
        // support for domain separators.
        let code = AssetCode::new(seed, aap_asset_desc);
        let asset = AssetDefinition::new(code, aap_asset_policy).context(CryptoError)?;

        self.network
            .lock()
            .await
            .register_erc20(asset.clone(), erc20_code, sponsor_addr)
            .map_err(cape_to_wallet_err)?;

        Ok(asset)
    }

    pub async fn wrap(
        &mut self,
        src_addr: EthereumAddr,
        // We take as input the target asset, not the source ERC20 code, because there may be more
        // than one AAP asset for a given ERC20 token. We need the user to disambiguate (probably
        // using a list of approved (AAP, ERC20) pairs provided by the query service).
        aap_asset: AssetDefinition,
        owner: UserAddress,
        amount: u64,
    ) -> Result<(), WalletError> {
        let mut network = self.network.lock().await;
        let erc20_code = match network.contract.erc20_registrar.get(&aap_asset) {
            Some((erc20_code, _)) => erc20_code.clone(),
            None => {
                return Err(WalletError::UndefinedAsset {
                    asset: aap_asset.code,
                })
            }
        };

        let pub_key = match network.address_map.get(&owner) {
            Some(pub_key) => pub_key.clone(),
            None => return Err(WalletError::InvalidAddress { address: owner }),
        };

        //todo Along with this wrap operation submitted to the contract, we must also transfer some
        // of the ERC20 token to the contract using an Ethereum wallet.
        network
            .wrap_erc20(
                erc20_code,
                src_addr,
                RecordOpening::new(
                    &mut self.rng,
                    amount,
                    aap_asset,
                    pub_key,
                    FreezeFlag::Unfrozen,
                ),
            )
            .map_err(cape_to_wallet_err)
    }

    pub async fn burn(
        &mut self,
        account: &UserAddress,
        dst_addr: EthereumAddr,
        aap_asset: &AssetCode,
        amount: u64,
        fee: u64,
    ) -> Result<TransactionReceipt<CapeLedger>, WalletError> {
        // A burn note is just a transfer note with a special `proof_bound_data` field consisting of
        // the magic burn bytes followed by the destination address.
        let bound_data = CAPE_BURN_MAGIC_BYTES
            .as_bytes()
            .iter()
            .chain(dst_addr.as_bytes())
            .cloned()
            .collect::<Vec<_>>();
        let (xfr, mut info) = self
            .wallet
            // The owner public key of the new record opening is ignored when processing a burn. We
            // need to put some address in the receiver field though, so just use the one we have
            // handy.
            .build_transfer(
                account,
                aap_asset,
                &[(account.clone(), amount)],
                fee,
                bound_data,
            )
            .await?;
        assert!(info.outputs.len() >= 2);
        if info.outputs.len() > 2 {
            return Err(WalletError::TransactionError {
                source: TransactionError::Fragmentation {
                    asset: *aap_asset,
                    amount,
                    suggested_amount: info.outputs[1].amount,
                    max_records: 1,
                },
            });
        }
        if let Some(history) = &mut info.history {
            history.kind = CapeTransactionKind::Burn;
        }

        let txn = CapeTransition::Transaction(CapeTransaction::Burn {
            xfr: Box::new(xfr),
            ro: Box::new(info.outputs[1].clone()),
        });
        self.wallet.submit(txn, info).await
    }

    pub async fn approved_assets(&self) -> Vec<(AssetDefinition, Erc20Code)> {
        unimplemented!()
    }
}

fn cape_to_wallet_err(err: CapeValidationError) -> WalletError {
    //todo Convert CapeValidationError to WalletError in a better way. Maybe WalletError should be
    // parameterized on the ledger type and there should be a ledger trait ValidationError.
    WalletError::catch_all(err.to_string())
}
