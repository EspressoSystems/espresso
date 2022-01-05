use super::*;
use crate::{
    api::FromError,
    cape_ledger::*,
    cape_state::*,
    node::{LedgerEvent, QueryServiceError},
    state::{
        key_set::{OrderByOutputs, SizedKey},
        ProverKeySet, VerifierKeySet, MERKLE_HEIGHT,
    },
    txn_builder::{RecordDatabase, TransactionError, TransactionReceipt, TransactionState},
    universal_params::UNIVERSAL_PARAM,
    wallet::{
        hd::KeyTree, loader::WalletLoader, persistence::AtomicWalletStorage, CryptoError,
        KeyStreamState, Wallet, WalletBackend, WalletError, WalletState,
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
    keys::{UserAddress, UserPubKey},
    proof::{freeze::FreezeProvingKey, transfer::TransferProvingKey},
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier,
        ReceiverMemo, RecordCommitment, RecordOpening,
    },
    MerklePath, MerkleTree, Signature,
};
use rand_chacha::ChaChaRng;
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tempdir::TempDir;

struct CommittedTransaction {
    txn: CapeTransition,
    uids: Vec<u64>,
    #[allow(clippy::type_complexity)]
    memos: Option<(
        Vec<(ReceiverMemo, RecordCommitment, u64, MerklePath)>,
        Signature,
    )>,
}

// A mock implementation of a CAPE network which maintains the full state of a CAPE ledger locally.
pub struct MockCapeNetwork {
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

impl MockCapeNetwork {
    pub fn new(
        verif_crs: VerifierKeySet,
        records: MerkleTree,
        initial_grant_memos: Vec<(ReceiverMemo, u64)>,
    ) -> Self {
        let mut ledger = Self {
            contract: CapeContractState::new(verif_crs, records.clone()),
            block_height: 0,
            records,
            pending_erc20_deposits: Default::default(),
            events: Default::default(),
            subscribers: Default::default(),
            pending_subscribers: Default::default(),
            txns: Default::default(),
            address_map: Default::default(),
        };

        // Broadcast receiver memos for the records which are included in the tree from the start,
        // so that clients can access records they have been granted at ledger setup time in a
        // uniform way.
        let memo_outputs = initial_grant_memos
            .into_iter()
            .map(|(memo, uid)| {
                let (comm, merkle_path) = ledger
                    .records
                    .get_leaf(uid)
                    .expect_ok()
                    .map(|(_, proof)| {
                        (
                            RecordCommitment::from_field_element(proof.leaf.0),
                            proof.path,
                        )
                    })
                    .unwrap();
                (memo, comm, uid, merkle_path)
            })
            .collect();
        ledger.generate_event(LedgerEvent::Memos {
            outputs: memo_outputs,
            transaction: None,
        });

        ledger
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
                let num_txns = txns.len();
                txns.iter().enumerate().for_each(|(i, txn)| {
                    let mut uids = Vec::new();
                    for comm in txn.commitments() {
                        uids.push(self.records.num_leaves());
                        self.records.push(comm.to_field_element());
                    }
                    self.txns.insert(
                        (self.block_height, i as u64),
                        CommittedTransaction {
                            txn: CapeTransition::Transaction(txn.clone()),
                            uids,
                            memos: None,
                        },
                    );
                });

                // Wrap each transaction and wrap event into a CapeTransition, build a
                // CapeBlock, and broadcast it to subscribers.
                let block = CapeBlock::new(
                    wraps
                        .into_iter()
                        .enumerate()
                        .map(|(i, comm)| {
                            let uids = vec![self.records.num_leaves()];
                            self.records.push(comm.to_field_element());

                            // Look up the auxiliary information associated with this deposit which
                            // we saved when we processed the deposit event. This lookup cannot
                            // fail, because the contract only finalizes a Wrap operation after it
                            // has already processed the deposit, which involves emitting an
                            // Erc20Deposited event.
                            let (erc20_code, src_addr, ro) =
                                self.pending_erc20_deposits.remove(&comm).unwrap();
                            let txn = CapeTransition::Wrap {
                                erc20_code,
                                src_addr,
                                ro,
                            };
                            self.txns.insert(
                                (self.block_height, (num_txns + i) as u64),
                                CommittedTransaction {
                                    txn: txn.clone(),
                                    uids,
                                    memos: None,
                                },
                            );
                            txn
                        })
                        .chain(txns.into_iter().map(CapeTransition::Transaction))
                        .collect(),
                );
                self.generate_event(LedgerEvent::Commit {
                    block,
                    block_id: self.block_height,
                    state_comm: self.block_height + 1,
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
}

impl<'a> MockNetwork<'a, CapeLedger> for MockCapeNetwork {
    fn now(&self) -> u64 {
        self.events.len() as u64
    }

    fn submit(&mut self, block: Block<CapeLedger>) -> Result<(), WalletError> {
        // Convert the submitted transactions to CapeOperations.
        let ops = block
            .txns()
            .into_iter()
            .map(|txn| match txn {
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
            })
            .collect();

        self.submit_operations(ops).map_err(cape_to_wallet_err)
    }

    fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError> {
        let txn = match self.txns.get_mut(&(block_id, txn_id)) {
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
        let merkle_tree = &self.records;
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
        self.generate_event(event);

        Ok(())
    }

    fn generate_event(&mut self, event: LedgerEvent<CapeLedger>) {
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

type MockCapeLedger<'a> =
    MockLedger<'a, CapeLedger, MockCapeNetwork, AtomicWalletStorage<'a, CapeLedger, ()>>;

pub struct MockCapeBackend<'a, Meta: Serialize + DeserializeOwned> {
    storage: Arc<Mutex<AtomicWalletStorage<'a, CapeLedger, Meta>>>,
    ledger: Arc<Mutex<MockCapeLedger<'a>>>,
    key_stream: KeyTree,
}

impl<'a, Meta: Serialize + DeserializeOwned + Send> MockCapeBackend<'a, Meta> {
    pub fn new(
        ledger: Arc<Mutex<MockCapeLedger<'a>>>,
        loader: &mut impl WalletLoader<Meta = Meta>,
    ) -> Result<Self, WalletError> {
        let storage = AtomicWalletStorage::new(loader)?;
        Ok(Self {
            key_stream: storage.key_stream(),
            storage: Arc::new(Mutex::new(storage)),
            ledger,
        })
    }

    pub async fn new_for_test(
        ledger: Arc<Mutex<MockCapeLedger<'a>>>,
        storage: Arc<Mutex<AtomicWalletStorage<'a, CapeLedger, Meta>>>,
    ) -> Result<MockCapeBackend<'a, Meta>, WalletError> {
        let key_stream = storage.lock().await.key_stream();
        Ok(Self {
            key_stream,
            storage,
            ledger,
        })
    }
}

#[async_trait]
impl<'a, Meta: Serialize + DeserializeOwned + Send> WalletBackend<'a, CapeLedger>
    for MockCapeBackend<'a, Meta>
{
    type EventStream = Pin<Box<dyn Stream<Item = LedgerEvent<CapeLedger>> + Send>>;
    type Storage = AtomicWalletStorage<'a, CapeLedger, Meta>;

    async fn storage<'l>(&'l mut self) -> MutexGuard<'l, Self::Storage> {
        self.storage.lock().await
    }

    async fn create(&mut self) -> Result<WalletState<'a, CapeLedger>, WalletError> {
        // Construct proving keys of the same arities as the verifier keys from the validator.
        let univ_param = &*UNIVERSAL_PARAM;
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
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
        let record_mt = network.records.clone();
        let merkle_leaf_to_forget = if record_mt.num_leaves() > 0 {
            Some(record_mt.num_leaves() - 1)
        } else {
            None
        };

        let state = WalletState {
            proving_keys,
            txn_state: TransactionState {
                validator: CapeTruster::new(network.block_height, record_mt.num_leaves()),
                now: 0,
                nullifiers: Default::default(),
                // Completely sparse nullifier set
                record_mt,
                records: RecordDatabase::default(),
                merkle_leaf_to_forget,

                transactions: Default::default(),
            },
            key_scans: Default::default(),
            key_state: KeyStreamState {
                auditor: 0,
                freezer: 0,
                user: 1,
            },
            auditable_assets: Default::default(),
            audit_keys: Default::default(),
            freeze_keys: Default::default(),
            user_keys: Default::default(),
            defined_assets: Default::default(),
        };

        drop(ledger);
        self.storage().await.create(&state).await?;

        Ok(state)
    }

    async fn subscribe(&self, t: u64) -> Self::EventStream {
        let (sender, receiver) = mpsc::unbounded();
        let mut ledger = self.ledger.lock().await;
        let network = ledger.network();
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
            .ledger
            .lock()
            .await
            .network()
            .address_map
            .get(address)
            .ok_or(QueryServiceError::InvalidAddress {})?
            .clone())
    }

    async fn register_user_key(&mut self, pub_key: &UserPubKey) -> Result<(), WalletError> {
        self.ledger
            .lock()
            .await
            .network()
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
        match nullifiers.get(nullifier) {
            Some(ret) => Ok((ret, ())),
            None => {
                let ret = self
                    .ledger
                    .lock()
                    .await
                    .network
                    .contract
                    .nullifiers
                    .contains(&nullifier);
                nullifiers.insert(nullifier, ret);
                Ok((ret, ()))
            }
        }
    }

    async fn get_transaction(
        &self,
        block_id: u64,
        txn_id: u64,
    ) -> Result<CapeTransition, WalletError> {
        let ledger = self.ledger.lock().await;
        Ok(ledger
            .network
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
        self.ledger.lock().await.submit(txn)
    }

    async fn post_memos(
        &mut self,
        block_id: u64,
        txn_id: u64,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError> {
        self.ledger
            .lock()
            .await
            .post_memos(block_id, txn_id, memos, sig)
    }
}

// Wrapper around a generic wallet adding CAPE-specific wallet functions.
pub struct LocalCapeWallet<'a, Meta: Serialize + DeserializeOwned + Send> {
    wallet: Wallet<'a, MockCapeBackend<'a, Meta>, CapeLedger>,
    // For actions submitted directly to the contract, such as sponsor and wrap.
    network: Arc<Mutex<MockCapeNetwork>>,
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
        let code = AssetCode::new_domestic(seed, aap_asset_desc);
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

struct MockCapeWalletLoader {
    path: PathBuf,
    key: KeyTree,
}

impl WalletLoader for MockCapeWalletLoader {
    type Meta = ();

    fn location(&self) -> PathBuf {
        self.path.clone()
    }

    fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError> {
        Ok(((), self.key.clone()))
    }

    fn load(&mut self, _meta: &Self::Meta) -> Result<KeyTree, WalletError> {
        Ok(self.key.clone())
    }
}

pub struct CapeTest {
    rng: ChaChaRng,
    temp_dirs: Vec<TempDir>,
}

impl CapeTest {
    fn temp_dir(&mut self) -> PathBuf {
        let dir = TempDir::new("cape_wallet").unwrap();
        let path = PathBuf::from(dir.path());
        self.temp_dirs.push(dir);
        path
    }
}

impl Default for CapeTest {
    fn default() -> Self {
        Self {
            rng: ChaChaRng::from_seed([42u8; 32]),
            temp_dirs: Vec::new(),
        }
    }
}

#[async_trait]
impl<'a> SystemUnderTest<'a> for CapeTest {
    type Ledger = CapeLedger;
    type MockBackend = MockCapeBackend<'a, ()>;
    type MockNetwork = MockCapeNetwork;
    type MockStorage = AtomicWalletStorage<'a, CapeLedger, ()>;

    async fn create_network(
        &mut self,
        verif_crs: VerifierKeySet,
        _proof_crs: ProverKeySet<'a, OrderByOutputs>,
        records: MerkleTree,
        initial_grants: Vec<(RecordOpening, u64)>,
    ) -> Self::MockNetwork {
        let initial_memos = initial_grants
            .into_iter()
            .map(|(ro, uid)| (ReceiverMemo::from_ro(&mut self.rng, &ro, &[]).unwrap(), uid))
            .collect();
        MockCapeNetwork::new(verif_crs, records, initial_memos)
    }

    async fn create_storage(&mut self) -> Self::MockStorage {
        let mut loader = MockCapeWalletLoader {
            path: self.temp_dir(),
            key: KeyTree::random(&mut self.rng).unwrap().0,
        };
        AtomicWalletStorage::new(&mut loader).unwrap()
    }

    async fn create_backend(
        &mut self,
        ledger: Arc<Mutex<MockLedger<'a, Self::Ledger, Self::MockNetwork, Self::MockStorage>>>,
        _initial_grants: Vec<(RecordOpening, u64)>,
        _seed: [u8; 32],
        storage: Arc<Mutex<Self::MockStorage>>,
        _key_pair: UserKeyPair,
    ) -> Self::MockBackend {
        MockCapeBackend::new_for_test(ledger, storage)
            .await
            .unwrap()
    }
}
