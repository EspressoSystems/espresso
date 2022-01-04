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

    fn last_event(&self) -> Option<LedgerEvent<CapeLedger>> {
        self.events.last().cloned()
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
        let key_id: u64 = 0;
        let key_pair = self.key_stream().derive_user_keypair(&key_id.to_le_bytes());
        self.register_user_key(&key_pair.pub_key()).await?;

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
        Ok(self
            .ledger
            .lock()
            .await
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
        println!("Posting memos for {}:{}", block_id, txn_id);
        let ledger = &mut *self.ledger.lock().await;
        let network = ledger.network();
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
        network.generate_event(event);

        Ok(())
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

#[cfg(any(test, fuzzing))]
pub mod test_helpers {
    use super::*;
    use crate::{
        state::{key_set, VerifierKeySet, MERKLE_HEIGHT},
        universal_params::UNIVERSAL_PARAM,
        wallet::{hd::KeyTree, Wallet},
    };
    use jf_aap::{
        keys::UserKeyPair,
        structs::{FreezeFlag, RecordCommitment},
        MerkleTree, TransactionVerifyingKey,
    };
    use key_set::KeySet;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::path::PathBuf;
    use std::time::Instant;
    use tempdir::TempDir;

    pub async fn create_test_network<'a>(
        xfr_sizes: &[(usize, usize)],
        initial_grants: Vec<u64>,
        now: &mut Instant,
    ) -> (
        Arc<Mutex<MockCapeLedger<'a>>>,
        Vec<(Wallet<'a, MockCapeBackend<'a, ()>, CapeLedger>, UserAddress)>,
        Vec<TempDir>,
    ) {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);

        // Populate the unpruned record merkle tree with an initial record commitment for each
        // non-zero initial grant. Collect user-specific info (keys and record openings
        // corresponding to grants) in `users`, which will be used to create the wallets later.
        let mut record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        let mut initial_grant_memos = Vec::new();
        let mut users: Vec<(KeyTree, UserKeyPair)> = vec![];
        for amount in initial_grants {
            let key_stream = KeyTree::random(&mut rng).unwrap().0;
            let wallet_key_stream = key_stream.derive_sub_tree("wallet".as_bytes());
            let key_id: u64 = 0;
            let key_pair = wallet_key_stream.derive_user_keypair(&key_id.to_le_bytes());

            if amount > 0 {
                let ro = RecordOpening::new(
                    &mut rng,
                    amount,
                    AssetDefinition::native(),
                    key_pair.pub_key(),
                    FreezeFlag::Unfrozen,
                );
                let comm = RecordCommitment::from(&ro);
                let uid = record_merkle_tree.num_leaves();
                record_merkle_tree.push(comm.to_field_element());

                let memo = ReceiverMemo::from_ro(&mut rng, &ro, &[]).unwrap();
                initial_grant_memos.push((memo, uid));

                users.push((key_stream, key_pair));
            } else {
                users.push((key_stream, key_pair));
            }
        }

        // Create the validator using the ledger state containing the initial grants, computed above.
        println!(
            "Generating validator keys: {}s",
            now.elapsed().as_secs_f32()
        );
        *now = Instant::now();

        let mut xfr_prove_keys = vec![];
        let mut xfr_verif_keys = vec![];
        for (num_inputs, num_outputs) in xfr_sizes {
            let (xfr_prove_key, xfr_verif_key, _) = jf_aap::proof::transfer::preprocess(
                &*UNIVERSAL_PARAM,
                *num_inputs,
                *num_outputs,
                MERKLE_HEIGHT,
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (_, mint_verif_key, _) =
            jf_aap::proof::mint::preprocess(&*UNIVERSAL_PARAM, MERKLE_HEIGHT).unwrap();
        let (_, freeze_verif_key, _) =
            jf_aap::proof::freeze::preprocess(&*UNIVERSAL_PARAM, 2, MERKLE_HEIGHT).unwrap();
        let verif_crs = VerifierKeySet {
            xfr: KeySet::new(xfr_verif_keys.into_iter()).unwrap(),
            mint: TransactionVerifyingKey::Mint(mint_verif_key),
            freeze: KeySet::new(
                vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
            )
            .unwrap(),
        };

        let ledger = Arc::new(Mutex::new(MockLedger::new(MockCapeNetwork::new(
            verif_crs,
            record_merkle_tree,
            initial_grant_memos,
        ))));

        // Create a wallet for each user based on the validator and the per-user information
        // computed above.
        let mut temp_dirs: Vec<TempDir> = Vec::new();
        let wallets: Vec<(Wallet<'a, MockCapeBackend<'a, ()>, CapeLedger>, UserAddress)> =
            iter(users)
                .enumerate()
                .then(|(i, (key_stream, key_pair))| {
                    let ledger = ledger.clone();
                    let temp_dir = TempDir::new(&format!("cape_wallet_{}", i)).unwrap();
                    let mut path = PathBuf::new();
                    path.push(temp_dir.path());
                    temp_dirs.push(temp_dir);
                    let path = TempDir::new(&format!("cape_wallet_{}", i))
                        .unwrap()
                        .into_path();
                    let mut loader = MockCapeWalletLoader {
                        path,
                        key: key_stream,
                    };
                    async move {
                        let mut wallet =
                            Wallet::new(MockCapeBackend::new(ledger, &mut loader).unwrap())
                                .await
                                .unwrap();
                        wallet.add_user_key(key_pair.clone(), 0).await.unwrap();
                        (wallet, key_pair.address())
                    }
                })
                .collect()
                .await;

        println!("Wallets set up: {}s", now.elapsed().as_secs_f32());
        *now = Instant::now();

        // Return the temporary directories to prevent them from being deleted now. They will
        // be automatically deleted when they are out of scope in the caller function.
        (ledger, wallets, temp_dirs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use jf_aap::structs::AssetCode;
    use std::time::Instant;
    use test_helpers::*;

    async fn test_two_wallets() {
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice an initial grant of 5 native coins and Bob an initial grant of 1 native
        // coin.
        let alice_grant = 5;
        let bob_grant = 1;
        let (ledger, mut wallets, _temp_dir) = create_test_network(
            &[(num_inputs, num_outputs)],
            vec![alice_grant, bob_grant],
            &mut now,
        )
        .await;
        ledger.lock().await.set_block_size(1).unwrap();
        let alice_address = wallets[0].1.clone();
        let bob_address = wallets[1].1.clone();

        // Verify initial wallet state.
        assert_ne!(alice_address, bob_address);
        assert_eq!(
            wallets[0]
                .0
                .balance(&alice_address, &AssetCode::native())
                .await,
            alice_grant
        );
        assert_eq!(
            wallets[1]
                .0
                .balance(&bob_address, &AssetCode::native())
                .await,
            bob_grant
        );

        let coin = wallets[0]
            .0
            .define_asset("Alice's asset".as_bytes(), Default::default())
            .await
            .unwrap();
        // Alice gives herself an initial grant of 5 coins.
        wallets[0]
            .0
            .mint(&alice_address, 1, &coin.code, 5, alice_address.clone())
            .await
            .unwrap();
        wallets[0].0.sync(2).await.unwrap();
        wallets[1].0.sync(2).await.unwrap();
        println!("Asset minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        assert_eq!(wallets[0].0.balance(&alice_address, &coin.code).await, 5);
        assert_eq!(wallets[1].0.balance(&bob_address, &coin.code).await, 0);

        let alice_initial_native_balance = wallets[0]
            .0
            .balance(&alice_address, &AssetCode::native())
            .await;
        let bob_initial_native_balance = wallets[1]
            .0
            .balance(&bob_address, &AssetCode::native())
            .await;

        // Construct a transaction to transfer some coins from Alice to Bob.
        wallets[0]
            .0
            .transfer(&alice_address, &coin.code, &[(bob_address.clone(), 3)], 1)
            .await
            .unwrap();
        wallets[0].0.sync(4).await.unwrap();
        wallets[1].0.sync(4).await.unwrap();
        println!("First transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both wallets reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `wallets` for).
        async fn check_balance<'a>(
            wallet: &(Wallet<'a, MockCapeBackend<'a, ()>, CapeLedger>, UserAddress),
            expected_coin_balance: u64,
            starting_native_balance: u64,
            fees_paid: u64,
            coin: &AssetDefinition,
        ) {
            assert_eq!(
                wallet.0.balance(&wallet.1, &coin.code).await,
                expected_coin_balance
            );
            assert_eq!(
                wallet.0.balance(&wallet.1, &AssetCode::native()).await,
                starting_native_balance - fees_paid
            );
        }
        check_balance(&wallets[0], 2, alice_initial_native_balance, 1, &coin).await;
        check_balance(&wallets[1], 3, bob_initial_native_balance, 0, &coin).await;

        // Check that Bob's wallet has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3
        // coins, but the sum of the outputs and fee of this transaction is only 2.
        wallets[1]
            .0
            .transfer(&bob_address, &coin.code, &[(alice_address, 1)], 1)
            .await
            .unwrap();
        wallets[0].0.sync(6).await.unwrap();
        wallets[1].0.sync(6).await.unwrap();
        println!(
            "Second transfer generated: {}s",
            now.elapsed().as_secs_f32()
        );

        check_balance(&wallets[0], 3, alice_initial_native_balance, 1, &coin).await;
        check_balance(&wallets[1], 2, bob_initial_native_balance, 1, &coin).await;
    }

    #[async_std::test]
    async fn test_xfr() -> std::io::Result<()> {
        test_two_wallets().await;
        Ok(())
    }
}
