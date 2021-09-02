#![deny(warnings)]

#[cfg(test)]
#[macro_use]
extern crate proptest;

mod set_merkle_tree;
mod util;

use async_scoped::AsyncScope;
use core::fmt::Debug;
use core::iter::once;
use futures::{channel::oneshot, prelude::*, stream::Stream};
use jf_primitives::{jubjub_dsa::Signature, merkle_tree};
use jf_txn::{
    errors::TxnApiError,
    freeze::{FreezeNote, FreezeNoteInput},
    keys::{
        AuditorKeyPair, AuditorPubKey, FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair,
        UserPubKey,
    },
    mint::MintNote,
    proof::{freeze::FreezeProvingKey, mint::MintProvingKey, transfer::TransferProvingKey},
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, BlindFactor, FeeInput, FreezeFlag,
        NoteType, Nullifier, ReceiverMemo, RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    txn_batch_verify,
    utils::compute_universal_param_size,
    TransactionNote, TransactionVerifyingKey,
};
use jf_utils::serialize::CanonicalBytes;
use merkle_tree::{AccMemberWitness, MerkleTree};
use phaselock::BlockContents;
#[allow(unused_imports)]
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
pub use set_merkle_tree::*;
use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{prelude::*, Read};
use std::ops::Bound::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const MERKLE_HEIGHT: u8 = 20 /*H*/;

// TODO
pub struct LedgerRecordCommitment(pub RecordCommitment);

// TODO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Transaction(pub TransactionNote);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ElaboratedTransaction {
    pub txn: TransactionNote,
    pub proofs: Vec<SetMerkleProof>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Block(pub Vec<TransactionNote>);

// A block with nullifier set non-membership proofs
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ElaboratedBlock {
    pub block: Block,
    pub proofs: Vec<Vec<SetMerkleProof>>,
}

impl BlockContents<64> for ElaboratedBlock {
    type State = ValidatorState;
    type Transaction = ElaboratedTransaction;
    type Error = ValidationError;

    fn next_block(_: &Self::State) -> Self {
        Default::default()
    }

    fn add_transaction(
        &self,
        _state: &ValidatorState,
        txn: &ElaboratedTransaction,
    ) -> Result<Self, ValidationError> {
        let mut ret = self.clone();

        let mut nulls = self
            .block
            .0
            .iter()
            .flat_map(|x| x.nullifiers().into_iter())
            .collect::<HashSet<_>>();
        for n in txn.txn.nullifiers().iter() {
            if nulls.contains(n) {
                return Err(ValidationError::ConflictingNullifiers {});
            }
            nulls.insert(*n);
        }

        ret.block.0.push(txn.txn.clone());
        ret.proofs.push(txn.proofs.clone());

        Ok(ret)
    }

    fn validate_block(&self, state: &ValidatorState) -> bool {
        state
            .validate_block(
                state.prev_commit_time + 1,
                self.block.clone(),
                self.proofs.clone(),
            )
            .is_ok()
    }
    fn append_to(&self, state: &ValidatorState) -> Result<ValidatorState, ValidationError> {
        let mut state = state.clone();
        state.validate_and_apply(
            state.prev_commit_time + 1,
            self.block.clone(),
            self.proofs.clone(),
            false,
        )?;
        Ok(state)
    }

    fn hash(&self) -> phaselock::BlockHash<64> {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "ElaboratedBlock".as_bytes());
        hasher.update("Block contents".as_bytes());
        hasher.update(&block_comm::block_commit(&self.block));
        hasher.update("Block proofs".as_bytes());
        hasher.update(&bincode::serialize(&self.proofs).unwrap());
        phaselock::BlockHash::<64>::from_array(
            hasher
                .finalize()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
        )
    }

    fn hash_bytes(bytes: &[u8]) -> phaselock::BlockHash<64> {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "PhaseLock bytes".as_bytes());
        hasher.update(bytes);
        phaselock::BlockHash::<64>::from_array(
            hasher
                .finalize()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
        )
    }

    fn hash_transaction(txn: &ElaboratedTransaction) -> phaselock::BlockHash<64> {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher =
            blake2::Blake2b::with_params(&[], &[], "ElaboratedTransaction Hash".as_bytes());
        hasher.update("Txn contents".as_bytes());
        hasher.update(&txn_comm::txn_commit(&txn.txn));
        hasher.update("Txn proofs".as_bytes());
        hasher.update(&bincode::serialize(&txn.proofs).unwrap());
        phaselock::BlockHash::<64>::from_array(
            hasher
                .finalize()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
        )
    }
}

mod key_set {
    use super::*;

    #[derive(Debug, Snafu)]
    #[snafu(visibility = "pub")]
    pub enum Error {
        DuplicateKeys {
            num_inputs: usize,
            num_outputs: usize,
        },
        NoKeys,
    }

    pub trait SizedKey {
        fn num_inputs(&self) -> usize;
        fn num_outputs(&self) -> usize;
    }

    impl<'a> SizedKey for TransferProvingKey<'a> {
        fn num_inputs(&self) -> usize {
            self.num_input()
        }

        fn num_outputs(&self) -> usize {
            self.num_output()
        }
    }

    impl<'a> SizedKey for FreezeProvingKey<'a> {
        fn num_inputs(&self) -> usize {
            self.num_input()
        }

        fn num_outputs(&self) -> usize {
            self.num_output()
        }
    }

    impl SizedKey for TransactionVerifyingKey {
        fn num_inputs(&self) -> usize {
            match self {
                TransactionVerifyingKey::Transfer(xfr) => xfr.num_input(),
                TransactionVerifyingKey::Freeze(freeze) => freeze.num_input(),
                TransactionVerifyingKey::Mint(_) => 1,
            }
        }

        fn num_outputs(&self) -> usize {
            match self {
                TransactionVerifyingKey::Transfer(xfr) => xfr.num_output(),
                TransactionVerifyingKey::Freeze(freeze) => freeze.num_output(),
                TransactionVerifyingKey::Mint(_) => 2,
            }
        }
    }

    pub trait KeyOrder {
        type SortKey: Ord + Debug + Clone + Serialize + for<'a> Deserialize<'a>;
        fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OrderByInputs;
    impl KeyOrder for OrderByInputs {
        type SortKey = (usize, usize);
        fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey {
            (num_inputs, num_outputs)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OrderByOutputs;
    impl KeyOrder for OrderByOutputs {
        type SortKey = (usize, usize);
        fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey {
            (num_outputs, num_inputs)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeySet<K: SizedKey, Order: KeyOrder = OrderByInputs> {
        keys: BTreeMap<Order::SortKey, K>,
    }

    impl<K: SizedKey, Order: KeyOrder> KeySet<K, Order> {
        /// Create a new KeySet with the keys in an iterator. `keys` must contain at least one key,
        /// and it must not contain two keys with the same size.
        pub fn new(keys: impl Iterator<Item = K>) -> Result<Self, Error> {
            let mut map = BTreeMap::new();
            for key in keys {
                let sort_key = Order::sort_key(key.num_inputs(), key.num_outputs());
                if map.contains_key(&sort_key) {
                    return Err(Error::DuplicateKeys {
                        num_inputs: key.num_inputs(),
                        num_outputs: key.num_outputs(),
                    });
                }
                map.insert(sort_key, key);
            }
            if map.is_empty() {
                return Err(Error::NoKeys);
            }
            Ok(Self { keys: map })
        }

        /// Get the largest size supported by this KeySet.
        ///
        /// Panics if there are no keys in the KeySet. Since new() requires at least one key, this
        /// can only happen if the KeySet is corrupt (for example, it was deserialized from a
        /// corrupted file).
        pub fn max_size(&self) -> (usize, usize) {
            let key = &self.keys.iter().next_back().unwrap().1;
            (key.num_inputs(), key.num_outputs())
        }

        pub fn key_for_size(&self, num_inputs: usize, num_outputs: usize) -> Option<&K> {
            self.keys.get(&Order::sort_key(num_inputs, num_outputs))
        }

        /// Return the smallest key whose size is at least (num_inputs, num_outputs). If no such key
        /// is available, the error contains the largest size that could have been supported.
        pub fn best_fit_key(
            &self,
            num_inputs: usize,
            num_outputs: usize,
        ) -> Result<(usize, usize, &K), (usize, usize)> {
            self.keys
                .range((
                    Included(Order::sort_key(num_inputs, num_outputs)),
                    Unbounded,
                ))
                .next()
                .map(|(_, key)| (key.num_inputs(), key.num_outputs(), key))
                .ok_or_else(|| self.max_size())
        }
    }
}
use key_set::KeySet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverKeySet<'a, Order: key_set::KeyOrder = key_set::OrderByInputs> {
    pub mint: MintProvingKey<'a>,
    pub xfr: KeySet<TransferProvingKey<'a>, Order>,
    pub freeze: KeySet<FreezeProvingKey<'a>, Order>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierKeySet<Order: key_set::KeyOrder = key_set::OrderByInputs> {
    // TODO: is there a way to keep these types distinct?
    pub mint: TransactionVerifyingKey,
    pub xfr: KeySet<TransactionVerifyingKey, Order>,
    pub freeze: KeySet<TransactionVerifyingKey, Order>,
}

// TODO
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum ValidationError {
    NullifierAlreadyExists {
        nullifier: Nullifier,
    },
    BadNullifierProof {},
    MissingNullifierProof {},
    ConflictingNullifiers {},
    Failed {},
    BadMerkleLength {},
    BadMerkleLeaf {},
    BadMerkleRoot {},
    BadMerklePath {},
    CryptoError {
        err: TxnApiError,
    },
    UnsupportedTransferSize {
        num_inputs: usize,
        num_outputs: usize,
    },
    UnsupportedFreezeSize {
        num_inputs: usize,
    },
}

// TxnApiError doesn't implement Clone :/
impl Clone for ValidationError {
    fn clone(&self) -> Self {
        use ValidationError::*;
        match self {
            NullifierAlreadyExists { nullifier } => NullifierAlreadyExists {
                nullifier: *nullifier,
            },
            BadNullifierProof {} => BadNullifierProof {},
            MissingNullifierProof {} => MissingNullifierProof {},
            ConflictingNullifiers {} => ConflictingNullifiers {},
            Failed {} => Failed {},
            BadMerkleLength {} => BadMerkleLength {},
            BadMerkleLeaf {} => BadMerkleLeaf {},
            BadMerkleRoot {} => BadMerkleRoot {},
            BadMerklePath {} => BadMerklePath {},
            CryptoError { .. } => Failed {},
            UnsupportedTransferSize {
                num_inputs,
                num_outputs,
            } => UnsupportedTransferSize {
                num_inputs: *num_inputs,
                num_outputs: *num_outputs,
            },
            UnsupportedFreezeSize { num_inputs } => UnsupportedFreezeSize {
                num_inputs: *num_inputs,
            },
        }
    }
}

mod verif_crs_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type VerifCRSCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn verif_crs_commit(p: &VerifierKeySet) -> VerifCRSCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "VerifCRS Comm".as_bytes());
        hasher.update(&bincode::serialize(&p).unwrap());
        hasher.finalize().into_bytes()
    }
}

mod txn_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type TxnCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn txn_commit(p: &TransactionNote) -> TxnCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "Txn Comm".as_bytes());
        let byte_stream = bincode::serialize(&p).unwrap_or_else(|_| [].to_vec());
        hasher.update(&byte_stream);
        hasher.finalize().into_bytes()
    }
}

mod block_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type BlockCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn block_commit(p: &Block) -> BlockCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "Block Comm".as_bytes());
        hasher.update(&p.0.len().to_le_bytes());
        for t in p.0.iter() {
            hasher.update(&txn_comm::txn_commit(t));
        }
        hasher.finalize().into_bytes()
    }
}

mod record_merkle_hist_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type RecordMerkleHistCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn record_merkle_hist_commit(
        p: &VecDeque<merkle_tree::NodeValue>,
    ) -> RecordMerkleHistCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "Hist Comm".as_bytes());
        hasher.update(&p.len().to_le_bytes());
        for hash in p {
            hasher.update(&CanonicalBytes::from(*hash).0);
        }
        hasher.finalize().into_bytes()
    }
}

pub mod state_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type LedgerStateCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;
    lazy_static::lazy_static! {
        pub static ref INITIAL_PREV_COMM: LedgerStateCommitment = GenericArray::<_,_>::default();
    }

    #[derive(Debug)]
    pub struct LedgerCommInputs {
        pub prev_commit_time: u64,
        pub prev_state: state_comm::LedgerStateCommitment,
        pub verif_crs: verif_crs_comm::VerifCRSCommitment,
        pub record_merkle_root: merkle_tree::NodeValue,
        pub past_record_merkle_roots: record_merkle_hist_comm::RecordMerkleHistCommitment,
        pub nullifiers: set_hash::Hash,
        pub next_uid: u64,
        pub prev_block: block_comm::BlockCommitment,
    }

    impl LedgerCommInputs {
        pub fn commit(&self) -> LedgerStateCommitment {
            let mut hasher = blake2::Blake2b::with_params(&[], &[], "Ledger Comm".as_bytes());
            hasher.update("prev_commit_time".as_bytes());
            hasher.update(&self.prev_commit_time.to_le_bytes());
            hasher.update("prev_state".as_bytes());
            hasher.update(&self.prev_state);
            hasher.update("verif_crs".as_bytes());
            hasher.update(&self.verif_crs);
            hasher.update("record_merkle_root".as_bytes());
            hasher.update(&CanonicalBytes::from(self.record_merkle_root).0);
            hasher.update("past_record_merkle_roots".as_bytes());
            hasher.update(&self.past_record_merkle_roots);
            hasher.update("nullifiers".as_bytes());
            hasher.update(&self.nullifiers);
            hasher.update("next_uid".as_bytes());
            hasher.update(&self.next_uid.to_le_bytes());
            hasher.update("prev_block".as_bytes());
            hasher.update(&self.prev_block);

            hasher.finalize().into_bytes()
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorState {
    pub prev_commit_time: u64,
    pub prev_state: state_comm::LedgerStateCommitment,
    pub verif_crs: VerifierKeySet,
    // The current record Merkle root hash
    pub record_merkle_root: merkle_tree::NodeValue,
    // A list of recent record Merkle root hashes for validating slightly-out- of date transactions.
    pub past_record_merkle_roots: VecDeque<merkle_tree::NodeValue>,
    pub record_merkle_frontier: merkle_tree::MerkleTree<RecordCommitment>,
    pub nullifiers_root: set_hash::Hash,
    pub next_uid: u64,
    pub prev_block: Block,
}

impl ValidatorState {
    // How many previous record Merkle tree root hashes the validator should remember.
    //
    // Transactions can be validated without resubmitting or regenerating the ZKPs as long as they
    // were generated using a validator state that is at most RECORD_ROOT_HISTORY_SIZE states before
    // the current one.
    const RECORD_ROOT_HISTORY_SIZE: usize = 10;

    pub fn new(
        verif_crs: VerifierKeySet,
        record_merkle_frontier: MerkleTree<RecordCommitment>,
    ) -> Self {
        let nullifiers: SetMerkleTree = Default::default();
        let next_uid = record_merkle_frontier.num_leaves();

        Self {
            prev_commit_time: 0u64,
            prev_state: *state_comm::INITIAL_PREV_COMM,
            verif_crs,
            record_merkle_root: record_merkle_frontier.get_root_value(),
            past_record_merkle_roots: VecDeque::with_capacity(Self::RECORD_ROOT_HISTORY_SIZE),
            record_merkle_frontier,
            nullifiers_root: nullifiers.hash(),
            next_uid,
            prev_block: Default::default(),
        }
    }

    pub fn commit(&self) -> state_comm::LedgerStateCommitment {
        let inputs = state_comm::LedgerCommInputs {
            prev_commit_time: self.prev_commit_time,
            prev_state: self.prev_state,
            verif_crs: verif_crs_comm::verif_crs_commit(&self.verif_crs),
            record_merkle_root: self.record_merkle_root,
            // We need to include all the cached past record Merkle roots in the state commitment,
            // even though they are not part of the current ledger state, because they affect
            // validation: two validators with different caches will be able to validate different
            // blocks.
            //
            // Note that this requires correct validators to agree on the number of cached past root
            // hashes, since all the cached hashes are included in the state commitment and are thus
            // part of the observable state of the ledger. This prevents heavyweight validators from
            // caching extra past roots and thereby making it easier to verify transactions, but
            // because root hashes are small, it should be possible to find a value of
            // RECORD_ROOT_HISTORY_SIZE which strikes a balance between small space requirements (so
            // that lightweight validators can keep up with the cache) and covering enough of
            // history to make it easy for clients. If this is not possible, lightweight validators
            // could also store a sparse history, and when they encounter a root hash that they do
            // not have cached, they could ask a full validator for a proof that that hash was once
            // the root of the record Merkle tree.
            past_record_merkle_roots: record_merkle_hist_comm::record_merkle_hist_commit(
                &self.past_record_merkle_roots,
            ),
            nullifiers: self.nullifiers_root,
            next_uid: self.next_uid,
            prev_block: block_comm::block_commit(&self.prev_block),
        };
        // dbg!(&inputs);
        inputs.commit()
    }

    pub fn validate_block(
        &self,
        now: u64,
        txns: Block,
        null_pfs: Vec<Vec<SetMerkleProof>>,
    ) -> Result<(Block, Vec<Vec<SetMerkleProof>>), ValidationError> {
        let mut nulls = HashSet::new();
        use ValidationError::*;
        for (pf, n) in null_pfs
            .iter()
            .zip(txns.0.iter())
            .flat_map(|(pfs, txn)| pfs.iter().zip(txn.nullifiers().into_iter()))
        {
            if nulls.contains(&n)
                || pf
                    .check(n, &self.nullifiers_root)
                    .map_err(|_| BadNullifierProof {})?
            {
                return Err(NullifierAlreadyExists { nullifier: n });
            }

            nulls.insert(n);
        }

        let verif_keys = txns
            .0
            .iter()
            .map(|txn| match txn {
                TransactionNote::Mint(_) => Ok(&self.verif_crs.mint),
                TransactionNote::Transfer(note) => {
                    let num_inputs = note.inputs_nullifiers.len();
                    let num_outputs = note.output_commitments.len();
                    self.verif_crs
                        .xfr
                        .key_for_size(num_inputs, num_outputs)
                        .ok_or(UnsupportedTransferSize {
                            num_inputs,
                            num_outputs,
                        })
                }
                TransactionNote::Freeze(note) => {
                    let num_inputs = note.input_nullifiers.len();
                    let num_outputs = note.output_commitments.len();
                    self.verif_crs
                        .freeze
                        .key_for_size(num_inputs, num_outputs)
                        .ok_or(UnsupportedFreezeSize { num_inputs })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if !txns.0.is_empty() {
            txn_batch_verify(
                &txns.0,
                &txns
                    .0
                    .iter()
                    .map(|note| {
                        // Only validate transactions if we can confirm that the record Merkle root
                        // they were generated with is a valid previous or current ledger state.
                        if self.record_merkle_root == note.merkle_root()
                            || self.past_record_merkle_roots.contains(&note.merkle_root())
                        {
                            Ok(note.merkle_root())
                        } else {
                            Err(BadMerkleRoot {})
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                now,
                &verif_keys,
            )
            .map_err(|err| CryptoError { err })?;
        }

        Ok((txns, null_pfs))
    }

    pub fn validate_and_apply(
        &mut self,
        now: u64,
        txns: Block,
        null_pfs: Vec<Vec<SetMerkleProof>>,
        remember_commitments: bool,
    ) -> Result<Vec<u64> /* new uids */, ValidationError> {
        let (txns, _null_pfs) = self.validate_block(now, txns, null_pfs.clone())?;
        let comm = self.commit();
        self.prev_commit_time = now;
        self.prev_block = txns.clone();

        let nullifiers = txns
            .0
            .iter()
            .zip(null_pfs.into_iter())
            .flat_map(|(txn, null_pfs)| txn.nullifiers().into_iter().zip(null_pfs.into_iter()))
            .collect();

        self.nullifiers_root = set_merkle_lw_multi_insert(nullifiers, self.nullifiers_root)
            .map_err(|_| ValidationError::BadNullifierProof {})?
            .0;

        let mut ret = vec![];
        for o in txns
            .0
            .iter()
            .flat_map(|x| x.output_commitments().into_iter())
        {
            let uid = self.next_uid;
            self.record_merkle_frontier.push(o);
            if !remember_commitments {
                self.record_merkle_frontier.forget(uid).expect_ok().unwrap();
            }
            ret.push(uid);
            self.next_uid += 1;
            assert_eq!(self.next_uid, self.record_merkle_frontier.num_leaves());
        }

        if self.past_record_merkle_roots.len() >= Self::RECORD_ROOT_HISTORY_SIZE {
            self.past_record_merkle_roots.pop_back();
        }
        self.past_record_merkle_roots
            .push_front(self.record_merkle_root);
        self.record_merkle_root = self.record_merkle_frontier.get_root_value();
        self.prev_state = comm;
        Ok(ret)
    }
}

pub struct MultiXfrTestState {
    pub prng: ChaChaRng,

    pub univ_setup: &'static jf_txn::proof::UniversalParam,
    pub prove_keys: ProverKeySet<'static>,
    pub verif_keys: VerifierKeySet,

    pub native_token: AssetDefinition,

    pub keys: Vec<UserKeyPair>,

    pub asset_seeds: Vec<(AssetCodeSeed, Vec<u8>)>,
    pub asset_defs: Vec<AssetDefinition>,

    pub fee_records: Vec<u64>, // for each key
    pub owners: Vec<usize>,    // for each record
    pub memos: Vec<ReceiverMemo>,
    pub nullifiers: SetMerkleTree,
    pub record_merkle_tree: merkle_tree::MerkleTree<RecordCommitment>,
    // pub asset_defs: Vec<AssetDefinition>,
    pub validator: ValidatorState,

    pub outer_timer: Instant,
    pub inner_timer: Instant,
}

/// Generates universal parameter and store it to file.
pub fn set_universal_param(prng: &mut ChaChaRng) {
    let universal_param = jf_txn::proof::universal_setup(
        *[
            compute_universal_param_size(NoteType::Transfer, 3, 3, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Transfer: {}",
                        err
                    )
                },
            ),
            compute_universal_param_size(NoteType::Mint, 0, 0, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Mint: {}",
                        err
                    )
                },
            ),
            compute_universal_param_size(NoteType::Freeze, 2, 2, MERKLE_HEIGHT).unwrap_or_else(
                |err| {
                    panic!(
                        "Error while computing the universal parameter size for Freeze: {}",
                        err
                    )
                },
            ),
        ]
        .iter()
        .max()
        .unwrap(),
        prng,
    )
    .unwrap_or_else(|err| panic!("Error while setting up the universal parameter: {}", err));
    let param_bytes = bincode::serialize(&universal_param)
        .unwrap_or_else(|err| panic!("Error while serializing the universal parameter: {}", err));
    // TODO: Remove literal relative paths (https://gitlab.com/translucence/systems/system/-/issues/17)
    let mut file = File::create("../../zerok/zerok_lib/src/universal_param".to_string())
        .unwrap_or_else(|err| panic!("Error while creating a universal parameter file: {}", err));
    file.write_all(&param_bytes).unwrap_or_else(|err| {
        panic!(
            "Error while writing to the universal parameter file: {}",
            err
        )
    });
}

/// Reads universal parameter from file if it exists. If not, generates the universal parameter, stores
/// it to file, and returns it.
pub fn get_universal_param(prng: &mut ChaChaRng) -> jf_txn::proof::UniversalParam {
    // TODO: Remove literal relative paths (https://gitlab.com/translucence/systems/system/-/issues/17)
    let path_str = "../../zerok/zerok_lib/src/universal_param".to_string();
    let path = Path::new(&path_str);

    // create a new seeded PRNG from the master PRNG when getting the UniversalParam. This ensures a
    // deterministic RNG result after the call, either the UniversalParam is newly generated or loaded
    // from a file.
    let mut new_prng = ChaChaRng::from_rng(prng)
        .unwrap_or_else(|err| panic!("Error while creating a new PRNG: {}", err));
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            set_universal_param(&mut new_prng);
            File::open(&path).unwrap_or_else(|_| {
                panic!(
                    "Cannot find the universal parameter file after generation: {}",
                    path.display()
                )
            })
        }
    };
    let mut param_bytes = Vec::new();
    file.read_to_end(&mut param_bytes)
        .unwrap_or_else(|err| panic!("Error while reading the universal parameter file: {}", err));
    bincode::deserialize(&param_bytes[..])
        .unwrap_or_else(|err| panic!("Error while deserializing the universal parameter: {}", err))
}

#[derive(Debug, Clone, Copy)]
pub struct MultiXfrRecordSpec {
    pub asset_def_ix: u8,
    pub owner_key_ix: u8,
    pub asset_amount: u64,
}

impl MultiXfrTestState {
    pub fn update_timer<F>(now: &mut Instant, print: F)
    where
        F: FnOnce(f32),
    {
        print(now.elapsed().as_secs_f32());
        *now = Instant::now();
    }

    /// Creates test state with initial records.
    ///
    /// Notes: `initial_records` must have at least one record, which is the first element of the tuple, `MultiXfrRecordSpec`.
    /// The second element, `Vec<MultiXfrRecordSpec>`, may store additional elements or be `None`.
    pub fn initialize(
        seed: [u8; 32],
        num_keys: u8,
        num_asset_defs: u8,
        initial_records: (MultiXfrRecordSpec, Vec<MultiXfrRecordSpec>),
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut timer = Instant::now();
        Self::update_timer(&mut timer, |_| println!("Generating params"));
        let mut prng = ChaChaRng::from_seed(seed);

        let univ_setup = Box::leak(Box::new(get_universal_param(&mut prng)));
        let (xfr_prove_key_22, xfr_verif_key_22, _) =
            jf_txn::proof::transfer::preprocess(univ_setup, 2, 2, MERKLE_HEIGHT)?;
        let (xfr_prove_key_33, xfr_verif_key_33, _) =
            jf_txn::proof::transfer::preprocess(univ_setup, 3, 3, MERKLE_HEIGHT)?;
        let (mint_prove_key, mint_verif_key, _) =
            jf_txn::proof::mint::preprocess(univ_setup, MERKLE_HEIGHT)?;
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_txn::proof::freeze::preprocess(univ_setup, 2, MERKLE_HEIGHT)?;

        let native_token = AssetDefinition::native();

        Self::update_timer(&mut timer, |t| println!("CRS set up: {}s", t));

        let keys: Vec<_> = (0..=(num_keys as usize + 1))
            .map(|_| UserKeyPair::generate(&mut prng))
            .collect();

        let asset_seeds: Vec<(AssetCodeSeed, Vec<u8>)> = (0..=(num_asset_defs as usize))
            .map(|i| {
                (
                    AssetCodeSeed::generate(&mut prng),
                    format!("Def {}", i).as_bytes().to_vec(),
                )
            })
            .collect();
        let asset_defs: Vec<AssetDefinition> = once(Ok(native_token.clone()))
            .chain(asset_seeds.iter().map(|(seed, desc)| {
                AssetDefinition::new(AssetCode::new(*seed, desc), Default::default())
            }))
            .collect::<Result<Vec<_>, _>>()?;

        let mut owners = vec![];
        let mut memos = vec![];

        Self::update_timer(&mut timer, |t| println!("Keys and defs: {}s", t));

        let mut t = MerkleTree::new(MERKLE_HEIGHT).ok_or(ValidationError::Failed {})?;

        let mut fee_records = vec![];

        for key in 0..keys.len() as u8 {
            let amt = 1u64 << 32;
            fee_records.push(t.num_leaves());
            let def = &asset_defs[0];
            let key = key as usize % keys.len();
            owners.push(key);
            let key = &keys[key];
            let rec = RecordOpening::new(
                &mut prng,
                amt,
                def.clone(),
                key.pub_key(),
                FreezeFlag::Unfrozen,
            );

            t.push(RecordCommitment::from(&rec));

            memos.push(ReceiverMemo::from_ro(&mut prng, &rec, &[])?);
        }

        Self::update_timer(&mut timer, |t| println!("Native token records: {}s", t));

        let nullifiers: SetMerkleTree = Default::default();

        let verif_keys = VerifierKeySet {
            mint: TransactionVerifyingKey::Mint(mint_verif_key),
            xfr: KeySet::new(
                vec![
                    TransactionVerifyingKey::Transfer(xfr_verif_key_22),
                    TransactionVerifyingKey::Transfer(xfr_verif_key_33),
                ]
                .into_iter(),
            )?,
            freeze: KeySet::new(
                vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
            )?,
        };

        Self::update_timer(&mut timer, |t| println!("Verify Keys: {}s", t));

        let mut ret = Self {
            univ_setup,
            prng,
            prove_keys: ProverKeySet {
                mint: mint_prove_key,
                xfr: KeySet::new(vec![xfr_prove_key_22, xfr_prove_key_33].into_iter())?,
                freeze: KeySet::new(vec![freeze_prove_key].into_iter())?,
            },
            verif_keys: verif_keys.clone(),
            native_token,
            keys,
            fee_records,
            asset_seeds,
            asset_defs,
            owners,
            memos,
            nullifiers, /*asset_defs,*/
            record_merkle_tree: t.clone(),
            validator: ValidatorState::new(verif_keys, t),
            outer_timer: timer,
            inner_timer: Instant::now(),
        };

        let mut setup_block = ElaboratedBlock::next_block(&ret.validator);

        let mut keys_in_block = HashSet::<usize>::new();

        let mut to_add = std::iter::once(initial_records.0)
            .chain((initial_records.1).into_iter())
            .flat_map(|x| vec![x, x].into_iter())
            .map(|spec| (spec.asset_def_ix, spec.owner_key_ix, spec.asset_amount))
            .collect::<Vec<_>>();

        while !to_add.is_empty() {
            let mut this_block = vec![];
            for (def_ix, key, amt) in core::mem::take(&mut to_add).into_iter() {
                let amt = if amt < 2 { 2 } else { amt };
                let def_ix = def_ix as usize % ret.asset_defs.len();
                // We can't mint native tokens
                let def_ix = if def_ix < 1 { 1 } else { def_ix };
                let kix = key as usize % ret.keys.len();

                if keys_in_block.contains(&kix) {
                    to_add.push((def_ix as u8, key, amt));
                    continue;
                } else {
                    keys_in_block.insert(kix);
                    this_block.push((def_ix as u8, key, amt));
                }
            }

            let this_block = this_block
                .into_iter()
                .map(|x| ChaChaRng::from_rng(&mut ret.prng).map(|y| (x, y)))
                .collect::<Result<Vec<_>, _>>()?;

            let txns = this_block
                .into_par_iter()
                .map(|((def_ix, key, amt), mut prng)| {
                    let amt = if amt < 2 { 2 } else { amt };
                    let def_ix = def_ix as usize % ret.asset_defs.len();
                    // We can't mint native tokens
                    let def_ix = if def_ix < 1 { 1 } else { def_ix };
                    let def = ret.asset_defs[def_ix].clone();
                    let kix = key as usize % ret.keys.len();

                    let key = &ret.keys[kix];

                    let rec = RecordOpening::new(
                        &mut prng,
                        amt,
                        def,
                        key.pub_key(),
                        FreezeFlag::Unfrozen,
                    );

                    /*
                                *
                                * pub fn generate<R>(
                        rng: &mut R,
                        mint_ro: RecordOpening,
                        ac_seed: AssetCodeSeed,
                        ac_description: &[u8],
                        fee_input: FeeInput<'_>,
                        fee: u64,
                        proving_key: &MintProvingKey<'_>
                    ) -> Result<(Self, [ReceiverMemo; 2], Signature, RecordOpening), TxnApiError>
                                */

                    let fee_ix = ret.fee_records[kix];
                    let fee_rec = {
                        let comm = ret
                            .record_merkle_tree
                            .get_leaf(fee_ix as u64)
                            .expect_ok()
                            .unwrap()
                            .0;
                        let memo = ret.memos[fee_ix as usize].clone();
                        let open_rec = memo.decrypt(key, &comm, &[]).unwrap();
                        let nullifier = key.nullify(
                            open_rec.asset_def.policy_ref().freezer_pub_key(),
                            fee_ix as u64,
                            &comm,
                        );
                        assert!(!ret.nullifiers.contains(nullifier).unwrap().0);
                        open_rec
                    };

                    assert_eq!(
                        ret.record_merkle_tree.get_root_value(),
                        ret.validator.record_merkle_frontier.get_root_value()
                    );
                    let fee_input = FeeInput {
                        ro: fee_rec,
                        owner_keypair: key,
                        acc_member_witness: AccMemberWitness {
                            merkle_path: ret
                                .record_merkle_tree
                                .get_leaf(fee_ix)
                                .expect_ok()
                                .unwrap()
                                .1,
                            root: ret.validator.record_merkle_frontier.get_root_value(),
                            uid: fee_ix,
                        },
                    };

                    let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut prng, fee_input, 1).unwrap();

                    let memos = vec![
                        ReceiverMemo::from_ro(&mut prng, &fee_out_rec, &[]).unwrap(),
                        ReceiverMemo::from_ro(&mut prng, &rec, &[]).unwrap(),
                    ];

                    // TODO: use and check the ReceiverMemo signature
                    let (note, _memo_kp) = MintNote::generate(
                        &mut prng,
                        rec,
                        ret.asset_seeds[def_ix - 1].0,
                        &ret.asset_seeds[def_ix - 1].1,
                        fee_info,
                        &ret.prove_keys.mint,
                    )
                    .unwrap();

                    (kix, note, memos)
                })
                .collect::<Vec<_>>();

            for (kix, note, memos) in txns {
                let nul = ret.nullifiers.contains(note.input_nullifier).unwrap().1;

                let ix = setup_block.block.0.len();
                ret.try_add_transaction(
                    &mut setup_block,
                    ElaboratedTransaction {
                        txn: TransactionNote::Mint(Box::new(note)),
                        proofs: vec![nul],
                    },
                    0,
                    ix,
                    0,
                    memos,
                    vec![kix, kix],
                )
                .unwrap();
            }

            keys_in_block.clear();
            ret.validate_and_apply(core::mem::take(&mut setup_block), 0, 0, 0.0)
                .unwrap();

            setup_block = ElaboratedBlock::next_block(&ret.validator);
        }

        ret.validate_and_apply(core::mem::take(&mut setup_block), 0, 0, 0.0)
            .unwrap();

        Ok(ret)
    }

    /// Generates transactions with the specified block information.
    ///
    /// For each transaction `(multi_input, rec1, rec2, key1, key2, diff)` in `block`, takes the the
    ///     records {rec1} or {rec1, rec2} (depending on the value of `multi_input`), transfers them
    ///     to `key1`, and, if `multi_input`, `key2`, and tries to have the difference in value
    ///     between the output records be `diff`.
    ///
    /// Returns vector of
    ///     index of transaction within block
    ///     (receiver memos, receiver indices)
    ///     transaction
    ///
    /// Note: `round` and `num_txs` are for `println!`s only.
    // Issue: https://gitlab.com/translucence/systems/system/-/issues/16.
    #[allow(clippy::type_complexity)]
    pub fn generate_transactions(
        &mut self,
        round: usize,
        block: Vec<(bool, u16, u16, u8, u8, i32)>,
        num_txs: usize,
    ) -> Result<
        Vec<(usize, Vec<(usize, ReceiverMemo)>, ElaboratedTransaction)>,
        Box<dyn std::error::Error>,
    > {
        let splits = block
            .into_iter()
            .enumerate()
            .map(|x| ChaChaRng::from_rng(&mut self.prng).map(|y| (x, y)))
            .collect::<Result<Vec<_>, _>>()?;

        let mut txns = splits
            .into_par_iter()
            .map(
                |((ix, (multi_input, in1, in2, k1, k2, amt_diff)), mut prng)| {
                    let now = Instant::now();

                    println!("Txn {}.{}/{}", round + 1, ix, num_txs);

                    let mut fee_rec = None;
                    let mut rec1 = None;
                    let mut rec2 = None;

                    let mut in1 = in1 as usize % self.owners.len();
                    let mut in2 = in2 as usize % self.owners.len();
                    for i in (0..(self.owners.len() - in1)).rev() {
                        let memo = &self.memos[i];
                        let kix = self.owners[i];
                        // it's their fee wallet
                        if i as u64 == self.fee_records[kix] {
                            continue;
                        }

                        let key = &self.keys[kix];

                        let comm = self
                            .record_merkle_tree
                            .get_leaf(i as u64)
                            .expect_ok()
                            .unwrap()
                            .0;

                        let open_rec = memo.decrypt(key, &comm, &[]).unwrap();

                        let nullifier = key.nullify(
                            open_rec.asset_def.policy_ref().freezer_pub_key(),
                            i as u64,
                            &comm,
                        );
                        if !self.nullifiers.contains(nullifier).unwrap().0 {
                            in1 = i;
                            rec1 = Some((open_rec, kix));
                            let fee_ix = self.fee_records[kix];
                            fee_rec = Some((fee_ix, {
                                let comm = self
                                    .record_merkle_tree
                                    .get_leaf(fee_ix as u64)
                                    .expect_ok()
                                    .unwrap()
                                    .0;
                                let memo = self.memos[fee_ix as usize].clone();
                                let open_rec = memo.decrypt(key, &comm, &[]).unwrap();
                                let nullifier = key.nullify(
                                    open_rec.asset_def.policy_ref().freezer_pub_key(),
                                    fee_ix as u64,
                                    &comm,
                                );
                                assert!(!self.nullifiers.contains(nullifier).unwrap().0);
                                open_rec
                            }));
                        }
                    }

                    if !multi_input {
                        if let Some((rec1, in_key1)) = &rec1 {
                            return self.generate_single_record_transfer(
                                &mut prng,
                                in1,
                                rec1.clone(),
                                *in_key1,
                                fee_rec,
                                k1,
                                round,
                                ix,
                                num_txs,
                                now,
                            );
                        }
                    }

                    // TODO; factor this into a local closure or something instead
                    // of a pasted block
                    for i in (0..(self.owners.len() - in2)).rev() {
                        if i == in1 {
                            continue;
                        }

                        let memo = &self.memos[i];
                        let kix = self.owners[i];
                        let key = &self.keys[kix];

                        if i as u64 == self.fee_records[kix] {
                            continue;
                        }

                        let comm = self
                            .record_merkle_tree
                            .get_leaf(i as u64)
                            .expect_ok()
                            .unwrap()
                            .0;

                        let open_rec = memo.decrypt(key, &comm, &[]).unwrap();

                        let nullifier = key.nullify(
                            open_rec.asset_def.policy_ref().freezer_pub_key(),
                            i as u64,
                            &comm,
                        );
                        if !self.nullifiers.contains(nullifier).unwrap().0 {
                            in2 = i;
                            rec2 = Some((open_rec, kix));
                            if fee_rec.is_none() {
                                let fee_ix = self.fee_records[kix];
                                fee_rec = Some((fee_ix, {
                                    let comm = self
                                        .record_merkle_tree
                                        .get_leaf(fee_ix as u64)
                                        .expect_ok()
                                        .unwrap()
                                        .0;
                                    let memo = self.memos[fee_ix as usize].clone();
                                    let open_rec = memo.decrypt(key, &comm, &[]).unwrap();
                                    let nullifier = key.nullify(
                                        open_rec.asset_def.policy_ref().freezer_pub_key(),
                                        fee_ix as u64,
                                        &comm,
                                    );
                                    assert!(!self.nullifiers.contains(nullifier).unwrap().0);
                                    open_rec
                                }));
                            }
                            break;
                        }
                    }

                    if !multi_input {
                        if let Some((rec2, in_key2)) = &rec2 {
                            return self.generate_single_record_transfer(
                                &mut prng,
                                in2,
                                rec2.clone(),
                                *in_key2,
                                fee_rec,
                                k1,
                                round,
                                ix,
                                num_txs,
                                now,
                            );
                        }
                    }

                    if rec1.is_none() || rec2.is_none() {
                        println!(
                            "Txn {}.{}/{}: No records found, {}s",
                            round + 1,
                            ix,
                            num_txs,
                            now.elapsed().as_secs_f32()
                        );
                        return None;
                    }

                    let (fee_ix, fee_rec) = fee_rec?;
                    let ((rec1, in_key1), (rec2, in_key2)) = (rec1?, rec2?);
                    let in_key1_ix = in_key1;
                    let in_key1 = &self.keys[in_key1];
                    let in_key2 = &self.keys[in_key2];

                    assert!(fee_ix != in1 as u64);
                    assert!(fee_ix != in2 as u64);

                    let k1 = k1 as usize % self.keys.len();
                    let k1_ix = k1;
                    let k1 = &self.keys[k1];
                    let k2 = k2 as usize % self.keys.len();
                    let k2_ix = k2;
                    let k2 = &self.keys[k2];

                    let out_def1 = rec1.asset_def.clone();
                    let out_def2 = rec2.asset_def.clone();

                    let (out_amt1, out_amt2) = {
                        if out_def1 == out_def2 {
                            let total = rec1.amount + rec2.amount;
                            let offset = (amt_diff as i64) / 2;
                            let midval = (total / 2) as i64;
                            let amt1 = midval + offset;
                            let amt1 = if amt1 < 1 {
                                1
                            } else if amt1 as u64 >= total {
                                total - 1
                            } else {
                                amt1 as u64
                            };
                            let amt2 = total - amt1;
                            (amt1, amt2)
                        } else {
                            (rec1.amount, rec2.amount)
                        }
                    };

                    // dbg!(&out_amt1);
                    // dbg!(&out_amt2);
                    // dbg!(&fee_rec.amount);

                    let out_rec1 = RecordOpening::new(
                        &mut prng,
                        out_amt1,
                        out_def1,
                        k1.pub_key(),
                        FreezeFlag::Unfrozen,
                    );

                    let out_rec2 = RecordOpening::new(
                        &mut prng,
                        out_amt2,
                        out_def2,
                        k2.pub_key(),
                        FreezeFlag::Unfrozen,
                    );

                    // self.memos.push(ReceiverMemo::from_ro(&mut prng, &out_rec1, &[]).unwrap());
                    // self.memos.push(ReceiverMemo::from_ro(&mut prng, &out_rec2, &[]).unwrap());

                    println!(
                        "Txn {}.{}/{} inputs chosen: {}",
                        round + 1,
                        ix,
                        num_txs,
                        now.elapsed().as_secs_f32()
                    );
                    let now = Instant::now();

                    let fee_input = FeeInput {
                        ro: fee_rec,
                        owner_keypair: in_key1,
                        acc_member_witness: AccMemberWitness {
                            merkle_path: self
                                .record_merkle_tree
                                .get_leaf(fee_ix)
                                .expect_ok()
                                .unwrap()
                                .1,
                            root: self.validator.record_merkle_frontier.get_root_value(),
                            uid: fee_ix,
                        },
                    };

                    let input1 = TransferNoteInput {
                        ro: rec1,
                        owner_keypair: in_key1,
                        cred: None,
                        acc_member_witness: AccMemberWitness {
                            merkle_path: self
                                .record_merkle_tree
                                .get_leaf(in1 as u64)
                                .expect_ok()
                                .unwrap()
                                .1,
                            root: self.validator.record_merkle_frontier.get_root_value(),
                            uid: in1 as u64,
                        },
                    };

                    let input2 = TransferNoteInput {
                        ro: rec2,
                        owner_keypair: in_key2,
                        cred: None,
                        acc_member_witness: AccMemberWitness {
                            merkle_path: self
                                .record_merkle_tree
                                .get_leaf(in2 as u64)
                                .expect_ok()
                                .unwrap()
                                .1,
                            root: self.validator.record_merkle_frontier.get_root_value(),
                            uid: in2 as u64,
                        },
                    };

                    println!(
                        "Txn {}.{}/{} inputs generated: {}",
                        round + 1,
                        ix,
                        num_txs,
                        now.elapsed().as_secs_f32()
                    );
                    let now = Instant::now();

                    let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut prng, fee_input, 1).unwrap();

                    let owner_memos = vec![&fee_out_rec, &out_rec1, &out_rec2]
                        .into_iter()
                        .map(|r| ReceiverMemo::from_ro(&mut prng, r, &[]))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    let (txn, _owner_memo_kp) = TransferNote::generate_non_native(
                        &mut prng,
                        vec![input1, input2],
                        &[out_rec1, out_rec2],
                        fee_info,
                        self.validator.prev_commit_time + 1,
                        self.prove_keys.xfr.key_for_size(3, 3).unwrap(),
                    )
                    .unwrap();

                    // owner_memos_key
                    // .verify(&helpers::get_owner_memos_digest(&owner_memos),
                    //     &owner_memos_sig)?;
                    println!(
                        "Txn {}.{}/{} note generated: {}",
                        round + 1,
                        ix,
                        num_txs,
                        now.elapsed().as_secs_f32()
                    );
                    let now = Instant::now();

                    let nullifier_pfs = txn
                        .inputs_nullifiers
                        .iter()
                        .map(|n| self.nullifiers.contains(*n).unwrap().1)
                        .collect();

                    println!(
                        "Txn {}.{}/{} nullifier proofs generated: {}s",
                        round + 1,
                        ix,
                        num_txs,
                        now.elapsed().as_secs_f32()
                    );

                    assert_eq!(owner_memos.len(), 3);
                    let keys_and_memos = vec![in_key1_ix, k1_ix, k2_ix]
                        .into_iter()
                        .zip(owner_memos.into_iter())
                        .collect();

                    Some((
                        ix,
                        keys_and_memos,
                        ElaboratedTransaction {
                            txn: TransactionNote::Transfer(Box::new(txn)),
                            proofs: nullifier_pfs,
                        },
                    ))
                },
            )
            .filter_map(|x| x)
            .collect::<Vec<_>>();

        txns.sort_by(|(i, _, _), (j, _, _)| i.cmp(j));
        Ok(txns)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn generate_single_record_transfer(
        &self,
        prng: &mut ChaChaRng,
        rec_ix: usize,
        rec: RecordOpening,
        in_key_ix: usize,
        fee_rec: Option<(u64, RecordOpening)>,
        out_key_ix: u8,
        round: usize,
        ix: usize,
        num_txs: usize,
        now: Instant,
    ) -> Option<(usize, Vec<(usize, ReceiverMemo)>, ElaboratedTransaction)> {
        println!(
            "Txn {}.{}/{}: generating single-input transaction {}s",
            round + 1,
            ix,
            num_txs,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let in_key = &self.keys[in_key_ix];
        let (fee_ix, fee_rec) = fee_rec?;

        let out_key_ix = out_key_ix as usize % self.keys.len();
        let out_key = &self.keys[out_key_ix];

        assert_ne!(rec.amount, 0);
        let out_rec1 = RecordOpening::new(
            prng,
            rec.amount,
            rec.asset_def.clone(),
            out_key.pub_key(),
            FreezeFlag::Unfrozen,
        );

        println!(
            "Txn {}.{}/{} inputs chosen: {}",
            round + 1,
            ix,
            num_txs,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let fee_input = FeeInput {
            ro: fee_rec,
            owner_keypair: in_key,
            acc_member_witness: AccMemberWitness {
                merkle_path: self
                    .record_merkle_tree
                    .get_leaf(fee_ix)
                    .expect_ok()
                    .unwrap()
                    .1,
                root: self.validator.record_merkle_frontier.get_root_value(),
                uid: fee_ix,
            },
        };

        let input = TransferNoteInput {
            ro: rec,
            owner_keypair: in_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: self
                    .record_merkle_tree
                    .get_leaf(rec_ix as u64)
                    .expect_ok()
                    .unwrap()
                    .1,
                root: self.validator.record_merkle_frontier.get_root_value(),
                uid: rec_ix as u64,
            },
        };

        println!(
            "Txn {}.{}/{} inputs generated: {}",
            round + 1,
            ix,
            num_txs,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let (fee_info, fee_out_rec) = TxnFeeInfo::new(prng, fee_input, 1).unwrap();

        let owner_memos = vec![&fee_out_rec, &out_rec1]
            .into_iter()
            .map(|r| ReceiverMemo::from_ro(prng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let (txn, _owner_memo_kp) = TransferNote::generate_non_native(
            prng,
            vec![input],
            &[out_rec1],
            fee_info,
            self.validator.prev_commit_time + 1,
            self.prove_keys.xfr.key_for_size(2, 2).unwrap(),
        )
        .unwrap();

        println!(
            "Txn {}.{}/{} note generated: {}",
            round + 1,
            ix,
            num_txs,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let nullifier_pfs = txn
            .inputs_nullifiers
            .iter()
            .map(|n| self.nullifiers.contains(*n).unwrap().1)
            .collect();

        println!(
            "Txn {}.{}/{} nullifier proofs generated: {}s",
            round + 1,
            ix,
            num_txs,
            now.elapsed().as_secs_f32()
        );

        assert_eq!(owner_memos.len(), 2);
        let keys_and_memos = vec![in_key_ix, out_key_ix]
            .into_iter()
            .zip(owner_memos.into_iter())
            .collect();

        Some((
            ix,
            keys_and_memos,
            ElaboratedTransaction {
                txn: TransactionNote::Transfer(Box::new(txn)),
                proofs: nullifier_pfs,
            },
        ))
    }

    /// Tries to add a transaction to a block.
    ///
    /// Note: `round` and `num_txs` are for `println!`s only.
    // Issue: https://gitlab.com/translucence/systems/system/-/issues/16.
    #[allow(clippy::too_many_arguments)]
    pub fn try_add_transaction(
        &mut self,
        blk: &mut ElaboratedBlock,
        txn: ElaboratedTransaction,
        round: usize,
        ix: usize,
        num_txs: usize,
        owner_memos: Vec<ReceiverMemo>,
        kixs: Vec<usize>,
    ) -> Result<(), ValidationError> {
        println!("Block {}/{} trying to add {}", round + 1, num_txs, ix);

        let base_ix = self.record_merkle_tree.num_leaves()
            + blk
                .block
                .0
                .iter()
                .map(|x| x.output_commitments().len() as u64)
                .sum::<u64>();
        let newblk = blk.add_transaction(&self.validator, &txn)?;
        println!("Block {}/{} adding {}", round + 1, num_txs, ix);
        self.memos.extend(owner_memos);
        self.fee_records[kixs[0]] = base_ix;
        self.owners.extend(kixs);

        *blk = newblk;
        Ok(())
    }

    /// Validates and applys a block.
    ///
    /// Note: `round` and `num_txs` are for `println!`s only.
    // Issue: https://gitlab.com/translucence/systems/system/-/issues/16.
    pub fn validate_and_apply(
        &mut self,
        blk: ElaboratedBlock,
        round: usize,
        num_txs: usize,
        generation_time: f32,
    ) -> Result<(), ValidationError> {
        Self::update_timer(&mut self.inner_timer, |_| ());

        if !blk.validate_block(&self.validator) {
            self.validator.validate_block(
                self.validator.prev_commit_time + 1,
                blk.block.clone(),
                blk.proofs,
            )?;
            return Err(ValidationError::Failed {});
        }
        let new_state = blk.append_to(&self.validator).unwrap();

        for n in blk.block.0.iter().flat_map(|x| x.nullifiers().into_iter()) {
            assert!(!self.nullifiers.contains(n).unwrap().0);
            self.nullifiers.insert(n);
        }
        for comm in blk
            .block
            .0
            .iter()
            .flat_map(|x| x.output_commitments().into_iter())
        {
            self.record_merkle_tree.push(comm);
        }

        self.validator = new_state;

        let mut checking_time: f32 = 0.0;
        Self::update_timer(&mut self.inner_timer, |t| {
            checking_time = t;
        });

        Self::update_timer(&mut self.outer_timer, |t| {
            println!(
                "Block {}/{}: {} transactions, {}s ({}s generation, {}s checking)",
                round + 1,
                num_txs,
                blk.block.0.len(),
                t,
                generation_time,
                checking_time
            )
        });

        assert_eq!(self.nullifiers.hash(), self.validator.nullifiers_root);
        Ok(())
    }
}

#[derive(Debug)]
pub enum WalletError {
    InsufficientBalance {
        asset: AssetCode,
        required: u64,
        actual: u64,
    },
    Fragmentation {
        asset: AssetCode,
        amount: u64,
        suggested_amount: u64,
        max_records: usize,
    },
    TooManyOutputs {
        asset: AssetCode,
        max_records: usize,
        num_receivers: usize,
        num_change_records: usize,
    },
    UndefinedAsset {
        asset: AssetCode,
    },
    InvalidBlock {
        val_err: ValidationError,
    },
    NullifierAlreadyPublished {
        nullifier: Nullifier,
    },
    CryptoError {
        err: TxnApiError,
    },
    InvalidAddress {
        address: UserAddress,
    },
    InvalidAuditorKey {
        my_key: AuditorPubKey,
        asset_key: AuditorPubKey,
    },
    InvalidFreezerKey {
        my_key: FreezerPubKey,
        asset_key: FreezerPubKey,
    },
}

// Events consumed by the wallet produced by the backend (which potentially includes validators,
// query servers, bulletin boards, etc.). Eventually we may want the wallet to subscribe itself to
// these events transparently, but this part of the system is underspecified, so for now the wallet
// simply has a public method for receiving mocked versions of these events.
#[derive(Clone, Debug)]
pub enum LedgerEvent {
    Commit(ElaboratedBlock, Vec<Vec<ReceiverMemo>>),
    Reject(ElaboratedBlock, ValidationError),
}

pub struct WalletState<'a> {
    rng: ChaChaRng,
    // sequence number of the last event processed
    now: u64,
    // wallets run validation in tandem with the validators, so that they do not have to trust new
    // blocks received from the event stream
    validator: ValidatorState,
    // proving key set. The proving keys are ordered by number of outputs first and number of inputs
    // second, because the wallet is less flexible with respect to number of outputs. If we are
    // building a transaction and find we have too many inputs we can always generate a merge
    // transaction to defragment, but if the user requests a transaction with N independent outputs,
    // there is nothing we can do to decrease that number. So when searching for an appropriate
    // proving key, we will want to find a key with enough outputs first, and then worry about the
    // number of inputs.
    proving_keys: ProverKeySet<'a, key_set::OrderByOutputs>,
    // all records we care about, including records we own, records we have audited, and records we
    // can freeze or unfreeze
    records: RecordDatabase,
    // key pair for decrypting auditor memos
    auditor_key_pair: AuditorKeyPair,
    // asset definitions for which we are an auditor, indexed by code
    auditable_assets: HashMap<AssetCode, AssetDefinition>,
    // key pair for computing nullifiers of records owned by someone else but which we can freeze or
    // unfreeze
    freezer_key_pair: FreezerKeyPair,
    // sparse nullifier set Merkle tree mirrored from validators
    nullifiers: SetMerkleTree,
    // maps defined asset code to asset definition, seed and description of the asset
    defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
    // set of unconfirmed transactions, indexed by fee nullifier. We maintain the invariant that
    // every nullifier in this set corresponds to an on-hold record, which ensures that there is
    // never more than one transaction in flight with the same nullifier. Thus it is safe to use the
    // fee record nullifier (which is always present) as a unique identifier for transactions. This
    // is kind of a hack. It's standing in for what would be a better solution: a "user_data" field
    // on transaction notes, preserved across round trips to the validators, which we could use as a
    // unique ID.
    pending_txns: HashMap<Nullifier, PendingTransaction>,
    // the fee nullifiers of transactions expiring at each validator timestamp.
    expiring_txns: BTreeMap<u64, HashSet<Nullifier>>,
}

struct PendingTransaction {
    receiver_memos: Vec<ReceiverMemo>,
    signature: Signature,
    freeze_outputs: Vec<RecordOpening>,
    timeout: u64,
}

pub trait WalletBackend<'a> {
    type EventStream: 'a + Stream<Item = LedgerEvent> + Unpin + Send;
    fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError>;
    fn store(&mut self, key_pair: &UserKeyPair, state: &WalletState) -> Result<(), WalletError>;
    fn subscribe(&self, starting_at: u64) -> Self::EventStream;
    fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError>;

    // Submit a transaction to a validator.
    fn submit(
        &mut self,
        txn: ElaboratedTransaction,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
    ) -> Result<(), WalletError>;
}

pub struct WalletSession<'a, Backend: WalletBackend<'a>> {
    backend: Backend,
    key_pair: UserKeyPair,
    _marker: std::marker::PhantomData<&'a ()>,
}

struct RecordInfo {
    ro: RecordOpening,
    uid: u64,
    // if Some(t), this record is on hold until the validator timestamp surpasses `t`, because this
    // record has been used as an input to a transaction that is not yet confirmed.
    hold_until: Option<u64>,
}

impl RecordInfo {
    fn on_hold(&self, now: u64) -> bool {
        matches!(self.hold_until, Some(t) if t > now)
    }

    fn hold_until(&mut self, until: u64) {
        self.hold_until = Some(until);
    }

    fn unhold(&mut self) {
        self.hold_until = None;
    }
}

pub struct RecordDatabase {
    // all records in the database, by uid
    record_info: HashMap<u64, RecordInfo>,
    // record (size, uid) indexed by asset type, owner, and freeze status, for easy allocation as
    // transfer or freeze inputs. The records for each asset are ordered by increasing size, which
    // makes it easy to implement a worst-fit allocator that minimizes fragmentation.
    asset_records: HashMap<(AssetCode, UserPubKey, FreezeFlag), BTreeSet<(u64, u64)>>,
    // record uids indexed by nullifier, for easy removal when confirmed as transfer inputs
    nullifier_records: HashMap<Nullifier, u64>,
}

impl RecordDatabase {
    /// Find records which can be the input to a transaction, matching the given parameters.
    fn input_records<'a>(
        &'a self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        now: u64,
    ) -> impl Iterator<Item = &'a RecordInfo> {
        self.asset_records
            .get(&(*asset, owner.clone(), frozen))
            .into_iter()
            .flatten()
            .rev()
            .filter_map(move |(_, uid)| {
                let record = &self.record_info[uid];
                if record.ro.amount == 0 || record.on_hold(now) {
                    // Skip useless dummy records and records that are on hold
                    None
                } else {
                    Some(record)
                }
            })
    }
    /// Find a record with exactly the requested amount, which can be the input to a transaction,
    /// matching the given parameters.
    fn input_record_with_amount(
        &self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        amount: u64,
        now: u64,
    ) -> Option<&RecordInfo> {
        let unspent_records = self.asset_records.get(&(*asset, owner.clone(), frozen))?;
        let exact_matches = unspent_records.range((amount, 0)..(amount + 1, 0));
        for (match_amount, uid) in exact_matches {
            assert_eq!(*match_amount, amount);
            let record = &self.record_info[uid];
            assert_eq!(record.ro.amount, amount);
            if record.on_hold(now) {
                continue;
            }
            return Some(record);
        }

        None
    }

    fn record_with_nullifier_mut(&mut self, nullifier: &Nullifier) -> Option<&mut RecordInfo> {
        let uid = self.nullifier_records.get(nullifier)?;
        self.record_info.get_mut(uid)
    }

    fn insert(&mut self, ro: RecordOpening, uid: u64, key_pair: &UserKeyPair) {
        let nullifier = key_pair.nullify(
            ro.asset_def.policy_ref().freezer_pub_key(),
            uid,
            &RecordCommitment::from(&ro),
        );
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    fn insert_freezable(&mut self, ro: RecordOpening, uid: u64, key_pair: &FreezerKeyPair) {
        let nullifier = key_pair.nullify(&ro.pub_key, uid, &RecordCommitment::from(&ro));
        self.insert_with_nullifier(ro, uid, nullifier)
    }

    fn insert_with_nullifier(&mut self, ro: RecordOpening, uid: u64, nullifier: Nullifier) {
        self.asset_records
            .entry((ro.asset_def.code, ro.pub_key.clone(), ro.freeze_flag))
            .or_insert_with(BTreeSet::new)
            .insert((ro.amount, uid));
        self.nullifier_records.insert(nullifier, uid);
        self.record_info.insert(
            uid,
            RecordInfo {
                ro,
                uid,
                hold_until: None,
            },
        );
    }

    fn remove_by_nullifier(&mut self, nullifier: Nullifier) -> Option<RecordInfo> {
        self.nullifier_records.remove(&nullifier).map(|uid| {
            let record = self.record_info.remove(&uid).unwrap();
            self.asset_records
                .get_mut(&(
                    record.ro.asset_def.code,
                    record.ro.pub_key.clone(),
                    record.ro.freeze_flag,
                ))
                .unwrap()
                .remove(&(record.ro.amount, uid));
            record
        })
    }
}

impl Default for RecordDatabase {
    fn default() -> Self {
        Self {
            record_info: HashMap::new(),
            asset_records: HashMap::new(),
            nullifier_records: HashMap::new(),
        }
    }
}

// a never expired target
const UNEXPIRED_VALID_UNTIL: u64 = 2u64.pow(jf_txn::constants::MAX_TIMESTAMP_LEN as u32) - 1;
// how long (in number of validator states) a record used as an input to an unconfirmed transaction
// should be kept on hold before the transaction is considered timed out. This should be the number
// of validator states after which the transaction's proof can no longer be verified.
const RECORD_HOLD_TIME: u64 = ValidatorState::RECORD_ROOT_HISTORY_SIZE as u64;

impl<'a> WalletState<'a> {
    pub fn pub_key(&self, session: &WalletSession<'a, impl WalletBackend<'a>>) -> UserPubKey {
        session.key_pair.pub_key()
    }

    pub fn balance(
        &self,
        session: &WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetCode,
        frozen: FreezeFlag,
    ) -> u64 {
        self.records
            .input_records(
                asset,
                &self.pub_key(session),
                frozen,
                self.validator.prev_commit_time,
            )
            .map(|record| record.ro.amount)
            .sum()
    }

    pub fn handle_event(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        event: LedgerEvent,
    ) {
        self.now += 1;
        match event {
            LedgerEvent::Commit(block, receiver_memos) => {
                // Don't trust the network connection that provided us this event; validate it
                // against our local mirror of the ledger and bail out if it is invalid.
                let mut uids = match self.validator.validate_and_apply(
                    self.validator.prev_commit_time + 1,
                    block.block.clone(),
                    block.proofs.clone(),
                    true, // remember all commitments; we will forget the ones we don't need later
                ) {
                    Ok(uids) => {
                        // Get a list of new uids and whether we want to remember them in our record
                        // Merkle tree. Initially, set `remember` to false for all uids, to maximize
                        // sparseness. If any of the consumers of this block (for example, the
                        // auditor component, or the owner of this wallet) care about a uid, they
                        // will set its `remember` flag to true.
                        uids.into_iter().map(|uid| (uid, false)).collect::<Vec<_>>()
                    }
                    Err(val_err) => {
                        println!("received invalid block: {:?}, {:?}", block, val_err);
                        return;
                    }
                };
                // Some transactions may have just expired when we stepped the validator state.
                // Remove them from our pending transaction data structures.
                //
                // This maintains the invariant that everything in `pending_transactions` must
                // correspond to an on-hold record, because everything which corresponds to a record
                // whose hold just expired will be removed from the set now.
                self.clear_expired_transactions();

                for ((txn, proofs), receiver_memos) in block
                    .block
                    .0
                    .into_iter()
                    .zip(block.proofs)
                    .zip(receiver_memos)
                {
                    // Split the uids corresponding to this transaction off the front of `uids`.
                    let mut this_txn_uids = uids;
                    uids = this_txn_uids.split_off(txn.output_len());

                    assert_eq!(this_txn_uids.len(), txn.output_len());
                    let txn = ElaboratedTransaction { txn, proofs };

                    // Different concerns within the wallet consume transactions in different ways.
                    // Now we give each concern a chance to consume this transaction, performing any
                    // processing they need to do and possibly setting the `remember` flag for
                    // output records they care about.
                    //
                    // This is a transaction we submitted and have been
                    // awaiting confirmation.
                    self.clear_pending_transaction(&txn, Ok(&mut this_txn_uids));
                    // This is someone else's transaction but we can audit it.
                    self.audit_transaction(session, &txn, &mut this_txn_uids);
                    // This is someone else's transaction but we are a receiver of some of its
                    // outputs.
                    self.receive_transaction_outputs(
                        session,
                        &txn,
                        receiver_memos,
                        &mut this_txn_uids,
                    );

                    // Update spent nullifiers.
                    for nullifier in txn.txn.nullifiers().into_iter() {
                        self.nullifiers.insert(nullifier);
                        // TODO prune nullifiers that we don't need for our non-inclusion proofs

                        if let Some(record) = self.records.remove_by_nullifier(nullifier) {
                            self.record_merkle_tree_mut().forget(record.uid);
                        }
                    }

                    // Prune the record Merkle tree of records we don't care about.
                    for (uid, remember) in this_txn_uids {
                        if !remember {
                            self.record_merkle_tree_mut().forget(uid);
                        }
                    }
                }
            }

            LedgerEvent::Reject(block, err) => {
                for (txn, proofs) in block.block.0.into_iter().zip(block.proofs) {
                    let mut txn = ElaboratedTransaction { txn, proofs };
                    if let Some(pending) = self.clear_pending_transaction(&txn, Err(err.clone())) {
                        // Try to resubmit if the error is recoverable.
                        if let ValidationError::BadNullifierProof {} = err {
                            if self.update_nullifier_proofs(&mut txn).is_ok() {
                                println!("recoverable error in txn {:?}, resubmitting", txn);
                                if self
                                    .submit_elaborated_transaction(
                                        &mut session.backend,
                                        txn,
                                        pending.receiver_memos,
                                        pending.signature,
                                        pending.freeze_outputs,
                                    )
                                    .is_err()
                                {
                                    println!("failed to resubmit transaction");
                                }
                            }
                        }
                    }
                }
            }
        };
    }

    fn clear_pending_transaction(
        &mut self,
        txn: &ElaboratedTransaction,
        uids: Result<&mut [(u64, bool)], ValidationError>,
    ) -> Option<PendingTransaction> {
        let now = self.validator.prev_commit_time;

        // Remove the transaction from `pending_txns` and `expiring_txns`. This restores the
        // invariant that every pending nullifier corresponds to an on-hold record, since we just
        // cleared the hold for the inputs to this transaction.
        let txn_id = txn.txn.nullifiers()[0];
        let pending = self.pending_txns.remove(&txn_id);
        if let Some(pending) = &pending {
            if let Some(expiring) = self.expiring_txns.get_mut(&pending.timeout) {
                expiring.remove(&txn_id);
            }
        }

        for nullifier in txn.txn.nullifiers() {
            if let Some(record) = self.records.record_with_nullifier_mut(&nullifier) {
                if pending.is_some() {
                    // If we started this transaction, all of its inputs should have been on hold,
                    // to preserve the invariant that all input nullifiers of all pending
                    // transactions are on hold.
                    assert!(record.on_hold(now));

                    if uids.is_err() {
                        // If the transaction was not accepted for any reason, its nullifiers have
                        // not been spent, so remove the hold we placed on them.
                        record.unhold();
                    }
                } else {
                    // This isn't even our transaction.
                    assert!(!record.on_hold(now));
                }
            }
        }

        // If this was a successful freeze transaction, add all of its frozen/unfrozen outputs to
        // our freezable database.
        if let Ok(uids) = uids {
            if let Some(pending) = &pending {
                // the first uid corresponds to the fee change output, which is not one of the
                // `freeze_outputs`, so we skip that one
                for ((uid, remember), ro) in uids.iter_mut().skip(1).zip(&pending.freeze_outputs) {
                    self.records
                        .insert_freezable(ro.clone(), *uid, &self.freezer_key_pair);
                    *remember = true;
                }
            }
        }

        pending
    }

    fn clear_expired_transactions(&mut self) {
        let now = self.validator.prev_commit_time;

        #[cfg(any(test, debug_assertions))]
        {
            if let Some(earliest_timeout) = self.expiring_txns.keys().next() {
                // Transactions expiring before now should already have been removed from the
                // expiring_txns set, because we clear expired transactions every time we step the
                // validator state.
                assert!(*earliest_timeout >= now);
            }
        }

        for nullifier in self.expiring_txns.remove(&now).into_iter().flatten() {
            // Transactions expiring now should only contain records that are held until now.
            assert!(
                self.records
                    .record_with_nullifier_mut(&nullifier)
                    .unwrap()
                    .hold_until
                    == Some(now)
            );
            self.pending_txns.remove(&nullifier);
        }
    }

    fn audit_transaction(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &ElaboratedTransaction,
        uids: &mut [(u64, bool)],
    ) {
        // Try to decrypt auditor memos.
        let mut audit_data = None;
        match &txn.txn {
            TransactionNote::Transfer(xfr) => {
                for asset in self.auditable_assets.values() {
                    audit_data = self
                        .auditor_key_pair
                        .open_transfer_audit_memo(asset, xfr)
                        .ok();
                    if audit_data.is_some() {
                        break;
                    }
                }
            }
            TransactionNote::Mint(mint) => {
                audit_data = self
                    .auditor_key_pair
                    .open_mint_audit_memo(mint)
                    .ok()
                    .map(|audit_output| (vec![], vec![audit_output]));
            }
            TransactionNote::Freeze(_) => {}
        }
        if let Some((_, audit_outputs)) = audit_data {
            //todo !jeb.bearer eventually, we will probably want to save all the audit memos for
            // the whole transaction (inputs and outputs) regardless of whether any of the outputs
            // are freezeable, just for general auditing purposes.

            // the first uid corresponds to the fee change output, which has no audit memo, so skip
            // that one
            for ((uid, remember), output) in uids.iter_mut().skip(1).zip(audit_outputs) {
                if let (Some(asset_def), Some(pub_key), Some(amount), Some(blind)) = (
                    self.auditable_assets.get(&output.asset_code),
                    output
                        .user_address
                        .and_then(|address| session.backend.get_public_key(&address).ok()),
                    output.amount,
                    output.blinding_factor,
                ) {
                    // If the audit memo contains all the information we need to potentially freeze
                    // this record, save it in our database for later freezing.
                    if *asset_def.policy_ref().freezer_pub_key() == self.freezer_key_pair.pub_key()
                    {
                        let record_opening = RecordOpening {
                            amount,
                            asset_def: asset_def.clone(),
                            pub_key,
                            freeze_flag: FreezeFlag::Unfrozen,
                            blind,
                        };
                        self.records
                            .insert_freezable(record_opening, *uid, &self.freezer_key_pair);
                        *remember = true;
                    }
                }
            }
        }
    }

    fn receive_transaction_outputs(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        txn: &ElaboratedTransaction,
        receiver_memos: Vec<ReceiverMemo>,
        uids: &mut [(u64, bool)],
    ) {
        let output_commitments = match &txn.txn {
            TransactionNote::Transfer(xfr) => xfr.output_commitments.clone(),
            TransactionNote::Mint(mint) => vec![mint.chg_comm, mint.mint_comm],
            TransactionNote::Freeze(freeze) => freeze.output_commitments.clone(),
        };
        assert_eq!(output_commitments.len(), receiver_memos.len());
        assert_eq!(output_commitments.len(), uids.len());
        for (((uid, remember), record_commitment), memo) in
            uids.iter_mut().zip(output_commitments).zip(receiver_memos)
        {
            if let Ok(record_opening) = memo.decrypt(&session.key_pair, &record_commitment, &[]) {
                // If this record is for us (i.e. its corresponding memo decrypts under our
                // key), then add it to our owned records.
                self.records.insert(record_opening, *uid, &session.key_pair);
                *remember = true;
            }
        }
    }

    fn update_nullifier_proofs(&self, txn: &mut ElaboratedTransaction) -> Result<(), WalletError> {
        txn.proofs = txn
            .txn
            .nullifiers()
            .iter()
            .map(|n| {
                let (contains, proof) = self.nullifiers.contains(*n).unwrap();
                if contains {
                    Err(WalletError::NullifierAlreadyPublished { nullifier: *n })
                } else {
                    Ok(proof)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    pub fn define_asset(
        &mut self,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let seed = AssetCodeSeed::generate(&mut self.rng);
        let code = AssetCode::new(seed, description);
        let asset_definition =
            AssetDefinition::new(code, policy).map_err(|err| WalletError::CryptoError { err })?;
        self.defined_assets
            .insert(code, (asset_definition.clone(), seed, description.to_vec()));
        // If the policy lists ourself as the auditor, automatically start auditing transactions
        // involving this asset.
        if *asset_definition.policy_ref().auditor_pub_key() == self.auditor_key_pair.pub_key() {
            self.auditable_assets
                .insert(asset_definition.code, asset_definition.clone());
        }
        Ok(asset_definition)
    }

    /// Use `audit_asset` to start auditing transactions with a given asset type, when the asset
    /// type was defined by someone else and sent to us out of band.
    ///
    /// Auditing of assets created by this user with an appropriate asset policy begins
    /// automatically. Calling this function is unnecessary.
    pub fn audit_asset(&mut self, asset: &AssetDefinition) -> Result<(), WalletError> {
        let my_key = self.auditor_key_pair.pub_key();
        let asset_key = asset.policy_ref().auditor_pub_key();
        if my_key != *asset_key {
            return Err(WalletError::InvalidAuditorKey {
                my_key,
                asset_key: asset_key.clone(),
            });
        }

        self.auditable_assets.insert(asset.code, asset.clone());
        Ok(())
    }

    pub fn transfer(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetDefinition,
        receivers: &[(UserAddress, u64)],
        fee: u64,
    ) -> Result<(), WalletError> {
        let receivers = receivers
            .iter()
            .map(|(addr, amt)| Ok((session.backend.get_public_key(addr)?, *amt)))
            .collect::<Result<Vec<_>, _>>()?;
        if *asset == AssetDefinition::native() {
            self.transfer_native(session, &receivers, fee)
        } else {
            self.transfer_non_native(session, asset, &receivers, fee)
        }
    }

    pub fn mint(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        let (fee_ro, uid) = self.find_native_record_for_fee(session, fee)?;
        let acc_member_witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
            .expect_ok()
            .unwrap()
            .1;
        let (asset_def, seed, asset_description) = self
            .defined_assets
            .get(asset_code)
            .ok_or(WalletError::UndefinedAsset { asset: *asset_code })?;
        let mint_record = RecordOpening {
            amount,
            asset_def: asset_def.clone(),
            pub_key: session.backend.get_public_key(&owner)?,
            freeze_flag: FreezeFlag::Unfrozen,
            blind: BlindFactor::rand(&mut self.rng),
        };

        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness,
            owner_keypair: &session.key_pair,
        };
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let rng = &mut self.rng;
        let recv_memos = vec![&fee_out_rec, &mint_record]
            .into_iter()
            .map(|r| ReceiverMemo::from_ro(rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (mint_note, sig_key) = jf_txn::mint::MintNote::generate(
            &mut self.rng,
            mint_record,
            *seed,
            asset_description.as_slice(),
            fee_info,
            &self.proving_keys.mint,
        )
        .map_err(|err| WalletError::CryptoError { err })?;
        let signature = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            &mut session.backend,
            TransactionNote::Mint(Box::new(mint_note)),
            recv_memos,
            signature,
            vec![],
        )
    }

    /// Freeze at least `amount` of a particular asset owned by a given user.
    ///
    /// In order to freeze an asset, this wallet must be an auditor of that asset type, and it must
    /// have observed enough transactions to determine that the target user owns at least `amount`
    /// of that asset.
    ///
    /// Freeze transactions do not currently support change, so the amount frozen will be at least
    /// `amount` but might be more, depending on the distribution of the freezable records we have
    /// for the target user.
    ///
    /// Some of these restrictions can be rolled back in the future:
    /// * An API can be provided for freezing without being an auditor, if a freezable record
    ///   opening is provided to us out of band by an auditor.
    /// * `freeze` uses the same allocation scheme for input records as transfers, which tries to
    ///   minimize fragmentation. But freeze transactions do not increase fragmentation because they
    ///   have no change output, so we could use a different allocation scheme that tries to
    ///   minimize change, which would limit the amount we can over-freeze, and would guarantee that
    ///   we freeze the exact amount if it is possible to make exact change with the freezable
    ///   records we have.
    pub fn freeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Frozen)
    }

    /// Unfreeze at least `amount` of a particular asset owned by a given user.
    ///
    /// This wallet must have previously been used to freeze (without an intervening `unfreeze`) at
    /// least `amount` of the given asset for the given user.
    ///
    /// Similar restrictions on change apply as for `freeze`.
    pub fn unfreeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        self.freeze_or_unfreeze(session, fee, asset, amount, owner, FreezeFlag::Unfrozen)
    }

    fn freeze_or_unfreeze(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
        outputs_frozen: FreezeFlag,
    ) -> Result<(), WalletError> {
        let my_key = self.freezer_key_pair.pub_key();
        let asset_key = asset.policy_ref().freezer_pub_key();
        if my_key != *asset_key {
            return Err(WalletError::InvalidFreezerKey {
                my_key,
                asset_key: asset_key.clone(),
            });
        }

        let owner = session.backend.get_public_key(&owner)?;

        // find input records of the asset type to freeze (this does not include the fee input)
        let inputs_frozen = match outputs_frozen {
            FreezeFlag::Frozen => FreezeFlag::Unfrozen,
            FreezeFlag::Unfrozen => FreezeFlag::Frozen,
        };
        let (input_records, _) =
            self.find_records(&asset.code, &owner, inputs_frozen, amount, None)?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records.into_iter() {
            let witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                .expect_ok()
                .unwrap()
                .1;
            inputs.push(FreezeNoteInput {
                ro,
                acc_member_witness: witness,
                keypair: &self.freezer_key_pair,
            })
        }

        let (fee_ro, fee_uid) = self.find_native_record_for_fee(session, fee)?;
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness: AccMemberWitness::lookup_from_tree(
                self.record_merkle_tree(),
                fee_uid,
            )
            .expect_ok()
            .unwrap()
            .1,
            owner_keypair: &session.key_pair,
        };

        // find a proving key which can handle this transaction size
        let proving_key = Self::freeze_proving_key(&self.proving_keys.freeze, asset, &mut inputs)?;

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let (note, sig_key, outputs) =
            FreezeNote::generate(&mut self.rng, inputs, fee_info, proving_key)
                .map_err(|err| WalletError::CryptoError { err })?;
        let recv_memos = vec![&fee_out_rec]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            &mut session.backend,
            TransactionNote::Freeze(Box::new(note)),
            recv_memos,
            sig,
            outputs,
        )
    }

    fn transfer_native(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        receivers: &[(UserPubKey, u64)],
        fee: u64,
    ) -> Result<(), WalletError> {
        let total_output_amount: u64 =
            receivers.iter().fold(0, |sum, (_, amount)| sum + *amount) + fee;

        // find input records which account for at least the total amount, and possibly some change.
        let (input_records, _change) = self.find_records(
            &AssetCode::native(),
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records {
            let acc_member_witness =
                AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                    .expect_ok()
                    .unwrap()
                    .1;
            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness,
                owner_keypair: &session.key_pair,
                cred: None,
            });
        }

        // prepare outputs, excluding fee change (which will be automatically generated)
        let mut outputs = vec![];
        for (pub_key, amount) in receivers {
            outputs.push(RecordOpening::new(
                &mut self.rng,
                *amount,
                AssetDefinition::native(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }

        // find a proving key which can handle this transaction size
        let me = self.pub_key(session);
        let proving_key = Self::xfr_proving_key(
            &mut self.rng,
            me,
            &self.proving_keys.xfr,
            &AssetDefinition::native(),
            &mut inputs,
            &mut outputs,
            false,
        )?;

        // generate transfer note and receiver memos
        let (note, kp, fee_change_ro) = TransferNote::generate_native(
            &mut self.rng,
            inputs,
            &outputs,
            1,
            UNEXPIRED_VALID_UNTIL,
            proving_key,
        )
        .map_err(|err| WalletError::CryptoError { err })?;

        let outputs: Vec<_> = vec![fee_change_ro]
            .into_iter()
            .chain(outputs.into_iter())
            .collect();

        let recv_memos: Vec<_> = outputs
            .iter()
            .map(|ro| ReceiverMemo::from_ro(&mut self.rng, ro, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&kp, &recv_memos)
            .map_err(|err| WalletError::CryptoError { err })?;
        self.submit_transaction(
            &mut session.backend,
            TransactionNote::Transfer(Box::new(note)),
            recv_memos,
            sig,
            vec![],
        )
    }

    fn transfer_non_native(
        &mut self,
        session: &mut WalletSession<'a, impl WalletBackend<'a>>,
        asset: &AssetDefinition,
        receivers: &[(UserPubKey, u64)],
        fee: u64,
    ) -> Result<(), WalletError> {
        assert_ne!(
            *asset,
            AssetDefinition::native(),
            "call `transfer_native()` instead"
        );
        let total_output_amount: u64 = receivers.iter().fold(0, |sum, (_, amount)| sum + *amount);

        // find input records of the asset type to spend (this does not include the fee input)
        let (input_records, change) = self.find_records(
            &asset.code,
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            total_output_amount,
            None,
        )?;

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records.into_iter() {
            let witness = AccMemberWitness::lookup_from_tree(self.record_merkle_tree(), uid)
                .expect_ok()
                .unwrap()
                .1;
            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness: witness,
                owner_keypair: &session.key_pair,
                cred: None, // TODO support credentials
            })
        }

        // prepare outputs, excluding fee change (which will be automatically generated)
        let me = self.pub_key(session);
        let mut outputs = vec![];
        for (pub_key, amount) in receivers {
            outputs.push(RecordOpening::new(
                &mut self.rng,
                *amount,
                asset.clone(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }
        // change in the asset type being transfered (not fee change)
        if change > 0 {
            let change_ro = RecordOpening::new(
                &mut self.rng,
                change,
                asset.clone(),
                me.clone(),
                FreezeFlag::Unfrozen,
            );
            outputs.push(change_ro);
        }

        let (fee_ro, fee_uid) = self.find_native_record_for_fee(session, fee)?;
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness: AccMemberWitness::lookup_from_tree(
                self.record_merkle_tree(),
                fee_uid,
            )
            .expect_ok()
            .unwrap()
            .1,
            owner_keypair: &session.key_pair,
        };

        // find a proving key which can handle this transaction size
        let proving_key = Self::xfr_proving_key(
            &mut self.rng,
            me,
            &self.proving_keys.xfr,
            asset,
            &mut inputs,
            &mut outputs,
            change > 0,
        )?;

        // generate transfer note and receiver memos
        let (fee_info, fee_out_rec) = TxnFeeInfo::new(&mut self.rng, fee_input, fee).unwrap();
        let (note, sig_key) = TransferNote::generate_non_native(
            &mut self.rng,
            inputs,
            &outputs,
            fee_info,
            UNEXPIRED_VALID_UNTIL,
            proving_key,
        )
        .map_err(|err| WalletError::CryptoError { err })?;
        let recv_memos = vec![&fee_out_rec]
            .into_iter()
            .chain(outputs.iter())
            .map(|r| ReceiverMemo::from_ro(&mut self.rng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sig = sign_receiver_memos(&sig_key, &recv_memos).unwrap();
        self.submit_transaction(
            &mut session.backend,
            TransactionNote::Transfer(Box::new(note)),
            recv_memos,
            sig,
            vec![],
        )
    }

    fn submit_transaction(
        &mut self,
        backend: &mut impl WalletBackend<'a>,
        note: TransactionNote,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
    ) -> Result<(), WalletError> {
        let nullifier_pfs = note
            .nullifiers()
            .iter()
            .map(|n| self.nullifiers.contains(*n).unwrap().1)
            .collect();
        let txn = ElaboratedTransaction {
            txn: note,
            proofs: nullifier_pfs,
        };

        self.submit_elaborated_transaction(backend, txn, memos, sig, freeze_outputs)
    }

    fn submit_elaborated_transaction(
        &mut self,
        backend: &mut impl WalletBackend<'a>,
        txn: ElaboratedTransaction,
        memos: Vec<ReceiverMemo>,
        sig: Signature,
        freeze_outputs: Vec<RecordOpening>,
    ) -> Result<(), WalletError> {
        self.add_pending_transaction(&txn, memos.clone(), sig.clone(), freeze_outputs);
        backend.submit(txn, memos, sig)
    }

    fn add_pending_transaction(
        &mut self,
        txn: &ElaboratedTransaction,
        receiver_memos: Vec<ReceiverMemo>,
        signature: Signature,
        freeze_outputs: Vec<RecordOpening>,
    ) {
        let now = self.validator.prev_commit_time;
        let timeout = now + RECORD_HOLD_TIME;

        for nullifier in txn.txn.nullifiers() {
            // hold the record corresponding to this nullifier until the transaction is committed,
            // rejected, or expired.
            let record = self.records.record_with_nullifier_mut(&nullifier).unwrap();
            assert!(!record.on_hold(now));
            record.hold_until(timeout);
        }

        // Add the fee nullifier to `pending_txns` and `expiring_txns`. We know it corresponds to an
        // on-hold record since we just placed all the inputs to this transaction on hold. As soon
        // as the hold expires, `handle_event` will remove the fee nullifier from these data
        // structures by calling `clear_expired_transactions`.
        let nullifier = txn.txn.nullifiers()[0];
        let pending = PendingTransaction {
            receiver_memos,
            signature,
            timeout,
            freeze_outputs,
        };
        self.pending_txns.insert(nullifier, pending);
        self.expiring_txns
            .entry(timeout)
            .or_default()
            .insert(nullifier);
    }

    #[allow(clippy::type_complexity)]
    fn find_records(
        &self,
        asset: &AssetCode,
        owner: &UserPubKey,
        frozen: FreezeFlag,
        amount: u64,
        max_records: Option<usize>,
    ) -> Result<(Vec<(RecordOpening, u64)>, u64), WalletError> {
        let now = self.validator.prev_commit_time;

        // If we have a record with the exact size required, use it to avoid fragmenting big records
        // into smaller change records.
        if let Some(record) = self
            .records
            .input_record_with_amount(asset, owner, frozen, amount, now)
        {
            return Ok((vec![(record.ro.clone(), record.uid)], 0));
        }

        // Take the biggest records we have until they exceed the required amount, as a heuristic to
        // try and get the biggest possible change record. This is a simple algorithm that
        // guarantees we will always return the minimum number of blocks, and thus we always succeed
        // in making a transaction if it is possible to do so within the allowed number of inputs.
        //
        // This algorithm is not optimal, though. For instance, it's possible we might be able to
        // make exact change using combinations of larger and smaller blocks. We can replace this
        // with something more sophisticated later.
        let mut result = vec![];
        let mut current_amount = 0u64;
        for record in self.records.input_records(asset, owner, frozen, now) {
            if let Some(max_records) = max_records {
                if result.len() >= max_records {
                    // Too much fragmentation: we can't make the required amount using few enough
                    // records. This should be less likely once we implement a better allocation
                    // strategy (or, any allocation strategy).
                    //
                    // In this case, we could either simply return an error, or we could
                    // automatically generate a merge transaction to defragment our assets.
                    // Automatically merging assets would implicitly incur extra transaction fees,
                    // so for now we do the simple, uncontroversial thing and error out.
                    return Err(WalletError::Fragmentation {
                        asset: *asset,
                        amount,
                        suggested_amount: current_amount,
                        max_records,
                    });
                }
            }
            current_amount += record.ro.amount;
            result.push((record.ro.clone(), record.uid));
            if current_amount >= amount {
                return Ok((result, current_amount - amount));
            }
        }

        Err(WalletError::InsufficientBalance {
            asset: *asset,
            required: amount,
            actual: current_amount,
        })
    }

    /// find a record and corresponding uid on the native asset type with enough
    /// funds to pay transaction fee
    fn find_native_record_for_fee(
        &self,
        session: &WalletSession<'a, impl WalletBackend<'a>>,
        fee: u64,
    ) -> Result<(RecordOpening, u64), WalletError> {
        self.find_records(
            &AssetCode::native(),
            &self.pub_key(session),
            FreezeFlag::Unfrozen,
            fee,
            Some(1),
        )
        .map(|(ros, _change)| ros.into_iter().next().unwrap())
    }

    // Find a proving key large enough to prove the given transaction, padding with dummy records if
    // necessary.
    //
    // `proving_keys` should always be `&self.proving_key`. This is a non-member function in order
    // to prove to the compiler that the result only borrows from `&self.proving_key`, not all of
    // `&self`.
    fn xfr_proving_key<'k>(
        rng: &mut ChaChaRng,
        me: UserPubKey,
        proving_keys: &'k KeySet<TransferProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<TransferNoteInput>,
        outputs: &mut Vec<RecordOpening>,
        change_record: bool,
    ) -> Result<&'k TransferProvingKey<'a>, WalletError> {
        let total_output_amount = outputs.iter().map(|ro| ro.amount).sum();
        // non-native transfers have an extra fee input, which is not included in `inputs`.
        let fee_inputs = if *asset == AssetDefinition::native() {
            0
        } else {
            1
        };
        // both native and non-native transfers have an extra fee change output which is
        // automatically generated and not included in `outputs`.
        let fee_outputs = 1;

        let num_inputs = inputs.len() + fee_inputs;
        let num_outputs = outputs.len() + fee_outputs;
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, max_outputs)| {
                if max_outputs >= num_outputs {
                    // If there is a key that can fit the correct number of outputs had we only
                    // managed to find fewer inputs, call this a fragmentation error.
                    WalletError::Fragmentation {
                        asset: asset.code,
                        amount: total_output_amount,
                        suggested_amount: inputs
                            .iter()
                            .take(max_inputs - fee_inputs)
                            .map(|input| input.ro.amount)
                            .sum(),
                        max_records: max_inputs,
                    }
                } else {
                    // Otherwise, we just have too many outputs for any of our available keys. There
                    // is nothing we can do about that on the wallet side.
                    WalletError::TooManyOutputs {
                        asset: asset.code,
                        max_records: max_outputs,
                        num_receivers: outputs.len() - change_record as usize,
                        num_change_records: 1 + change_record as usize,
                    }
                }
            })?;
        assert!(num_inputs <= key_inputs);
        assert!(num_outputs <= key_outputs);

        if num_inputs < key_inputs {
            // TODO pad with dummy inputs, (leaving room for the fee input if applicable)
            unimplemented!("dummy inputs");
        }
        if num_outputs < key_outputs {
            // pad with dummy (0-amount) outputs (leaving room for the fee change output if
            // applicable)
            while {
                outputs.push(RecordOpening::new(
                    rng,
                    0,
                    asset.clone(),
                    me.clone(),
                    FreezeFlag::Unfrozen,
                ));
                outputs.len() < key_outputs - 1
            } {}
        }

        Ok(proving_key)
    }

    fn freeze_proving_key<'k>(
        proving_keys: &'k KeySet<FreezeProvingKey<'a>, key_set::OrderByOutputs>,
        asset: &AssetDefinition,
        inputs: &mut Vec<FreezeNoteInput>,
    ) -> Result<&'k FreezeProvingKey<'a>, WalletError> {
        let total_output_amount = inputs.iter().map(|input| input.ro.amount).sum();

        let num_inputs = inputs.len() + 1; // make sure to include fee input
        let num_outputs = num_inputs; // freeze transactions always have equal outputs and inputs
        let (key_inputs, key_outputs, proving_key) = proving_keys
            .best_fit_key(num_inputs, num_outputs)
            .map_err(|(max_inputs, _)| {
                WalletError::Fragmentation {
                    asset: asset.code,
                    amount: total_output_amount,
                    suggested_amount: inputs
                        .iter()
                        .take(max_inputs - 1) // leave room for fee input
                        .map(|input| input.ro.amount)
                        .sum(),
                    max_records: max_inputs,
                }
            })?;
        assert!(num_inputs <= key_inputs);
        assert!(num_outputs <= key_outputs);

        if num_inputs < key_inputs {
            // TODO pad with dummy inputs, (leaving room for the fee input if applicable)
            unimplemented!("dummy inputs");
        }

        Ok(proving_key)
    }

    fn record_merkle_tree(&self) -> &MerkleTree<RecordCommitment> {
        &self.validator.record_merkle_frontier
    }

    fn record_merkle_tree_mut(&mut self) -> &mut MerkleTree<RecordCommitment> {
        &mut self.validator.record_merkle_frontier
    }
}

type SyncHandles = HashMap<u64, Vec<oneshot::Sender<()>>>;
/// Note: it is a soundness requirement that the destructor of a `Wallet` run when the `Wallet` is
/// dropped. Therefore, `std::mem::forget` must not be used to forget a `Wallet` without running its
/// destructor.
pub struct Wallet<'a, Backend: WalletBackend<'a>> {
    // Data shared between the main thread and the event handling thread:
    //  * the trusted, persistent wallet state
    //  * the trusted, ephemeral wallet session
    //  * promise completion handles for futures returned by sync(), indexed by the timestamp at
    //    which the corresponding future is supposed to complete. Handles are added in sync() (main
    //    thread) and removed and completed in the event thread
    mutex: Arc<Mutex<(WalletState<'a>, WalletSession<'a, Backend>, SyncHandles)>>,
    // Handle for the task running the event handling loop. When dropped, this handle will cancel
    // the task, so this field is never read, it exists solely to live as long as this struct and
    // then be dropped.
    _event_task: AsyncScope<'a, ()>,
}

impl<'a, Backend: 'a + WalletBackend<'a> + Send> Wallet<'a, Backend> {
    pub fn new(key_pair: UserKeyPair, backend: Backend) -> Result<Self, WalletError> {
        let state = backend.load(&key_pair)?;
        let mut events = backend.subscribe(state.now);
        let session = WalletSession {
            key_pair,
            backend,
            _marker: Default::default(),
        };
        let sync_handles: SyncHandles = HashMap::new();
        let mutex = Arc::new(Mutex::new((state, session, sync_handles)));

        // Start the event loop.
        let event_task = {
            let mutex = mutex.clone();
            let mut scope = unsafe {
                // Creating an AsyncScope is considered unsafe because `std::mem::forget` is allowed
                // in safe code, and forgetting an AsyncScope can allow its inner futures to
                // continue to be scheduled to run after the lifetime of the scope ends, since
                // normally the destructor of the scope ensures that its futures are driven to
                // completion before its lifetime ends.
                //
                // Since we are immediately going to store `scope` in the resulting `Wallet`, its
                // lifetime will be the same as the `Wallet`, and its destructor will run as long as
                // no one calls `forget` on the `Wallet` -- which no one should ever have any reason
                // to.
                AsyncScope::create()
            };
            scope.spawn_cancellable(
                async move {
                    while let Some(event) = events.next().await {
                        let (state, session, sync_handles) = &mut *mutex.lock().unwrap();
                        // handle an event
                        state.handle_event(session, event);
                        // signal any sync() futures which should complete after the last event
                        if let Some(handles) = sync_handles.remove(&state.now) {
                            for handle in handles {
                                if handle.send(()).is_err() {
                                    // Errors mean the receiving end has dropped their promise before we
                                    // could signal it. This signal is a fire-and-forget operation; we
                                    // don't care if the receiver is listening or not, so just ignore
                                    // this error.
                                }
                            }
                        }
                    }
                },
                || (),
            );
            scope
        };

        Ok(Self {
            mutex,
            _event_task: event_task,
        })
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, (WalletState<'a>, WalletSession<'a, Backend>, SyncHandles)> {
        // It's acceptable to `unwrap()` here, because the only way the mutex can be poisoned is if
        // another method in this class paniced while holding the lock. Therefore, if this function
        // panics, the solution is always to go fix that other panic.
        self.mutex.lock().unwrap()
    }

    pub fn pub_key(&self) -> UserPubKey {
        let (state, session, ..) = &*self.lock();
        state.pub_key(session)
    }

    pub fn auditor_pub_key(&self) -> AuditorPubKey {
        let (state, ..) = &*self.lock();
        state.auditor_key_pair.pub_key()
    }

    pub fn freezer_pub_key(&self) -> FreezerPubKey {
        let (state, ..) = &*self.lock();
        state.freezer_key_pair.pub_key()
    }

    pub fn address(&self) -> UserAddress {
        self.pub_key().address()
    }

    pub fn balance(&self, asset: &AssetCode) -> u64 {
        let (state, session, ..) = &*self.lock();
        state.balance(session, asset, FreezeFlag::Unfrozen)
    }

    pub fn frozen_balance(&self, asset: &AssetCode) -> u64 {
        let (state, session, ..) = &*self.lock();
        state.balance(session, asset, FreezeFlag::Frozen)
    }

    pub fn transfer(
        &mut self,
        asset: &AssetDefinition,
        receivers: &[(UserAddress, u64)],
        fee: u64,
    ) -> Result<(), WalletError> {
        let (state, session, ..) = &mut *self.lock();
        state.transfer(session, asset, receivers, fee)
    }

    /// define a new asset and store secret info for minting
    pub fn define_asset(
        &mut self,
        description: &[u8],
        policy: AssetPolicy,
    ) -> Result<AssetDefinition, WalletError> {
        let (state, ..) = &mut *self.lock();
        state.define_asset(description, policy)
    }

    /// create a mint note that assign asset to an owner
    pub fn mint(
        &mut self,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        let (state, session, ..) = &mut *self.lock();
        state.mint(session, fee, asset_code, amount, owner)
    }

    pub fn freeze(
        &mut self,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        let (state, session, ..) = &mut *self.lock();
        state.freeze(session, fee, asset, amount, owner)
    }

    pub fn unfreeze(
        &mut self,
        fee: u64,
        asset: &AssetDefinition,
        amount: u64,
        owner: UserAddress,
    ) -> Result<(), WalletError> {
        let (state, session, ..) = &mut *self.lock();
        state.unfreeze(session, fee, asset, amount, owner)
    }

    pub async fn sync(&self, t: u64) -> Result<(), oneshot::Canceled> {
        let mut guard = self.lock();
        let (state, _, sync_handles) = &mut *guard;

        if state.now < t {
            let (sender, receiver) = oneshot::channel();
            sync_handles.entry(t).or_insert_with(Vec::new).push(sender);
            drop(guard);
            receiver.await
        } else {
            Ok(())
        }
    }
}

#[cfg(any(test, fuzzing))]
pub mod test_helpers {
    use super::*;
    use futures::channel::mpsc as channel;
    use futures::future;

    pub struct MockLedger<'a> {
        pub now: u64,
        pub validator: ValidatorState,
        nullifiers: SetMerkleTree,
        subscribers: Vec<channel::UnboundedSender<LedgerEvent>>,
        current_block: ElaboratedBlock,
        current_memos: Vec<Vec<ReceiverMemo>>,
        block_size: usize,
        hold_next_transaction: bool,
        held_transaction: Option<(ElaboratedTransaction, Vec<ReceiverMemo>, Signature)>,
        proving_keys: ProverKeySet<'a, key_set::OrderByOutputs>,
        address_map: HashMap<UserAddress, UserPubKey>,
    }

    impl<'a> MockLedger<'a> {
        fn generate_event(&mut self, e: LedgerEvent) {
            self.now += 1;
            for s in self.subscribers.iter_mut() {
                s.start_send(e.clone()).unwrap();
            }
        }

        fn flush(&mut self) {
            let block = std::mem::replace(
                &mut self.current_block,
                ElaboratedBlock::next_block(&self.validator),
            );
            let memos = std::mem::take(&mut self.current_memos);
            match self.validator.validate_and_apply(
                self.now,
                block.block.clone(),
                block.proofs.clone(),
                false,
            ) {
                Ok(_) => self.generate_event(LedgerEvent::Commit(block, memos)),
                Err(err) => self.generate_event(LedgerEvent::Reject(block, err)),
            }
        }

        pub fn hold_next_transaction(&mut self) {
            self.hold_next_transaction = true;
        }

        pub fn release_held_transaction(
            &mut self,
        ) -> Option<(ElaboratedTransaction, Vec<ReceiverMemo>, Signature)> {
            if let Some((txn, memos, sig)) = self.held_transaction.take() {
                self.submit(txn.clone(), memos.clone(), sig.clone());
                Some((txn, memos, sig))
            } else {
                None
            }
        }

        pub fn submit(
            &mut self,
            txn: ElaboratedTransaction,
            memos: Vec<ReceiverMemo>,
            sig: Signature,
        ) {
            if self.hold_next_transaction {
                self.held_transaction = Some((txn, memos, sig));
                self.hold_next_transaction = false;
                return;
            }

            if let Err(err) = txn.txn.verify_receiver_memos_signature(&memos, &sig) {
                let rejected = ElaboratedBlock {
                    block: Block(vec![txn.txn]),
                    proofs: vec![txn.proofs],
                };
                self.generate_event(LedgerEvent::Reject(
                    rejected,
                    ValidationError::CryptoError { err },
                ));
                return;
            }

            match self.current_block.add_transaction(&self.validator, &txn) {
                Ok(block) => {
                    self.current_block = block;
                    self.current_memos.push(memos);
                    if self.current_block.block.0.len() >= self.block_size {
                        self.flush();
                    }
                }
                Err(err) => {
                    let rejected = ElaboratedBlock {
                        block: Block(vec![txn.txn]),
                        proofs: vec![txn.proofs],
                    };
                    self.generate_event(LedgerEvent::Reject(rejected, err));
                }
            }
        }
    }

    pub async fn sync<'a>(
        ledger: &Arc<Mutex<MockLedger<'a>>>,
        wallets: &[Wallet<'a, impl 'a + WalletBackend<'a> + Send>],
    ) {
        let now = ledger.lock().unwrap().now;
        sync_with(wallets, now).await;
    }

    pub async fn sync_with<'a>(wallets: &[Wallet<'a, impl 'a + WalletBackend<'a> + Send>], t: u64) {
        println!("waiting for sync point {}", t);
        future::join_all(wallets.iter().map(|wallet| wallet.sync(t))).await;
    }

    #[derive(Clone)]
    pub struct MockWalletBackend<'a> {
        ledger: Arc<Mutex<MockLedger<'a>>>,
        initial_grants: Vec<(RecordOpening, u64)>,
        seed: [u8; 32],
    }

    impl<'a> WalletBackend<'a> for MockWalletBackend<'a> {
        type EventStream = channel::UnboundedReceiver<LedgerEvent>;

        fn load(&self, key_pair: &UserKeyPair) -> Result<WalletState<'a>, WalletError> {
            let ledger = self.ledger.lock().unwrap();
            assert_eq!(
                ledger.now, 0,
                "MockWalletBackend does not support restartability"
            );
            let mut rng = ChaChaRng::from_seed(self.seed);
            Ok(WalletState {
                validator: ledger.validator.clone(),
                proving_keys: ledger.proving_keys.clone(),
                records: {
                    let mut db: RecordDatabase = Default::default();
                    for (ro, uid) in self.initial_grants.iter() {
                        db.insert(ro.clone(), *uid, key_pair);
                    }
                    db
                },
                nullifiers: ledger.nullifiers.clone(),
                defined_assets: HashMap::new(),
                now: 0,
                pending_txns: Default::default(),
                expiring_txns: Default::default(),
                auditable_assets: Default::default(),
                auditor_key_pair: AuditorKeyPair::generate(&mut rng),
                freezer_key_pair: FreezerKeyPair::generate(&mut rng),
                rng,
            })
        }

        fn store(
            &mut self,
            _key_pair: &UserKeyPair,
            _state: &WalletState,
        ) -> Result<(), WalletError> {
            unimplemented!("MockWalletBackend does not support persistence");
        }

        fn subscribe(&self, starting_at: u64) -> Self::EventStream {
            let mut ledger = self.ledger.lock().unwrap();
            assert_eq!(
                starting_at, ledger.now,
                "subscribing from a historical state is not supported in the MockWalletBackend"
            );
            let (sender, receiver) = channel::unbounded();
            ledger.subscribers.push(sender);
            receiver
        }

        fn get_public_key(&self, address: &UserAddress) -> Result<UserPubKey, WalletError> {
            let ledger = self.ledger.lock().unwrap();
            match ledger.address_map.get(address) {
                Some(key) => Ok(key.clone()),
                None => Err(WalletError::InvalidAddress {
                    address: address.clone(),
                }),
            }
        }

        fn submit(
            &mut self,
            txn: ElaboratedTransaction,
            memos: Vec<ReceiverMemo>,
            sig: Signature,
        ) -> Result<(), WalletError> {
            self.ledger.lock().unwrap().submit(txn, memos, sig);
            Ok(())
        }
    }

    pub fn create_test_network<'a>(
        univ_param: &'a jf_txn::proof::UniversalParam,
        xfr_sizes: &[(usize, usize)],
        initial_grants: Vec<u64>,
        now: &mut Instant,
    ) -> (
        Arc<Mutex<MockLedger<'a>>>,
        Vec<Wallet<'a, MockWalletBackend<'a>>>,
    ) {
        let mut rng = ChaChaRng::from_seed([42u8; 32]);

        // Populate the unpruned record merkle tree with an initial record commitment for each
        // non-zero initial grant. Collect user-specific info (keys and record openings
        // corresponding to grants) in `users`, which will be used to create the wallets later.
        let mut record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        let mut users = vec![];
        for amount in initial_grants {
            let key = UserKeyPair::generate(&mut rng);
            if amount > 0 {
                let ro = RecordOpening::new(
                    &mut rng,
                    amount,
                    AssetDefinition::native(),
                    key.pub_key(),
                    FreezeFlag::Unfrozen,
                );
                let comm = RecordCommitment::from(&ro);
                let uid = record_merkle_tree.num_leaves();
                record_merkle_tree.push(comm);
                users.push((key, vec![(ro, uid)]));
            } else {
                users.push((key, vec![]));
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
            let (xfr_prove_key, xfr_verif_key, _) = jf_txn::proof::transfer::preprocess(
                univ_param,
                *num_inputs,
                *num_outputs,
                MERKLE_HEIGHT,
            )
            .unwrap();
            xfr_prove_keys.push(xfr_prove_key);
            xfr_verif_keys.push(TransactionVerifyingKey::Transfer(xfr_verif_key));
        }
        let (mint_prove_key, mint_verif_key, _) =
            jf_txn::proof::mint::preprocess(univ_param, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_txn::proof::freeze::preprocess(univ_param, 2, MERKLE_HEIGHT).unwrap();
        let nullifiers: SetMerkleTree = Default::default();
        let validator = ValidatorState::new(
            VerifierKeySet {
                xfr: KeySet::new(xfr_verif_keys.into_iter()).unwrap(),
                mint: TransactionVerifyingKey::Mint(mint_verif_key),
                freeze: KeySet::new(
                    vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
                )
                .unwrap(),
            },
            record_merkle_tree,
        );

        let comm = validator.commit();
        println!(
            "Validator set up with state {:x?}: {}s",
            comm,
            now.elapsed().as_secs_f32()
        );

        let current_block = ElaboratedBlock::next_block(&validator);
        let ledger = Arc::new(Mutex::new(MockLedger {
            now: 0,
            validator,
            nullifiers,
            subscribers: Vec::new(),
            current_block,
            current_memos: Vec::new(),
            block_size: 1,
            hold_next_transaction: false,
            held_transaction: None,
            proving_keys: ProverKeySet {
                xfr: KeySet::new(xfr_prove_keys.into_iter()).unwrap(),
                mint: mint_prove_key,
                freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
            },
            address_map: users
                .iter()
                .map(|(key, _)| (key.address(), key.pub_key()))
                .collect(),
        }));

        // Create a wallet for each user based on the validator and the per-user information
        // computed above.
        let wallets = users
            .into_iter()
            .map(|(key, initial_grants)| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                Wallet::new(
                    key,
                    MockWalletBackend {
                        ledger: ledger.clone(),
                        initial_grants,
                        seed,
                    },
                )
                .unwrap()
            })
            .collect();

        println!("Wallets set up: {}s", now.elapsed().as_secs_f32());
        *now = Instant::now();
        (ledger, wallets)
    }

    /*
     * This test is very similar to test_two_wallets, but it is parameterized on the number of users,
     * number of asset types, initial ledger state, and transactions to do, so it can be used with
     * quickcheck or proptest to do randomized fuzzing.
     */
    #[allow(clippy::type_complexity)]
    pub async fn test_multixfr_wallet(
        // List of blocks containing (def,key1,key2,amount) transfer specs
        // An asset def of 0 in a transfer spec or record indicates the native asset type; other
        // asset types are indexed startin from 1.
        txs: Vec<Vec<(u8, u8, u8, u64)>>,
        nkeys: u8,
        ndefs: u8,
        // (def,key,amount)
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>,
    ) {
        println!(
            "multixfr_wallet test: {} users, {} assets, {} records, {} transfers",
            nkeys,
            ndefs,
            init_recs.len() + 1,
            txs.iter().flatten().count()
        );
        let mut now = Instant::now();

        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let univ_param = get_universal_param(&mut prng);

        let xfr_sizes = &[
            (1, 2), // basic native transfer
            (2, 2), // basic non-native transfer, or native merge
            (2, 3), // non-native transfer with change output
            (3, 2), // non-native merge
        ];
        let mut balances = vec![vec![0; ndefs as usize + 1]; nkeys as usize];
        let grants =
            // The issuer (wallet 0) gets 1 coin per initial record, to pay transaction fees while
            // it mints and distributes the records, and 1 coin per transaction, to pay transaction
            // fees while minting additional records if test wallets run out of balance during the
            // test.
            once((1 + init_recs.len() + txs.iter().flatten().count()) as u64).chain(
                (0..nkeys)
                    .map(|i| {
                        // The remaining wallets (the test wallets) get 1 coin for each transaction
                        // in which they are the sender, to pay transaction fees, plus...
                        let txn_fees = txs.iter()
                            .flatten()
                            .map(|(_, sender, _, _)| {
                                if sender % nkeys == i {1} else {0}
                            })
                            .sum::<u64>();
                        balances[i as usize][0] += txn_fees;
                        txn_fees +
                        // ...one record for each native asset type initial record that they own,
                        // plus...
                        once(&init_rec).chain(&init_recs)
                            .map(|(def, owner, amount)| {
                                let def = (def % (ndefs + 1)) as usize;
                                let owner = (owner % nkeys) as usize;
                                if def == 0 && owner == (i as usize) {
                                    balances[owner][def] += amount;
                                    *amount
                                } else {
                                    0
                                }
                            })
                            .sum::<u64>() +
                        // We want to prevent transfers of the native asset type from failing due to
                        // insufficient funds, or worse, from dipping into native coins which were
                        // intended to be used later as transaction fees. Unlike non-native
                        // transfers, we can't mint more native coins during the test if we find
                        // that one of the wallets is low on balance. So we give each wallet an
                        // extra grant of native coins large enough to cover all the native
                        // transactions it will need to make, when combined with its original grant
                        // of native coins.
                        {
                            let total_txn_amount: u64 = txs.iter()
                                .flatten()
                                .map(|(def, sender, _, amount)| {
                                    if (def % (ndefs + 1)) == 0 && (sender % nkeys) == i {
                                        *amount
                                    } else {
                                        0
                                    }
                                })
                                .sum();
                            if txn_fees + total_txn_amount > balances[i as usize][0] {
                                let extra = txn_fees + total_txn_amount - balances[i as usize][0];
                                balances[i as usize][0] += extra;
                                extra
                            } else {
                                0
                            }
                        }
                    })
            ).collect();

        let (ledger, mut wallets) = create_test_network(&univ_param, xfr_sizes, grants, &mut now);
        println!(
            "ceremony complete, minting initial records: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();

        // Define all of the test assets and mint initial records.
        let assets: Vec<AssetDefinition> = (0..ndefs)
            .map(|i| {
                wallets[0]
                    .define_asset(format!("Asset {}", i).as_bytes(), Default::default())
                    .unwrap()
            })
            .collect();
        for (asset, owner, amount) in once(init_rec).chain(init_recs) {
            let asset = (asset % (ndefs + 1)) as usize;
            if asset == 0 {
                // can't mint native assets
                continue;
            }
            let address = wallets[(owner % nkeys) as usize + 1].address();
            balances[(owner % nkeys) as usize][asset] += amount;
            wallets[0]
                .mint(1, &assets[asset - 1].code, amount, address)
                .unwrap();
            sync(&ledger, &wallets).await;
        }

        println!("assets minted: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check initial balances. This cannot be a closure because rust infers the wrong lifetime
        // for the references (it tries to use 'a, which is longer than we want to borrow `wallets`
        // for).
        fn check_balances<'a>(
            wallets: &[Wallet<'a, MockWalletBackend<'a>>],
            balances: &[Vec<u64>],
            assets: &[AssetDefinition],
        ) {
            for (i, balance) in balances.iter().enumerate() {
                let wallet = &wallets[i + 1];

                // Check native asset balance.
                assert_eq!(wallet.balance(&AssetCode::native()), balance[0]);
                for (j, asset) in assets.iter().enumerate() {
                    assert_eq!(wallet.balance(&asset.code), balance[j + 1]);
                }
            }
        }
        check_balances(&wallets, &balances, &assets);

        // Run the test transactions.
        for (i, block) in txs.iter().enumerate() {
            println!(
                "Starting block {}/{}: {}s",
                i + 1,
                txs.len(),
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();

            // TODO process block as a batch. For now, do txs one by one.
            for (j, (asset_ix, sender_ix, receiver_ix, amount)) in block.iter().enumerate() {
                println!(
                    "Starting txn {}.{}/{}:{:?}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    (asset_ix, sender_ix, receiver_ix, amount),
                    now.elapsed().as_secs_f32()
                );

                let asset_ix = (asset_ix % (ndefs + 1)) as usize;
                let sender_ix = (sender_ix % nkeys) as usize;
                let receiver_ix = (receiver_ix % nkeys) as usize;
                let native = AssetDefinition::native();
                let asset = if asset_ix == 0 {
                    &native
                } else {
                    &assets[asset_ix - 1]
                };
                let receiver = wallets[receiver_ix + 1].address();
                let sender_address = wallets[sender_ix + 1].address();
                let sender_balance = wallets[sender_ix + 1].balance(&asset.code);

                let mut amount = if *amount <= sender_balance {
                    *amount
                } else if sender_balance > 0 {
                    // If we don't have enough to make the whole transfer, but we have some,
                    // transfer half of what we have.
                    let new_amount = std::cmp::max(sender_balance / 2, 1);
                    println!(
                        "decreasing transfer amount due to insufficient balance: {} -> {}: {}s",
                        *amount,
                        new_amount,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    new_amount
                } else {
                    // If we don't have any of this asset type, mint more.
                    assert_ne!(asset, &AssetDefinition::native());
                    println!(
                        "minting {} more of asset {:?}: {}s",
                        *amount,
                        &asset.code,
                        now.elapsed().as_secs_f32()
                    );
                    now = Instant::now();
                    wallets[0]
                        .mint(1, &asset.code, 2 * amount, sender_address)
                        .unwrap();
                    sync(&ledger, &wallets).await;
                    balances[sender_ix][asset_ix] += 2 * amount;

                    println!("asset minted: {}s", now.elapsed().as_secs_f32());
                    now = Instant::now();
                    *amount
                };

                ledger.lock().unwrap().hold_next_transaction();
                let sender = &mut wallets[sender_ix + 1];
                match sender.transfer(asset, &[(receiver.clone(), amount)], 1) {
                    Ok(txn) => txn,
                    Err(WalletError::Fragmentation {
                        suggested_amount, ..
                    }) => {
                        // Allow fragmentation. Without merge transactions, there's not much we can
                        // do to prevent it, and merge transactions require multiple transaction
                        // arities, which requires either dummy records or multiple verifier keys in
                        // the validator.
                        if suggested_amount > 0 {
                            // If the wallet suggested a transaction amount that it _can_ process,
                            // try again with that amount.
                            println!(
                                "decreasing transfer amount due to fragmentation: {} -> {}: {}s",
                                amount,
                                suggested_amount,
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();

                            amount = suggested_amount;
                            sender.transfer(asset, &[(receiver, amount)], 1).unwrap()
                        } else {
                            println!(
                                "skipping transfer due to fragmentation: {}s",
                                now.elapsed().as_secs_f32()
                            );
                            now = Instant::now();
                            continue;
                        }
                    }
                    Err(err) => {
                        panic!("transaction failed: {:?}", err)
                    }
                };
                println!("transaction generated: {}s", now.elapsed().as_secs_f32());
                now = Instant::now();

                balances[sender_ix][0] -= 1; // transaction fee
                balances[sender_ix][asset_ix] -= amount;
                balances[receiver_ix][asset_ix] += amount;

                // The sending wallet should report the new balance immediately, even before a
                // validator has confirmed the transaction, because the transferred records are
                // placed on hold until the transfer is confirmed or rejected.
                //
                // Note that the sender may report less than the final balance if it is waiting on a
                // change output to be confirmed.
                assert!(sender.balance(&native.code) <= balances[sender_ix][0]);
                assert!(sender.balance(&asset.code) <= balances[sender_ix][asset_ix]);

                ledger.lock().unwrap().release_held_transaction();
                sync(&ledger, &wallets).await;
                check_balances(&wallets, &balances, &assets);

                println!(
                    "Finished txn {}.{}/{}: {}s",
                    i + 1,
                    j + 1,
                    block.len(),
                    now.elapsed().as_secs_f32()
                );
            }
        }
    }
}

// TODO(joe): proper Err returns
#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task::block_on;
    use test_helpers::*;

    use merkle_tree::LookupResult;
    use proptest::collection::vec;
    use proptest::strategy::Strategy;
    use quickcheck::QuickCheck;

    /*
     * Test idea:
     *  - generate asset definitions somehow (tracing? probably not for now)
     *  - generate initial asset records
     *  - Repeatedly:
     *      - Pick 1 or 2 non-spent record(s)
     *      - Pick 1 or 2 recipients and the balance of outputs
     *      - build a transaction
     *      - apply that transaction
     */
    #[allow(clippy::type_complexity)] //todo replace (bool, u16, u16, u8, u8, i32) with a struct TransactionSpec
    fn test_multixfr(
        /*
         * multi_input (if false, generates smaller transaction and rec2 is ignored),
         * rec1,rec2 (0-indexed back in time),
         * key1, key2, diff in outputs (out1-out2) if diff
         * can't be achieved with those records, it will
         * saturate the other to zero.
         */
        txs: Vec<Vec<(bool, u16, u16, u8, u8, i32)>>,
        nkeys: u8,
        ndefs: u8,
        init_rec: (u8, u8, u64),
        init_recs: Vec<(u8, u8, u64)>, // (def,key) -> amount
    ) {
        let mut state = MultiXfrTestState::initialize(
            [0x7au8; 32],
            nkeys,
            ndefs,
            (
                MultiXfrRecordSpec {
                    asset_def_ix: init_rec.0,
                    owner_key_ix: init_rec.1,
                    asset_amount: init_rec.2,
                },
                init_recs
                    .into_iter()
                    .map(
                        |(asset_def_ix, owner_key_ix, asset_amount)| MultiXfrRecordSpec {
                            asset_def_ix,
                            owner_key_ix,
                            asset_amount,
                        },
                    )
                    .collect(),
            ),
        )
        .unwrap();

        // let mut prng = ChaChaRng::from_entropy();

        let num_txs = txs.len();

        println!("{} blocks", num_txs);

        for (i, block) in txs.into_iter().enumerate() {
            assert_eq!(state.owners.len(), state.memos.len());
            assert_eq!(state.validator.nullifiers_root, state.nullifiers.hash());
            MultiXfrTestState::update_timer(&mut state.outer_timer, |_| {
                println!(
                    "Block {}/{}, {} candidate txns",
                    i + 1,
                    num_txs,
                    block.len()
                )
            });

            // let block = block.into_iter().take(5).collect::<Vec<_>>();
            let txns = state.generate_transactions(i, block, num_txs).unwrap();

            let mut generation_time: f32 = 0.0;
            MultiXfrTestState::update_timer(&mut state.outer_timer, |t| {
                generation_time = t;
                println!("Block {}/{} txns generated: {}s", i + 1, num_txs, t)
            });

            let mut blk = ElaboratedBlock::default();
            for (ix, keys_and_memos, txn) in txns {
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                let _ = state.try_add_transaction(&mut blk, txn, i, ix, num_txs, owner_memos, kixs);
            }

            state
                .validate_and_apply(blk, i, num_txs, generation_time)
                .unwrap();
        }
    }

    /*
     * Test idea:
     *  - generate asset definitions somehow (tracing? probably not for now)
     *  - generate initial asset records
     *  - Repeatedly:
     *      - Pick (1? 2?) non-spent record(s)
     *      - Pick 1 or 2 recipients and the balance of outputs
     *      - build a transaction
     *      - apply that transaction
     */

    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_paramsetup() {
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        println!("generating universal parameters");

        let univ = jf_txn::proof::universal_setup(
            compute_universal_param_size(NoteType::Transfer, 1, 1, MERKLE_HEIGHT).unwrap(),
            &mut prng,
        )
        .unwrap();
        let (_prove, _verif, _constraint_count) =
            jf_txn::proof::transfer::preprocess(&univ, 1, 1, MERKLE_HEIGHT).unwrap();

        println!("CRS set up");
    }

    #[test]
    fn test_verifier_key_commit_hash() {
        // Check that ValidatorStates with different verify_crs have different commits.
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        println!("generating universal parameters");

        let univ = get_universal_param(&mut prng);
        let (_, mint, _) = jf_txn::proof::mint::preprocess(&univ, MERKLE_HEIGHT).unwrap();
        let (_, xfr11, _) =
            jf_txn::proof::transfer::preprocess(&univ, 1, 1, MERKLE_HEIGHT).unwrap();
        let (_, xfr22, _) =
            jf_txn::proof::transfer::preprocess(&univ, 2, 2, MERKLE_HEIGHT).unwrap();
        let (_, freeze2, _) = jf_txn::proof::freeze::preprocess(&univ, 2, MERKLE_HEIGHT).unwrap();
        let (_, freeze3, _) = jf_txn::proof::freeze::preprocess(&univ, 3, MERKLE_HEIGHT).unwrap();
        println!("CRS set up");

        let validator = |xfrs: &[_], freezes: &[_]| {
            let record_merkle_tree = MerkleTree::new(MERKLE_HEIGHT).unwrap();
            ValidatorState::new(
                VerifierKeySet {
                    mint: TransactionVerifyingKey::Mint(mint.clone()),
                    xfr: KeySet::new(xfrs.iter().map(|size| {
                        TransactionVerifyingKey::Transfer(match size {
                            (1, 1) => xfr11.clone(),
                            (2, 2) => xfr22.clone(),
                            _ => panic!("invalid xfr size"),
                        })
                    }))
                    .unwrap(),
                    freeze: KeySet::new(freezes.iter().map(|size| {
                        TransactionVerifyingKey::Freeze(match size {
                            2 => freeze2.clone(),
                            3 => freeze3.clone(),
                            _ => panic!("invalid freeze size"),
                        })
                    }))
                    .unwrap(),
                },
                record_merkle_tree,
            )
        };

        let validator_xfr11_freeze2 = validator(&[(1, 1)], &[2]);
        let validator_xfr11_freeze3 = validator(&[(1, 1)], &[3]);
        let validator_xfr22_freeze2 = validator(&[(2, 2)], &[2]);
        let validator_xfr11_22_freeze2 = validator(&[(1, 1), (2, 2)], &[2]);
        let validator_xfr11_freeze2_3 = validator(&[(1, 1)], &[2, 3]);
        for (v1, v2) in [
            // Different xfr keys, same freeze keys
            (&validator_xfr11_freeze2, &validator_xfr22_freeze2),
            // Different freeze keys, same xfr keys
            (&validator_xfr11_freeze2, &validator_xfr11_freeze3),
            // Different number of xfr keys
            (&validator_xfr11_freeze2, &validator_xfr11_22_freeze2),
            // Different number of freeze keys
            (&validator_xfr11_freeze2, &validator_xfr11_freeze2_3),
        ] {
            assert_ne!(v1.commit(), v2.commit());
        }
    }

    #[test]
    fn test_record_history_commit_hash() {
        // Check that ValidatorStates with different record histories have different commits.
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        println!("generating universal parameters");

        let univ = get_universal_param(&mut prng);
        let (_, mint, _) = jf_txn::proof::mint::preprocess(&univ, MERKLE_HEIGHT).unwrap();
        let (_, xfr, _) = jf_txn::proof::transfer::preprocess(&univ, 1, 1, MERKLE_HEIGHT).unwrap();
        let (_, freeze, _) = jf_txn::proof::freeze::preprocess(&univ, 2, MERKLE_HEIGHT).unwrap();
        println!("CRS set up");

        let verif_crs = VerifierKeySet {
            mint: TransactionVerifyingKey::Mint(mint),
            xfr: KeySet::new(vec![TransactionVerifyingKey::Transfer(xfr)].into_iter()).unwrap(),
            freeze: KeySet::new(vec![TransactionVerifyingKey::Freeze(freeze)].into_iter()).unwrap(),
        };
        let mut v1 = ValidatorState::new(verif_crs, MerkleTree::new(MERKLE_HEIGHT).unwrap());
        let mut v2 = v1.clone();

        // Test validators with different history lengths.
        v1.past_record_merkle_roots
            .push_front(merkle_tree::NodeValue::from(0));
        assert_ne!(v1.commit(), v2.commit());

        // Test validators with the same length, but different histories.
        v2.past_record_merkle_roots
            .push_front(merkle_tree::NodeValue::from(1));
        assert_ne!(v1.commit(), v2.commit());
    }

    #[test]
    #[allow(unused_variables)]
    fn test_2user() {
        let now = Instant::now();

        println!("generating params");

        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);

        let univ_setup = jf_txn::proof::universal_setup(
            compute_universal_param_size(NoteType::Transfer, 1, 1, MERKLE_HEIGHT).unwrap(),
            &mut prng,
        )
        .unwrap();

        let (xfr_prove_key, xfr_verif_key, _) =
            jf_txn::proof::transfer::preprocess(&univ_setup, 1, 2, MERKLE_HEIGHT).unwrap();
        let (mint_prove_key, mint_verif_key, _) =
            jf_txn::proof::mint::preprocess(&univ_setup, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_txn::proof::freeze::preprocess(&univ_setup, 2, MERKLE_HEIGHT).unwrap();

        for (l, k) in vec![
            ("xfr", CanonicalBytes::from(xfr_verif_key.clone())),
            ("mint", CanonicalBytes::from(mint_verif_key.clone())),
            ("freeze", CanonicalBytes::from(freeze_verif_key.clone())),
        ] {
            println!("{}: {} bytes", l, k.0.len());
        }

        let prove_keys = ProverKeySet::<key_set::OrderByInputs> {
            mint: mint_prove_key,
            xfr: KeySet::new(vec![xfr_prove_key].into_iter()).unwrap(),
            freeze: KeySet::new(vec![freeze_prove_key].into_iter()).unwrap(),
        };

        let verif_keys = VerifierKeySet {
            mint: TransactionVerifyingKey::Mint(mint_verif_key),
            xfr: KeySet::new(vec![TransactionVerifyingKey::Transfer(xfr_verif_key)].into_iter())
                .unwrap(),
            freeze: KeySet::new(
                vec![TransactionVerifyingKey::Freeze(freeze_verif_key)].into_iter(),
            )
            .unwrap(),
        };

        println!("CRS set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let alice_key = UserKeyPair::generate(&mut prng);
        let bob_key = UserKeyPair::generate(&mut prng);

        let coin = AssetDefinition::native();

        let alice_rec_builder = RecordOpening::new(
            &mut prng,
            2,
            coin.clone(),
            alice_key.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let alice_rec1 = alice_rec_builder;

        let mut t = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        assert_eq!(
            t.get_root_value(),
            MerkleTree::<RecordCommitment>::new(MERKLE_HEIGHT)
                .unwrap()
                .get_root_value()
        );
        let alice_rec_elem = RecordCommitment::from(&alice_rec1);
        // dbg!(&RecordCommitment::from(&alice_rec1));
        assert_eq!(
            RecordCommitment::from(&alice_rec1),
            RecordCommitment::from(&alice_rec1)
        );
        t.push(RecordCommitment::from(&alice_rec1));
        let alice_rec_path = t.get_leaf(0).expect_ok().unwrap().1;
        assert_eq!(alice_rec_path.nodes.len(), MERKLE_HEIGHT as usize);

        let mut nullifiers: SetMerkleTree = Default::default();

        println!("Tree set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let first_root = t.get_root_value();

        let alice_rec_final = TransferNoteInput {
            ro: alice_rec1,
            owner_keypair: &alice_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: alice_rec_path.clone(),
                root: first_root,
                uid: 0,
            },
        };

        let mut wallet_merkle_tree = t.clone();
        let mut validator = ValidatorState::new(verif_keys, t);

        println!("Validator set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let comm = validator.commit();
        // assert_eq!(&comm.as_ref(),
        //     &[0x78, 0x35, 0x59, 0x80, 0x24, 0xab, 0xe2, 0x71, 0xbb, 0x26, 0x1d, 0xbd, 0x4f, 0xc0,
        //       0xfb, 0xb8, 0xc3, 0x01, 0x62, 0xae, 0x95, 0xf5, 0x8c, 0x20, 0xc5, 0xf6, 0x00, 0x14,
        //       0xbc, 0x3c, 0x79, 0xa6, 0x2d, 0xe6, 0xdc, 0x5d, 0xac, 0x36, 0x54, 0x9f, 0xad, 0x24,
        //       0xc6, 0x69, 0x59, 0xb0, 0x68, 0x85, 0x7f, 0x27, 0x1e, 0x77, 0xb7, 0xf8, 0xab, 0x0d,
        //       0x08, 0xe8, 0x00, 0x30, 0xfe, 0xc1, 0xa4, 0x86]);
        println!(
            "Validator has state {:x?}: {}s",
            comm,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        MerkleTree::check_proof(
            validator.record_merkle_root,
            0,
            alice_rec_elem,
            &alice_rec_path,
        )
        .unwrap();

        println!("Path checked: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let ((txn1, _, _), bob_rec) = {
            let bob_rec = RecordOpening::new(
                &mut prng,
                1, /* 1 less, for the transaction fee */
                coin,
                bob_key.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let txn = TransferNote::generate_native(
                &mut prng,
                /* inputs:         */ vec![alice_rec_final],
                /* outputs:        */ &[bob_rec.clone()],
                /* fee:            */ 1,
                /* valid_until:    */ 2,
                /* proving_key:    */ prove_keys.xfr.key_for_size(1, 2).unwrap(),
            )
            .unwrap();
            (txn, bob_rec)
        };

        println!("Transfer has {} outputs", txn1.output_commitments.len());
        println!(
            "Transfer is {} bytes long",
            serde_cbor::ser::to_vec_packed(&txn1).unwrap().len()
        );

        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let nullifier_pfs = txn1
            .inputs_nullifiers
            .iter()
            .map(|n| nullifiers.contains(*n).unwrap().1)
            .collect();
        for n in txn1.inputs_nullifiers.iter() {
            nullifiers.insert(*n);
        }

        println!(
            "Transfer nullifier proofs generated: {}",
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let new_recs = txn1.output_commitments.to_vec();

        let new_uids = validator
            .validate_and_apply(
                1,
                Block(vec![TransactionNote::Transfer(Box::new(txn1))]),
                vec![nullifier_pfs],
                false,
            )
            .unwrap();

        println!(
            "Transfer validated & applied: {}s",
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        assert_eq!(&new_uids[1..], &[2]);
        for r in new_recs {
            wallet_merkle_tree.push(r);
        }

        let bob_rec = TransferNoteInput {
            ro: bob_rec,
            owner_keypair: &bob_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: wallet_merkle_tree.get_leaf(2).expect_ok().unwrap().1,
                root: validator.record_merkle_frontier.get_root_value(),
                uid: 2,
            },
        };

        assert_eq!(nullifiers.hash(), validator.nullifiers_root);

        println!(
            "New record merkle path retrieved: {}s",
            now.elapsed().as_secs_f32()
        );
        let comm = validator.commit();
        println!(
            "Validator has state {:x?}: {}s",
            comm,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();
    }

    /*
     * Test idea: simulate two wallets transferring funds back and forth. After initial
     * setup, the wallets only receive publicly visible information (e.g. block commitment
     * events and receiver memos posted on bulletin boards). Check that both wallets are
     * able to maintain accurate balance statements and enough state to construct new transfers.
     *
     * - Alice magically starts with some coins, Bob starts empty.
     * - Alice transfers some coins to Bob using exact change.
     * - Alice and Bob check their balances, then Bob transfers some coins back to Alice, in an
     *   amount that requires a fee change record.
     *
     * Limitations:
     * - Parts of the system are mocked (e.g. consensus is replaced by one omniscient validator,
     *   info event streams, query services, and bulletin boards is provided directly to the
     *   wallets by the test)
     */
    #[allow(unused_assignments)]
    async fn test_two_wallets(native: bool) {
        let mut now = Instant::now();
        println!("generating params");
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let univ_param = get_universal_param(&mut prng);

        // Each transaction in this test will be a transfer of 1 record, with an additional
        // fee change output. We need to fix the transfer arity because although the wallet
        // supports variable arities, the validator currently does not.
        let num_inputs = if native { 1 } else { 2 }; // non-native transfers have a separate fee input
        let num_outputs = if native { 2 } else { 3 }; // non-native transfers have an extra change output

        // Give Alice an initial grant of 5 native coins. If using non-native transfers, give Bob an
        // initial grant with which to pay his transaction fee, since he will not be receiving any
        // native coins from Alice.
        let alice_grant = 5;
        let bob_grant = if native { 0 } else { 1 };
        let (ledger, mut wallets) = create_test_network(
            &univ_param,
            &[(num_inputs, num_outputs)],
            vec![alice_grant, bob_grant],
            &mut now,
        );
        let alice_address = wallets[0].address();
        let bob_address = wallets[1].address();

        // Verify initial wallet state.
        assert_ne!(alice_address, bob_address);
        assert_eq!(wallets[0].balance(&AssetCode::native()), alice_grant);
        assert_eq!(wallets[1].balance(&AssetCode::native()), bob_grant);

        let coin = if native {
            AssetDefinition::native()
        } else {
            let coin = wallets[0]
                .define_asset("Alice's asset".as_bytes(), Default::default())
                .unwrap();
            // Alice gives herself an initial grant of 5 coins.
            wallets[0]
                .mint(1, &coin.code, 5, alice_address.clone())
                .unwrap();
            sync(&ledger, &wallets).await;
            println!("Asset minted: {}s", now.elapsed().as_secs_f32());
            now = Instant::now();

            assert_eq!(wallets[0].balance(&coin.code), 5);
            assert_eq!(wallets[1].balance(&coin.code), 0);

            coin
        };

        let alice_initial_native_balance = wallets[0].balance(&AssetCode::native());
        let bob_initial_native_balance = wallets[1].balance(&AssetCode::native());

        // Construct a transaction to transfer some coins from Alice to Bob.
        wallets[0].transfer(&coin, &[(bob_address, 3)], 1).unwrap();
        sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both wallets reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `wallets` for).
        fn check_balance<'a>(
            wallet: &Wallet<'a, MockWalletBackend<'a>>,
            expected_coin_balance: u64,
            starting_native_balance: u64,
            fees_paid: u64,
            coin: &AssetDefinition,
            native: bool,
        ) {
            if native {
                assert_eq!(
                    wallet.balance(&coin.code),
                    expected_coin_balance - fees_paid
                );
            } else {
                assert_eq!(wallet.balance(&coin.code), expected_coin_balance);
                assert_eq!(
                    wallet.balance(&AssetCode::native()),
                    starting_native_balance - fees_paid
                );
            }
        }
        check_balance(
            &wallets[0],
            2,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        );
        check_balance(&wallets[1], 3, bob_initial_native_balance, 0, &coin, native);

        // Check that Bob's wallet has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3 coins, but
        // the sum of the outputs and fee of this transaction is only 2.
        wallets[1]
            .transfer(&coin, &[(alice_address, 1)], 1)
            .unwrap();
        sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        check_balance(
            &wallets[0],
            3,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        );
        check_balance(&wallets[1], 2, bob_initial_native_balance, 1, &coin, native);
    }

    #[async_std::test]
    async fn test_two_wallets_native() -> std::io::Result<()> {
        test_two_wallets(true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_two_wallets_non_native() -> std::io::Result<()> {
        test_two_wallets(false).await;
        Ok(())
    }

    // Test transactions that fail to complete.
    //
    // If `native`, the transaction is a native asset transfer.
    // If `!native && !mint && !freeze`, the trnasaction is a non-native asset transfer.
    // If `!native && mint`, the transaction is a non-native asset mint.
    // If `!native && freeze`, the transaction is a non-native asset freeze.
    //
    // If `timeout`, the failed transaction times out with no explicit rejection event. Otherwise,
    // the failed transaction fails to verify and a Reject event is emitted.
    //
    // (native, mint), (native, freeze), and (mint, freeze) are pairs of mutually exclusive flags.
    async fn test_wallet_rejected(native: bool, mint: bool, freeze: bool, timeout: bool) {
        assert!(!(native && mint));
        assert!(!(native && freeze));
        assert!(!(mint && freeze));

        let mut now = Instant::now();
        println!("generating params");

        let mut rng = ChaChaRng::from_seed([0x8au8; 32]);
        let univ_param = get_universal_param(&mut rng);

        // Native transfers have extra fee/change inputs/outputs.
        let num_inputs = if native { 1 } else { 2 };
        let num_outputs = if native { 2 } else { 3 };

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment (or, for non-native transfers, a transaction fee and a mint fee). wallets[1] will
        // act as the receiver, and wallets[2] will be a third party which generates
        // RECORD_HOLD_TIME transfers while a transfer from wallets[0] is pending, causing the
        // transfer to time out.
        let (ledger, mut wallets) = create_test_network(
            &univ_param,
            &[(num_inputs, num_outputs)],
            // If native, wallets[0] gets 1 coin to transfer and 1 for a transaction fee. Otherwise,
            // it gets
            //  * 1 transaction fee
            //  * 1 mint fee for its initial non-native record, if the test itself is not minting
            //    that record
            //  * 1 mint fee for wallets[2]'s initial non-native record in the timeout test.
            vec![
                if native {
                    2
                } else {
                    1 + !mint as u64 + timeout as u64
                },
                0,
                2 * RECORD_HOLD_TIME,
            ],
            &mut now,
        );

        let asset = if native {
            AssetDefinition::native()
        } else {
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(wallets[0].auditor_pub_key())
                .set_freezer_pub_key(wallets[0].freezer_pub_key())
                .reveal_record_opening()
                .unwrap();
            let asset = wallets[0]
                .define_asset("test asset".as_bytes(), policy)
                .unwrap();

            if !mint {
                // If we're freezing, the transaction is essentially taking balance away from
                // wallets[1], so wallets[1] gets 1 coin to start with. Otherwise, the transaction
                // is transferring balance from wallets[0] to wallets[1], so  wallets[0] gets 1
                // coin. We only need this if the test itself is not minting the asset later on.
                let dst = if freeze {
                    wallets[1].address()
                } else {
                    wallets[0].address()
                };
                wallets[0].mint(1, &asset.code, 1, dst).unwrap();
                sync(&ledger, &wallets).await;
            }

            if timeout {
                // If doing a timeout test, wallets[2] (the sender that will generate enough
                // transactions to cause wallets[0]'s transaction to timeout) gets RECORD_HOLD_TIME
                // coins.
                let dst = wallets[2].address();
                wallets[0]
                    .mint(1, &asset.code, RECORD_HOLD_TIME, dst)
                    .unwrap();
                sync(&ledger, &wallets).await;
            }

            asset
        };

        // Start a transfer that will ultimately get rejected.
        println!(
            "generating a transfer which will fail: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        ledger.lock().unwrap().hold_next_transaction();
        let receiver = wallets[1].address();
        if mint {
            wallets[0]
                .mint(1, &asset.code, 1, receiver.clone())
                .unwrap();
        } else if freeze {
            wallets[0].freeze(1, &asset, 1, receiver.clone()).unwrap();
        } else {
            wallets[0]
                .transfer(&asset, &[(receiver.clone(), 1)], 1)
                .unwrap();
        }
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that the sender's balance is on hold (for the fee and the payment).
        assert_eq!(wallets[0].balance(&AssetCode::native()), 0);
        if !freeze {
            assert_eq!(wallets[0].balance(&asset.code), 0);
        }

        // Now do something that causes the sender's transaction to not go through
        if timeout {
            // Generate RECORD_HOLD_TIME transactions to cause `txn` to time out.
            println!(
                "generating {} transfers to time out the original transfer: {}s",
                RECORD_HOLD_TIME,
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();
            for _ in 0..RECORD_HOLD_TIME {
                // Check that the sender's balance is still on hold.
                assert_eq!(wallets[0].balance(&AssetCode::native()), 0);
                if !freeze {
                    assert_eq!(wallets[0].balance(&asset.code), 0);
                }

                wallets[2]
                    .transfer(&asset, &[(receiver.clone(), 1)], 1)
                    .unwrap();
                sync(&ledger, &wallets).await;
            }
        } else {
            {
                let mut ledger = ledger.lock().unwrap();

                // Change the validator state, so that the wallet's transaction (built against the
                // old validator state) will fail to validate.
                let old_record_merkle_root = ledger.validator.record_merkle_root;
                ledger.validator.record_merkle_root = merkle_tree::NodeValue::from(0);

                println!(
                    "validating invalid transaction: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
                ledger.release_held_transaction();

                // The sender gets back in sync with the validator after their transaction is
                // rejected.
                ledger.validator.record_merkle_root = old_record_merkle_root;
            }

            sync(&ledger, &wallets).await;
        }

        // Check that the sender got their balance back.
        if native {
            assert_eq!(wallets[0].balance(&AssetCode::native()), 2);
        } else {
            assert_eq!(wallets[0].balance(&AssetCode::native()), 1);
            if !(mint || freeze) {
                // in the mint and freeze cases, we never had a non-native balance to start with
                assert_eq!(wallets[0].balance(&asset.code), 1);
            }
        }
        assert_eq!(
            wallets[1].balance(&asset.code),
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 1 } else { 0 })
        );

        // Now check that they can use the un-held record if their state gets back in sync with the
        // validator.
        println!(
            "transferring un-held record: {}s",
            now.elapsed().as_secs_f32()
        );
        if mint {
            wallets[0].mint(1, &asset.code, 1, receiver).unwrap();
        } else if freeze {
            wallets[0].freeze(1, &asset, 1, receiver).unwrap();
        } else {
            wallets[0].transfer(&asset, &[(receiver, 1)], 1).unwrap();
        }
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&AssetCode::native()), 0);
        assert_eq!(wallets[0].balance(&asset.code), 0);
        assert_eq!(
            wallets[1].balance(&asset.code),
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 0 } else { 1 })
        );
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_invalid() -> std::io::Result<()> {
        test_wallet_rejected(true, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_timeout() -> std::io::Result<()> {
        test_wallet_rejected(true, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, true, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, true, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_invalid() -> std::io::Result<()> {
        test_wallet_rejected(false, false, true, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_timeout() -> std::io::Result<()> {
        test_wallet_rejected(false, false, true, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_resubmit() -> std::io::Result<()> {
        let mut now = Instant::now();
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let univ_param = get_universal_param(&mut prng);

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment. wallets[1] will act as the receiver, and wallets[2] will be a third party
        // which generates RECORD_ROOT_HISTORY_SIZE-1 transfers while a transfer from wallets[0] is
        // pending, after which we will check if the pending transaction can be updated and
        // resubmitted.
        let (ledger, mut wallets) = create_test_network(
            &univ_param,
            &[(1, 2)],
            vec![
                2,
                0,
                2 * (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64,
            ],
            &mut now,
        );

        println!("generating transaction: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        ledger.lock().unwrap().hold_next_transaction();
        let receiver = wallets[1].address();
        wallets[0]
            .transfer(&AssetDefinition::native(), &[(receiver.clone(), 1)], 1)
            .unwrap();
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Generate a transaction, invalidating the pending transfer.
        println!(
            "generating {} transfers to invalidate the original transfer: {}s",
            ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1,
            now.elapsed().as_secs_f32(),
        );
        now = Instant::now();
        for _ in 0..ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1 {
            wallets[2]
                .transfer(&AssetDefinition::native(), &[(receiver.clone(), 1)], 1)
                .unwrap();
            sync(&ledger, &wallets).await;
        }

        // Check that the pending transaction eventually succeeds, after being automatically
        // resubmitted by the wallet.
        println!(
            "submitting invalid transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        let ledger_time = ledger.lock().unwrap().now;
        ledger.lock().unwrap().release_held_transaction().unwrap();
        // Wait for 2 events: the first Reject event and then a later Commit event after the wallet
        // resubmits.
        sync_with(&wallets, ledger_time + 2).await;
        assert_eq!(wallets[0].balance(&AssetCode::native()), 0);
        assert_eq!(
            wallets[1].balance(&AssetCode::native()),
            1 + (ValidatorState::RECORD_ROOT_HISTORY_SIZE - 1) as u64
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_freeze() -> std::io::Result<()> {
        let mut now = Instant::now();
        println!("generating params");

        let mut rng = ChaChaRng::from_seed([0x8au8; 32]);
        let univ_param = get_universal_param(&mut rng);

        // The sender wallet (wallets[0]) gets an initial grant of 1 for a transfer fee. wallets[1]
        // will act as the receiver, and wallets[2] will be a third party which issues and freezes
        // some of wallets[0]'s assets. It gets a grant of 3, for a mint fee, a freeze fee and an
        // unfreeze fee.
        let (ledger, mut wallets) =
            create_test_network(&univ_param, &[(2, 3)], vec![1, 0, 3], &mut now);

        let asset = {
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(wallets[2].auditor_pub_key())
                .set_freezer_pub_key(wallets[2].freezer_pub_key())
                .reveal_record_opening()
                .unwrap();
            let asset = wallets[2]
                .define_asset("test asset".as_bytes(), policy)
                .unwrap();

            // wallets[0] gets 1 coin to transfer to wallets[1].
            let dst = wallets[0].address();
            wallets[2].mint(1, &asset.code, 1, dst).unwrap();
            sync(&ledger, &wallets).await;

            asset
        };
        assert_eq!(wallets[0].balance(&asset.code), 1);
        assert_eq!(wallets[0].frozen_balance(&asset.code), 0);

        // Now freeze wallets[0]'s record.
        println!(
            "generating a freeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let dst = wallets[0].address();
        ledger.lock().unwrap().hold_next_transaction();
        wallets[2].freeze(1, &asset, 1, dst.clone()).unwrap();

        // Check that, like transfer inputs, freeze inputs are placed on hold and unusable while a
        // freeze that uses them is pending.
        match wallets[2].freeze(1, &asset, 1, dst) {
            Err(WalletError::InsufficientBalance { .. }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret),
        }

        // Now go ahead with the original freeze.
        ledger.lock().unwrap().release_held_transaction();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code), 0);
        assert_eq!(wallets[0].frozen_balance(&asset.code), 1);

        // Check that trying to transfer fails due to frozen balance.
        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        let dst = wallets[1].address();
        match wallets[0].transfer(&asset, &[(dst, 1)], 1) {
            Err(WalletError::InsufficientBalance { .. }) => {
                println!(
                    "transfer correctly failed due to frozen balance: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
            }
            ret => panic!("expected InsufficientBalance, got {:?}", ret),
        }

        // Now unfreeze the asset and try again.
        println!(
            "generating an unfreeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let dst = wallets[0].address();
        wallets[2].unfreeze(1, &asset, 1, dst).unwrap();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code), 1);
        assert_eq!(wallets[0].frozen_balance(&asset.code), 0);

        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        let dst = wallets[1].address();
        wallets[0].transfer(&asset, &[(dst, 1)], 1).unwrap();
        sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].balance(&asset.code), 0);
        assert_eq!(wallets[0].frozen_balance(&asset.code), 0);
        assert_eq!(wallets[1].balance(&asset.code), 1);

        Ok(())
    }

    #[async_std::test]
    async fn test_multixfr_wallet_simple() -> std::io::Result<()> {
        let alice_grant = (0, 0, 3); // Alice gets 3 of coin 0 to start
        let bob_grant = (1, 1, 3); // Bob gets 3 of coin 1 to start
        let txns = vec![vec![
            (1, 0, 1, 2), // Alice sends 2 of coin 1 to Bob
            (2, 1, 0, 2), // Bob sends 2 of coin 2 to Alice
            (1, 1, 0, 1), // Bob sends 1 of coin 1 to Alice
        ]];
        test_multixfr_wallet(txns, 2, 2, alice_grant, vec![bob_grant]).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_multixfr_wallet_various_kinds() -> std::io::Result<()> {
        let txns = vec![vec![
            (0, 0, 1, 1), // native asset transfer
            (1, 0, 1, 1), // non-native asset transfer with change output
            (1, 0, 2, 1), // non-native asset transfer with exact change
        ]];
        let native_grant = (0, 0, 1);
        let non_native_grant = (1, 0, 3);
        test_multixfr_wallet(txns, 2, 1, native_grant, vec![non_native_grant]).await;
        Ok(())
    }

    struct MultiXfrParams {
        max_txns: usize,
        max_blocks: usize,
        max_keys: u8,
        max_defs: u8,
        max_amt: u64,
        max_recs: usize,
    }

    impl MultiXfrParams {
        const fn new(txns: usize, max_amt: u64) -> Self {
            // divide txns into 5 blocks
            let max_txns = if txns > 5 { txns / 5 } else { 1 };
            let max_blocks = if txns > 5 { 5 } else { txns };
            // fewer users than txns so we get multiple txns with same key
            let max_keys = (txns / 2 + 2) as u8;
            // fewer defs than txns so we get multiple txns with same def
            let max_defs = (txns / 2 + 1) as u8;
            // enough records to give everyone 1 of each type, on average
            // Reasoning for /4:
            //      E[nkeys] = max_keys/2
            //      E[ndefs] = max_defs/2
            // So
            //      E[nkeys*ndefs] = max_keys*max_defs/4
            let max_recs = max_keys as usize * max_defs as usize / 4;

            MultiXfrParams {
                max_txns,
                max_blocks,
                max_keys,
                max_defs,
                max_amt,
                max_recs,
            }
        }

        fn def(&self) -> impl Strategy<Value = u8> {
            // range is inclusive because def 0 is the native asset, and other asset defs are
            // 1-indexed
            0..=self.max_defs
        }

        fn key(&self) -> impl Strategy<Value = u8> {
            0..self.max_keys
        }

        fn txn_amt(&self) -> impl Strategy<Value = u64> {
            // Transaction amounts are smaller than record amounts because we don't want to burn a
            // whole record in one transaction.
            1..=std::cmp::max(self.max_amt / 5, 2)
        }

        fn amt(&self) -> impl Strategy<Value = u64> {
            1..=self.max_amt
        }

        fn txs(&self) -> impl Strategy<Value = Vec<Vec<(u8, u8, u8, u64)>>> {
            vec(
                vec(
                    (self.def(), self.key(), self.key(), self.txn_amt()),
                    self.max_txns,
                ),
                self.max_blocks,
            )
        }

        fn nkeys(&self) -> impl Strategy<Value = u8> {
            2..=self.max_keys
        }

        fn ndefs(&self) -> impl Strategy<Value = u8> {
            1..=self.max_defs
        }

        fn rec(&self) -> impl Strategy<Value = (u8, u8, u64)> {
            (self.def(), self.key(), self.amt())
        }

        fn recs(&self) -> impl Strategy<Value = Vec<(u8, u8, u64)>> {
            vec(self.rec(), self.max_recs)
        }
    }

    const MULTI_XFR_SMALL: MultiXfrParams = MultiXfrParams::new(5, 1000);
    const MULTI_XFR_LARGE: MultiXfrParams = MultiXfrParams::new(50, 1000);

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        fn proptest_multixfr_wallet_small(
            txs in MULTI_XFR_SMALL.txs(),
            nkeys in MULTI_XFR_SMALL.nkeys(),
            ndefs in MULTI_XFR_SMALL.ndefs(),
            init_rec in MULTI_XFR_SMALL.rec(),
            init_recs in MULTI_XFR_SMALL.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 10,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        #[ignore]
        fn proptest_multixfr_wallet_many_small_tests(
            txs in MULTI_XFR_SMALL.txs(),
            nkeys in MULTI_XFR_SMALL.nkeys(),
            ndefs in MULTI_XFR_SMALL.ndefs(),
            init_rec in MULTI_XFR_SMALL.rec(),
            init_recs in MULTI_XFR_SMALL.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 1,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        #[ignore]
        fn proptest_multixfr_wallet_one_big_test(
            txs in MULTI_XFR_LARGE.txs(),
            nkeys in MULTI_XFR_LARGE.nkeys(),
            ndefs in MULTI_XFR_LARGE.ndefs(),
            init_rec in MULTI_XFR_LARGE.rec(),
            init_recs in MULTI_XFR_LARGE.recs(),
        ) {
            block_on(test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs));
        }
    }

    fn pow3(x: u64) -> u64 {
        let mut ret = 1u64;
        for i in (0..64).rev() {
            ret = ret.overflowing_mul(ret).0;
            if ((x >> i) & 1) == 1 {
                ret = ret.overflowing_mul(3).0;
            }
        }
        ret
    }

    fn test_merkle_tree(updates: Vec<Result<u64, usize>>) {
        println!("Iter: {} updates", updates.len());
        let (mut t1, mut t2) = (
            MerkleTree::<u64>::new(MERKLE_HEIGHT).unwrap(),
            MerkleTree::<u64>::new(MERKLE_HEIGHT).unwrap(),
        );
        for t in [&mut t1, &mut t2].iter_mut() {
            let mut map = Vec::new();
            for u in updates.iter() {
                match u {
                    Ok(val) => {
                        map.push(val);

                        t.push(pow3(*val));

                        // check_path(t.hasher.as_ref(), &path.unwrap(), &leaf_val,
                        //         &leaf_hash, MERKLE_HEIGHT, &t.root_hash)
                        //     .expect("Merkle3Tree generated an invalid proof");

                        // assert_eq!(old_val,old_tree_val.map(|x| x.1));
                    }
                    Err(i) => {
                        match (
                            map.get(*i).cloned().map(|x| pow3(*x as u64)),
                            t.get_leaf(*i as u64),
                        ) {
                            (None, LookupResult::EmptyLeaf) => {}
                            (Some(map_val), LookupResult::Ok(_tree_val, tree_proof)) => {
                                // assert_eq!(map_val,tree_val);
                                MerkleTree::check_proof(
                                    t.get_root_value(),
                                    *i as u64,
                                    map_val,
                                    &tree_proof,
                                )
                                .expect("Merkle path verification failed");
                            }
                            (l, r) => {
                                panic!("Mismatch: map_val = {:?}, tree_val,proof = {:?}", l, r);
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(t1.get_root_value(), t2.get_root_value());
    }

    #[test]
    fn quickcheck_multixfr_regression1() {
        test_multixfr(vec![vec![]], 0, 0, (0, 0, 0), vec![])
    }
    #[test]
    fn quickcheck_multixfr_regression2() {
        test_multixfr(
            vec![vec![(true, 0, 0, 0, 0, -2), (true, 0, 0, 0, 0, 0)]],
            0,
            0,
            (0, 0, 0),
            vec![(0, 0, 0)],
        )
    }

    #[test]
    fn quickcheck_multixfr_regression3() {
        test_multixfr(vec![], 0, 0, (0, 0, 0), vec![(0, 3, 0)])
    }

    #[test]
    fn quickcheck_multixfr_regression4() {
        test_multixfr(vec![vec![(true, 3, 0, 0, 0, 0)]], 0, 0, (0, 0, 0), vec![])
    }

    #[test]
    fn quickcheck_multixfr_regression5() {
        test_multixfr(
            vec![vec![(true, 0, 0, 1, 1, 0)], vec![(true, 0, 0, 0, 0, 0)]],
            1,
            0,
            (0, 0, 0),
            vec![],
        )
    }

    #[test]
    fn quickcheck_multixfr_regression6() {
        // This test caused 0-amount records to be created by breaking single records into two using
        // single-input transactions. 0-amount records in turn lead to underflows when the test
        // tries to compute output amounts that are separated by a non-zero amt_diff and sum to 0.
        test_multixfr(
            vec![
                vec![(false, 0, 0, 1, 1, 0)],
                vec![(false, 0, 0, 1, 1, 0)],
                vec![(false, 0, 0, 1, 1, 0)],
            ],
            2,
            1,
            (0, 0, 2),
            vec![],
        )
    }

    #[test]
    fn test_multixfr_multi_arity() {
        test_multixfr(
            vec![vec![(true, 0, 1, 1, 1, 0)], vec![(false, 5, 0, 1, 1, 0)]],
            2,
            1,
            (0, 0, 2),
            vec![(0, 0, 2), (0, 0, 2)],
        )
    }

    #[test]
    #[ignore]
    fn quickcheck_multixfr() {
        QuickCheck::new()
            .tests(1)
            .quickcheck(test_multixfr as fn(Vec<_>, u8, u8, _, Vec<_>) -> ());
    }

    #[test]
    fn quickcheck_merkle_tree_map() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_merkle_tree as fn(Vec<_>) -> ());
    }

    #[test]
    fn single_item_insert() {
        test_merkle_tree(vec![Ok(0)]);
    }

    #[test]
    fn double_item_insert() {
        test_merkle_tree(vec![Ok(0), Ok(1)]);
    }

    #[test]
    fn quickcheck_regressions() {}
}
