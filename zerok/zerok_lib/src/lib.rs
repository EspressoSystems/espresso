#![deny(warnings)]

mod set_merkle_tree;
mod util;

use core::fmt::Debug;
use core::iter::once;
use jf_primitives::merkle_tree;
use jf_txn::{
    errors::TxnApiError,
    keys::{FreezerKeyPair, UserKeyPair},
    mint::MintNote,
    proof::{freeze::FreezeProvingKey, mint::MintProvingKey, transfer::TransferProvingKey},
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, FeeInput, FreezeFlag, NoteType, Nullifier,
        ReceiverMemo, RecordCommitment, RecordOpening,
    },
    transfer::{TransferNote, TransferNoteInput},
    txn_batch_verify,
    utils::compute_universal_param_size,
    TransactionNote, TransactionVerifyingKey,
};
use jf_utils::serialize::CanonicalBytes;
use merkle_tree::{AccMemberWitness, MerkleTree};
use phaselock::BlockContents;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
pub use set_merkle_tree::*;
use snafu::Snafu;
use std::collections::HashSet;
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
        )?;
        Ok(state)
    }

    fn hash(&self) -> phaselock::BlockHash<64> {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "ElaboratedBlock".as_bytes());
        hasher.update(&"Block contents".as_bytes());
        hasher.update(&block_comm::block_commit(&self.block));
        hasher.update(&"Block proofs".as_bytes());
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
        hasher.update(&"Txn contents".as_bytes());
        hasher.update(&txn_comm::txn_commit(&txn.txn));
        hasher.update(&"Txn proofs".as_bytes());
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverKey<'a> {
    pub mint: MintProvingKey<'a>,
    pub xfr: TransferProvingKey<'a>,
    pub freeze: FreezeProvingKey<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierKey {
    // TODO: is there a way to keep these types distinct?
    pub mint: TransactionVerifyingKey,
    pub xfr: TransactionVerifyingKey,
    pub freeze: TransactionVerifyingKey,
}

// TODO
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum ValidationError {
    NullifierAlreadyExists { nullifier: Nullifier },
    BadNullifierProof {},
    MissingNullifierProof {},
    ConflictingNullifiers {},
    Failed {},
    BadMerkleLength {},
    BadMerkleLeaf {},
    BadMerkleRoot {},
    BadMerklePath {},
    CryptoError { err: TxnApiError },
}

mod verif_crs_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type VerifCRSCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn verif_crs_commit(p: &VerifierKey) -> VerifCRSCommitment {
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
            hasher.update(&txn_comm::txn_commit(&t));
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
        pub nullifiers: set_hash::Hash,
        pub next_uid: u64,
        pub prev_block: block_comm::BlockCommitment,
    }

    impl LedgerCommInputs {
        pub fn commit(&self) -> LedgerStateCommitment {
            let mut hasher = blake2::Blake2b::with_params(&[], &[], "Ledger Comm".as_bytes());
            hasher.update(&"prev_commit_time".as_bytes());
            hasher.update(&self.prev_commit_time.to_le_bytes());
            hasher.update(&"prev_state".as_bytes());
            hasher.update(&self.prev_state);
            hasher.update(&"verif_crs".as_bytes());
            hasher.update(&self.verif_crs);
            hasher.update(&"record_merkle_root".as_bytes());
            hasher.update(&CanonicalBytes::from(self.record_merkle_root).0);
            hasher.update(&"nullifiers".as_bytes());
            hasher.update(&self.nullifiers);
            hasher.update(&"next_uid".as_bytes());
            hasher.update(&self.next_uid.to_le_bytes());
            hasher.update(&"prev_block".as_bytes());
            hasher.update(&self.prev_block);

            hasher.finalize().into_bytes()
        }
    }
}

#[derive(Clone)]
pub struct ValidatorState {
    pub prev_commit_time: u64,
    pub prev_state: state_comm::LedgerStateCommitment,
    pub verif_crs: VerifierKey,
    pub record_merkle_root: merkle_tree::NodeValue,
    pub record_merkle_frontier: merkle_tree::MerkleTree<RecordCommitment>,
    pub nullifiers_root: set_hash::Hash,
    pub next_uid: u64,
    pub prev_block: Block,
}

impl ValidatorState {
    pub fn commit(&self) -> state_comm::LedgerStateCommitment {
        let inputs = state_comm::LedgerCommInputs {
            prev_commit_time: self.prev_commit_time,
            prev_state: self.prev_state,
            verif_crs: verif_crs_comm::verif_crs_commit(&self.verif_crs),
            record_merkle_root: self.record_merkle_root,
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

        let verif_keys: Vec<_> = txns
            .0
            .iter()
            .map(|txn| match txn {
                TransactionNote::Mint(_) => &self.verif_crs.mint,
                TransactionNote::Transfer(_) => &self.verif_crs.xfr,
                TransactionNote::Freeze(_) => &self.verif_crs.freeze,
            })
            .collect();

        if !txns.0.is_empty() {
            txn_batch_verify(
                &txns.0,
                &txns
                    .0
                    .iter()
                    .map(|_| self.record_merkle_frontier.get_root_value())
                    .collect::<Vec<_>>(),
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
    ) -> Result<Vec<u64> /* new uids */, ValidationError> {
        let (txns, _null_pfs) = self.validate_block(now, txns, null_pfs.clone())?;
        let comm = self.commit();
        self.prev_commit_time = now;
        self.prev_block = txns.clone();

        // TODO: getting this working requires getting something into the txn that allows nullifiers to be extracted.

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
            self.record_merkle_frontier.forget(uid).expect_ok().unwrap();
            ret.push(uid);
            self.next_uid += 1;
            assert_eq!(self.next_uid, self.record_merkle_frontier.num_leaves());
        }

        self.record_merkle_root = self.record_merkle_frontier.get_root_value();
        self.prev_state = comm;
        Ok(ret)
    }
}

pub struct MultiXfrTestState {
    pub prng: ChaChaRng,

    pub univ_setup: &'static jf_txn::proof::UniversalParam,
    pub prove_key: ProverKey<'static>,
    pub verif_key: VerifierKey,

    pub native_token: AssetDefinition,

    pub keys: Vec<UserKeyPair>,
    pub freezer_key: FreezerKeyPair,

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

        let univ_setup = Box::leak(Box::new(jf_txn::proof::universal_setup(
            *[
                compute_universal_param_size(NoteType::Transfer, 3, 3, MERKLE_HEIGHT)?,
                compute_universal_param_size(NoteType::Mint, 0, 0, MERKLE_HEIGHT)?,
                compute_universal_param_size(NoteType::Freeze, 2, 2, MERKLE_HEIGHT)?,
            ]
            .iter()
            .max()
            .unwrap(),
            &mut prng,
        )?));
        let (xfr_prove_key, xfr_verif_key, _) =
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

        let freezer_key = FreezerKeyPair::generate(&mut prng);

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

        let first_root = t.get_root_value();

        let next_uid = owners.len() as u64;
        let nullifiers: SetMerkleTree = Default::default();
        let nullifiers_root = nullifiers.hash();

        let verif_key = VerifierKey {
            mint: TransactionVerifyingKey::Mint(mint_verif_key),
            xfr: TransactionVerifyingKey::Transfer(xfr_verif_key),
            freeze: TransactionVerifyingKey::Freeze(freeze_verif_key),
        };

        Self::update_timer(&mut timer, |t| println!("Verify Keys: {}s", t));

        let mut ret = Self {
            univ_setup,
            prng,
            prove_key: ProverKey {
                mint: mint_prove_key,
                xfr: xfr_prove_key,
                freeze: freeze_prove_key,
            },
            verif_key: verif_key.clone(),
            freezer_key,
            native_token,
            keys,
            fee_records,
            asset_seeds,
            asset_defs,
            owners,
            memos,
            nullifiers, /*asset_defs,*/
            record_merkle_tree: t.clone(),
            validator: ValidatorState {
                prev_commit_time: 0u64,
                prev_state: *state_comm::INITIAL_PREV_COMM,
                verif_crs: verif_key,
                record_merkle_root: first_root,
                record_merkle_frontier: t,
                nullifiers_root,
                next_uid,
                prev_block: Default::default(),
            },
            outer_timer: timer,
            inner_timer: Instant::now(),
        };

        let mut setup_block = ElaboratedBlock::next_block(&ret.validator);

        let mut keys_in_block = HashSet::<usize>::new();

        for (def_ix, key, amt) in std::iter::once(initial_records.0)
            .chain((initial_records.1).into_iter())
            .flat_map(|x| vec![x, x].into_iter())
            .map(|spec| (spec.asset_def_ix, spec.owner_key_ix, spec.asset_amount))
        {
            let amt = if amt < 2 { 2 } else { amt };
            let def_ix = def_ix as usize % ret.asset_defs.len();
            // We can't mint native tokens
            let def_ix = if def_ix < 1 { 1 } else { def_ix };
            let def = ret.asset_defs[def_ix].clone();
            let kix = key as usize % ret.keys.len();

            if keys_in_block.contains(&kix) {
                keys_in_block.clear();
                ret.validate_and_apply(core::mem::take(&mut setup_block), 0, 0, 0.0)
                    .unwrap();

                setup_block = ElaboratedBlock::next_block(&ret.validator);
            }
            keys_in_block.insert(kix);

            let key = &ret.keys[kix];

            let rec =
                RecordOpening::new(&mut ret.prng, amt, def, key.pub_key(), FreezeFlag::Unfrozen);

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
                let open_rec = memo.decrypt(&key, &comm, &[]).unwrap();
                let nullifier = key.nullify(&ret.freezer_key.pub_key(), fee_ix as u64, &comm);
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

            let (note, memos, _memos_sig, _change_ro) = MintNote::generate(
                &mut ret.prng,
                rec,
                ret.asset_seeds[def_ix - 1].0,
                &ret.asset_seeds[def_ix - 1].1,
                fee_input,
                1,
                &ret.prove_key.mint,
            )
            .unwrap();

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
                memos.to_vec(),
                vec![kix, kix],
            )
            .unwrap();
        }

        ret.validate_and_apply(core::mem::take(&mut setup_block), 0, 0, 0.0)
            .unwrap();

        Ok(ret)
    }

    /// Generates transactions with the specified block information.
    ///
    /// For each transaction `(rec1, rec2, key1, key2, diff)` in `block`,
    ///     takes the the records `rec1` and `rec2`, transfers them to `key1` and `key2`,
    ///     and tries to have the difference in value between the records be `diff`.
    ///
    /// Note: `round` and `num_txs` are for `println!`s only.
    // Issue: https://gitlab.com/translucence/systems/system/-/issues/16.
    #[allow(clippy::type_complexity)]
    pub fn generate_transactions(
        &mut self,
        round: usize,
        block: Vec<(u16, u16, u8, u8, i32)>,
        num_txs: usize,
    ) -> Result<
        Vec<(
            usize,
            (Vec<ReceiverMemo>, usize, usize),
            ElaboratedTransaction,
        )>,
        Box<dyn std::error::Error>,
    > {
        let splits = block
            .into_iter()
            .enumerate()
            .map(|x| ChaChaRng::from_rng(&mut self.prng).map(|y| (x, y)))
            .collect::<Result<Vec<_>, _>>()?;

        let mut txns = splits
            .into_par_iter()
            .map(|((ix, (in1, in2, k1, k2, amt_diff)), mut prng)| {
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

                    let open_rec = memo.decrypt(&key, &comm, &[]).unwrap();

                    let nullifier = key.nullify(&self.freezer_key.pub_key(), i as u64, &comm);
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
                            let open_rec = memo.decrypt(&key, &comm, &[]).unwrap();
                            let nullifier =
                                key.nullify(&self.freezer_key.pub_key(), fee_ix as u64, &comm);
                            assert!(!self.nullifiers.contains(nullifier).unwrap().0);
                            open_rec
                        }));
                        break;
                    }
                }

                // let owner_memos_key = schnorr::KeyPair::generate(&mut prng);

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

                    let open_rec = memo.decrypt(&key, &comm, &[]).unwrap();

                    if let Some((rec1, _)) = rec1.as_ref() {
                        // TODO: re-add support for this when jellyfish supports multi-assets
                        // transfers and/or exchanges
                        if rec1.asset_def != open_rec.asset_def {
                            continue;
                        }
                    }

                    let nullifier = key.nullify(&self.freezer_key.pub_key(), i as u64, &comm);
                    if !self.nullifiers.contains(nullifier).unwrap().0 {
                        in2 = i;
                        rec2 = Some((open_rec, kix));
                        break;
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

                let (txn, owner_memos, _owner_memos_sig) = TransferNote::generate_non_native(
                    &mut prng,
                    vec![input1, input2],
                    &[out_rec1, out_rec2],
                    fee_input,
                    1,
                    self.validator.prev_commit_time + 1,
                    &self.prove_key.xfr,
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

                Some((
                    ix,
                    (owner_memos, k1_ix, k2_ix),
                    ElaboratedTransaction {
                        txn: TransactionNote::Transfer(Box::new(txn)),
                        proofs: nullifier_pfs,
                    },
                ))
            })
            .filter_map(|x| x)
            .collect::<Vec<_>>();

        txns.sort_by(|(i, _, _), (j, _, _)| i.cmp(j));
        Ok(txns)
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

// TODO(joe): proper Err returns
#[cfg(test)]
mod tests {
    use super::*;
    // use jf_txn::proof::transfer::TransferProvingKey;
    use merkle_tree::LookupResult;
    use quickcheck::QuickCheck;

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

    fn test_multixfr(
        /* rec1,rec2 (0-indexed back in time),
         * key1, key2, diff in outputs (out1-out2) if diff
         * can't be achieved with those records, it will
         * saturate the other to zero.
         */
        txs: Vec<Vec<(u16, u16, u8, u8, i32)>>,
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
            for (ix, (owner_memos, k1_ix, k2_ix), txn) in txns {
                let _ = state.try_add_transaction(
                    &mut blk,
                    txn,
                    i,
                    ix,
                    num_txs,
                    owner_memos,
                    vec![k1_ix, k1_ix, k2_ix],
                );
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
            jf_txn::proof::transfer::preprocess(&univ_setup, 1, 1, MERKLE_HEIGHT).unwrap();
        let (mint_prove_key, mint_verif_key, _) =
            jf_txn::proof::mint::preprocess(&univ_setup, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_txn::proof::freeze::preprocess(&univ_setup, 2, MERKLE_HEIGHT).unwrap();

        let prove_key = ProverKey {
            mint: mint_prove_key,
            xfr: xfr_prove_key,
            freeze: freeze_prove_key,
        };

        let verif_key = VerifierKey {
            mint: TransactionVerifyingKey::Mint(mint_verif_key),
            xfr: TransactionVerifyingKey::Transfer(xfr_verif_key),
            freeze: TransactionVerifyingKey::Freeze(freeze_verif_key),
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
            ro: alice_rec1.clone(),
            owner_keypair: &alice_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: alice_rec_path.clone(),
                root: first_root.clone(),
                uid: 0,
            },
        };

        let mut wallet_merkle_tree = t.clone();
        let mut validator = ValidatorState {
            prev_commit_time: 0,
            prev_state: *state_comm::INITIAL_PREV_COMM,
            verif_crs: verif_key,
            record_merkle_root: first_root,
            record_merkle_frontier: t,
            nullifiers_root: nullifiers.hash(),
            next_uid: 1,
            prev_block: Default::default(),
        };

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
                /* valid_until:    */ 2,
                /* proving_key:    */ &prove_key.xfr,
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

        let new_uids = validator
            .validate_and_apply(
                1,
                Block(vec![TransactionNote::Transfer(Box::new(txn1))]),
                vec![nullifier_pfs],
            )
            .unwrap();

        println!(
            "Transfer validated & applied: {}s",
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        assert_eq!(&new_uids, &vec![1]);
        wallet_merkle_tree.push(RecordCommitment::from(&bob_rec));

        let bob_rec = TransferNoteInput {
            ro: bob_rec,
            owner_keypair: &bob_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: wallet_merkle_tree.get_leaf(1).expect_ok().unwrap().1,
                root: validator.record_merkle_frontier.get_root_value(),
                uid: 1,
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
            vec![vec![(0, 0, 0, 0, -2), (0, 0, 0, 0, 0)]],
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
