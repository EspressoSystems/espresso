#![deny(warnings)]
// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

use crate::state::*;
use crate::universal_params::UNIVERSAL_PARAM;
use arbitrary::Arbitrary;
use core::iter::once;
use hotshot::traits::{BlockContents, State};
use jf_cap::{
    keys::UserKeyPair,
    mint::MintNote,
    sign_receiver_memos,
    structs::{
        Amount, AssetCode, AssetCodeSeed, AssetDefinition, FeeInput, FreezeFlag, ReceiverMemo,
        RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    AccMemberWitness, MerkleTree, Signature, TransactionNote, TransactionVerifyingKey,
};
use key_set::{KeySet, ProverKeySet, VerifierKeySet};
use num_bigint::BigInt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use seahorse::txn_builder::RecordAmount;
use std::collections::HashSet;
use std::time::Instant;

#[derive(Debug)]
pub struct MultiXfrTestState {
    pub prng: ChaChaRng,

    pub univ_setup: &'static jf_cap::proof::UniversalParam,
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
    pub record_merkle_tree: MerkleTree,
    // pub asset_defs: Vec<AssetDefinition>,
    pub validator: ValidatorState,

    pub outer_timer: Instant,
    pub inner_timer: Instant,
}

/// Transaction Information for println! only
pub struct TxnPrintInfo {
    /// Round number.
    round: usize,
    /// Number of transactions.
    num_txs: usize,
    /// Time measurement, optional.
    now: Option<Instant>,
}

impl TxnPrintInfo {
    pub fn get_now(&self) -> Option<Instant> {
        self.now
    }

    /// Constructs all transaction information for println! only.
    pub fn new(round: usize, num_txs: usize, now: Instant) -> Self {
        Self {
            round,
            num_txs,
            now: Some(now),
        }
    }

    /// Constructs println! information with round number and the number of transactions.
    pub fn new_no_time(round: usize, num_txs: usize) -> Self {
        Self {
            round,
            num_txs,
            now: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum TestTxSpec {
    OneInput {
        rec: u16,
        key: u8,
    },
    TwoInput {
        rec0: u16,
        rec1: u16,
        key0: u8,
        key1: u8,
        diff: i32,
    },
}

impl TestTxSpec {
    fn into_tuple(self) -> (bool, u16, u16, u8, u8, i32) {
        match self {
            Self::OneInput { rec, key } => (false, rec, rec, key, key, 0),
            Self::TwoInput {
                rec0,
                rec1,
                key0,
                key1,
                diff,
            } => (true, rec0, rec1, key0, key1, diff),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl quickcheck::Arbitrary for TestTxSpec {
    fn shrink(&self) -> Box<(dyn Iterator<Item = TestTxSpec> + 'static)> {
        match self {
            Self::OneInput { rec, key } => Box::new(
                (*rec, *key)
                    .shrink()
                    .map(|(rec, key)| Self::OneInput { rec, key }),
            ),
            Self::TwoInput {
                rec0,
                rec1,
                key0,
                key1,
                diff,
            } => Box::new(
                once(Self::OneInput {
                    rec: *rec0,
                    key: *key0,
                })
                .chain(once(Self::OneInput {
                    rec: *rec1,
                    key: *key1,
                }))
                .chain((*rec0, *rec1, *key0, *key1, *diff).shrink().map(
                    |(rec0, rec1, key0, key1, diff)| Self::TwoInput {
                        rec0,
                        rec1,
                        key0,
                        key1,
                        diff,
                    },
                )),
            ),
        }
    }

    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        if <bool as quickcheck::Arbitrary>::arbitrary(g) {
            Self::OneInput {
                rec: quickcheck::Arbitrary::arbitrary(g),
                key: quickcheck::Arbitrary::arbitrary(g),
            }
        } else {
            Self::TwoInput {
                rec0: quickcheck::Arbitrary::arbitrary(g),
                rec1: quickcheck::Arbitrary::arbitrary(g),
                key0: quickcheck::Arbitrary::arbitrary(g),
                key1: quickcheck::Arbitrary::arbitrary(g),
                diff: quickcheck::Arbitrary::arbitrary(g),
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub struct MultiXfrRecordSpec {
    pub asset_def_ix: u8,
    pub owner_key_ix: u8,
    pub asset_amount: u64,
}

impl MultiXfrTestState {
    const MAX_AMOUNT: u64 = 10_000;

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

        #[cfg(target_os = "linux")]
        let bytes_per_page = procfs::page_size().unwrap() as u64;
        #[cfg(target_os = "linux")]
        println!("{} bytes per page", bytes_per_page);

        let fence = || std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        let report_mem = || {
            fence();
            #[cfg(target_os = "linux")]
            {
                let process_stats = procfs::process::Process::myself().unwrap().statm().unwrap();
                println!(
                    "{:.3}MiB | raw: {:?}",
                    ((process_stats.size * bytes_per_page) as f64) / ((1u64 << 20) as f64),
                    process_stats
                );
            }
            fence();
        };

        report_mem();

        fence();
        let univ_setup = &*UNIVERSAL_PARAM;
        fence();
        Self::update_timer(&mut timer, |t| {
            println!("Generated universal params: {}s", t)
        });

        report_mem();

        fence();
        let (xfr_prove_key_22, xfr_verif_key_22, _) =
            jf_cap::proof::transfer::preprocess(univ_setup, 2, 2, MERKLE_HEIGHT)?;
        fence();
        Self::update_timer(&mut timer, |t| println!("Generated xfr22: {}s", t));

        report_mem();

        fence();
        let (xfr_prove_key_33, xfr_verif_key_33, _) =
            jf_cap::proof::transfer::preprocess(univ_setup, 3, 3, MERKLE_HEIGHT)?;
        fence();
        Self::update_timer(&mut timer, |t| println!("Generated xfr33: {}s", t));

        fence();
        report_mem();
        let (mint_prove_key, mint_verif_key, _) =
            jf_cap::proof::mint::preprocess(univ_setup, MERKLE_HEIGHT)?;
        fence();
        Self::update_timer(&mut timer, |t| println!("Generated mint: {}s", t));

        report_mem();

        fence();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_cap::proof::freeze::preprocess(univ_setup, 2, MERKLE_HEIGHT)?;
        fence();
        Self::update_timer(&mut timer, |t| println!("Generated freeze: {}s", t));

        report_mem();

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
                AssetDefinition::new(AssetCode::new_domestic(*seed, desc), Default::default())
            }))
            .collect::<Result<Vec<_>, _>>()?;

        let mut owners = vec![];
        let mut memos = vec![];

        Self::update_timer(&mut timer, |t| println!("Keys and defs: {}s", t));

        let mut t = MerkleTree::new(MERKLE_HEIGHT).ok_or(ValidationError::Failed {})?;

        let mut fee_records = vec![];

        for key in 0..keys.len() as u8 {
            let amt = Amount::from(1u64 << 32);
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

            t.push(RecordCommitment::from(&rec).to_field_element());

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

        let mut setup_block = ret.validator.next_block();

        let mut keys_in_block = HashSet::<usize>::new();

        let mut to_add = std::iter::once(initial_records.0)
            .chain((initial_records.1).into_iter())
            .flat_map(|x| vec![x, x].into_iter())
            .map(|spec| (spec.asset_def_ix, spec.owner_key_ix, spec.asset_amount))
            .collect::<Vec<_>>();

        while !to_add.is_empty() {
            let mut this_block = vec![];
            for (def_ix, key, amt) in core::mem::take(&mut to_add).into_iter() {
                let amt = if amt < 2 { 2 } else { amt % Self::MAX_AMOUNT };
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
                    let amt = Amount::from(if amt < 2 { 2 } else { amt });
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
                        let comm = RecordCommitment::from_field_element(
                            ret.record_merkle_tree
                                .get_leaf(fee_ix as u64)
                                .expect_ok()
                                .unwrap()
                                .1
                                .leaf
                                .0,
                        );
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
                        ret.record_merkle_tree.commitment(),
                        ret.validator.record_merkle_commitment
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
                                .1
                                .path,
                            root: ret.validator.record_merkle_commitment.root_value,
                            uid: fee_ix,
                        },
                    };

                    let (fee_info, fee_out_rec) =
                        TxnFeeInfo::new(&mut prng, fee_input, Amount::from(1u64)).unwrap();

                    let memos = vec![
                        ReceiverMemo::from_ro(&mut prng, &fee_out_rec, &[]).unwrap(),
                        ReceiverMemo::from_ro(&mut prng, &rec, &[]).unwrap(),
                    ];

                    // NOTE: we don't check the receiver memos here, but
                    // there are other tests that rely on that behavior.
                    let (note, memo_kp) = MintNote::generate(
                        &mut prng,
                        rec,
                        ret.asset_seeds[def_ix - 1].0,
                        &ret.asset_seeds[def_ix - 1].1,
                        fee_info,
                        &ret.prove_keys.mint,
                    )
                    .unwrap();

                    (
                        kix,
                        note,
                        memos.clone(),
                        sign_receiver_memos(&memo_kp, &memos).unwrap(),
                    )
                })
                .collect::<Vec<_>>();

            for (kix, note, memos, signature) in txns {
                let nul = ret.nullifiers.contains(note.input_nullifier).unwrap().1;

                let ix = setup_block.block.0.len();
                ret.try_add_transaction(
                    &mut setup_block,
                    ElaboratedTransaction {
                        txn: TransactionNote::Mint(Box::new(note)),
                        proofs: vec![nul],
                        memos: memos.clone(),
                        signature,
                    },
                    ix,
                    memos,
                    vec![kix, kix],
                    TxnPrintInfo::new_no_time(0, 0),
                )
                .unwrap();
            }

            keys_in_block.clear();
            ret.validate_and_apply(
                core::mem::take(&mut setup_block),
                0.0,
                TxnPrintInfo::new_no_time(0, 0),
            )
            .unwrap();

            setup_block = ret.validator.next_block();
        }

        ret.validate_and_apply(
            core::mem::take(&mut setup_block),
            0.0,
            TxnPrintInfo::new_no_time(0, 0),
        )
        .unwrap();

        Ok(ret)
    }

    /// Generates transactions with the specified block information.
    ///
    /// For each transaction `(multi_input, rec1, rec2, key1, key2, diff, expire)` in `block`, takes
    ///     the records {rec1} or {rec1, rec2} (depending on the value of `multi_input`), transfers
    ///     them to `key1`, and, if `multi_input`, `key2`, and tries to have the difference in value
    ///     between the output records be `diff`.
    ///
    /// Returns vector of
    ///     index of transaction within block
    ///     (receiver memos, receiver indices)
    ///     receiver memos signature
    ///     transaction
    pub fn generate_transactions(
        &mut self,
        block: Vec<(TestTxSpec, bool)>,
        print_info: TxnPrintInfo,
    ) -> Result<Vec<MultiXfrRecordSpecTransaction>, Box<dyn std::error::Error>> {
        let splits = block
            .into_iter()
            .enumerate()
            .map(|x| ChaChaRng::from_rng(&mut self.prng).map(|y| (x, y)))
            .collect::<Result<Vec<_>, _>>()?;

        let mut txns = splits
            .into_par_iter()
            .map(|((ix, (tx_spec, expire)), mut prng)| {
                let (multi_input, in1, in2, k1, k2, amt_diff) = tx_spec.into_tuple();
                let now = Instant::now();

                println!("Txn {}.{}/{}", print_info.round + 1, ix, print_info.num_txs);

                let mut fee_rec = None;
                let mut rec1 = None;
                let mut rec2 = None;

                let mut in1 = in1 as usize % self.owners.len();
                let mut in2 = in2 as usize % self.owners.len();

                // NOTE: This is nearly the same as the loop below. If
                // you change either, change both (or refactor them
                // into a local closure called twice)
                for i in (0..(self.owners.len() - in1)).rev() {
                    let memo = &self.memos[i];
                    let kix = self.owners[i];
                    // it's their fee keystore
                    if i as u64 == self.fee_records[kix] {
                        continue;
                    }

                    let key = &self.keys[kix];

                    let comm = RecordCommitment::from_field_element(
                        self.record_merkle_tree
                            .get_leaf(i as u64)
                            .expect_ok()
                            .unwrap()
                            .1
                            .leaf
                            .0,
                    );

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
                            let comm = RecordCommitment::from_field_element(
                                self.record_merkle_tree
                                    .get_leaf(fee_ix as u64)
                                    .expect_ok()
                                    .unwrap()
                                    .1
                                    .leaf
                                    .0,
                            );
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
                        break;
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
                            ix,
                            expire,
                            TxnPrintInfo::new(print_info.round, print_info.num_txs, now),
                        );
                    }
                }

                // NOTE: This is nearly the same as the loop above. If
                // you change either, change both (or refactor them
                // into a local closure called twice)
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

                    let comm = RecordCommitment::from_field_element(
                        self.record_merkle_tree
                            .get_leaf(i as u64)
                            .expect_ok()
                            .unwrap()
                            .1
                            .leaf
                            .0,
                    );

                    let open_rec = memo.decrypt(key, &comm, &[]).unwrap();

                    if let Some((rec1, _)) = &rec1 {
                        if open_rec.asset_def != rec1.asset_def {
                            continue;
                        }
                    }

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
                                let comm = RecordCommitment::from_field_element(
                                    self.record_merkle_tree
                                        .get_leaf(fee_ix as u64)
                                        .expect_ok()
                                        .unwrap()
                                        .1
                                        .leaf
                                        .0,
                                );
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
                            ix,
                            expire,
                            TxnPrintInfo::new(print_info.round, print_info.num_txs, now),
                        );
                    }
                }

                if rec1.is_none() || rec2.is_none() {
                    println!(
                        "Txn {}.{}/{}: No records found, {}s",
                        print_info.round + 1,
                        ix,
                        print_info.num_txs,
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
                        let total = BigInt::from(u128::from(rec1.amount))
                            + BigInt::from(u128::from(rec2.amount));
                        let offset = BigInt::from(amt_diff) / BigInt::from(2u64);
                        let midval = total.clone() / BigInt::from(2u64);
                        let amt1 = midval + offset;
                        let amt1 = if amt1 < BigInt::from(1u64) {
                            BigInt::from(1u64)
                        } else if amt1 >= total {
                            total.clone() - BigInt::from(1u64)
                        } else {
                            amt1
                        };
                        let amt2 = total - amt1.clone();
                        (
                            RecordAmount::try_from(amt1).unwrap().into(),
                            RecordAmount::try_from(amt2).unwrap().into(),
                        )
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

                println!(
                    "Txn {}.{}/{} inputs chosen: {}s",
                    print_info.round + 1,
                    ix,
                    print_info.num_txs,
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
                            .1
                            .path,
                        root: self.validator.record_merkle_commitment.root_value,
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
                            .1
                            .path,
                        root: self.validator.record_merkle_commitment.root_value,
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
                            .1
                            .path,
                        root: self.validator.record_merkle_commitment.root_value,
                        uid: in2 as u64,
                    },
                };

                println!(
                    "Txn {}.{}/{} inputs generated: {}s",
                    print_info.round + 1,
                    ix,
                    print_info.num_txs,
                    now.elapsed().as_secs_f32()
                );
                let now = Instant::now();

                let (fee_info, fee_out_rec) =
                    TxnFeeInfo::new(&mut prng, fee_input, Amount::from(1u64)).unwrap();

                let owner_memos = vec![&fee_out_rec, &out_rec1, &out_rec2]
                    .into_iter()
                    .map(|r| ReceiverMemo::from_ro(&mut prng, r, &[]))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                let (txn, owner_memo_kp) = TransferNote::generate_non_native(
                    &mut prng,
                    vec![input1, input2],
                    &[out_rec1, out_rec2],
                    fee_info,
                    if expire {
                        self.validator.prev_commit_time + 1
                    } else {
                        2u64.pow(jf_cap::constants::MAX_TIMESTAMP_LEN as u32) - 1
                    },
                    self.prove_keys.xfr.key_for_size(3, 3).unwrap(),
                    vec![],
                )
                .unwrap();

                let sig = sign_receiver_memos(&owner_memo_kp, &owner_memos).unwrap();
                println!(
                    "Txn {}.{}/{} note generated: {}s",
                    print_info.round + 1,
                    ix,
                    print_info.num_txs,
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
                    print_info.round + 1,
                    ix,
                    print_info.num_txs,
                    now.elapsed().as_secs_f32()
                );

                assert_eq!(owner_memos.len(), 3);
                let keys_and_memos = vec![in_key1_ix, k1_ix, k2_ix]
                    .into_iter()
                    .zip(owner_memos.iter().cloned())
                    .collect();

                Some(MultiXfrRecordSpecTransaction {
                    index: ix,
                    keys_and_memos,
                    signature: sig.clone(),
                    transaction: ElaboratedTransaction {
                        txn: TransactionNote::Transfer(Box::new(txn)),
                        proofs: nullifier_pfs,
                        memos: owner_memos,
                        signature: sig,
                    },
                })
            })
            .filter_map(|x| x)
            .collect::<Vec<_>>();

        txns.sort_by(|left, right| left.index.cmp(&right.index));
        Ok(txns)
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_single_record_transfer(
        &self,
        prng: &mut ChaChaRng,
        rec_ix: usize,
        rec: RecordOpening,
        in_key_ix: usize,
        fee_rec: Option<(u64, RecordOpening)>,
        out_key_ix: u8,
        ix: usize,
        expire: bool,
        print_info: TxnPrintInfo,
    ) -> Option<MultiXfrRecordSpecTransaction> {
        if let Some(now) = print_info.now {
            println!(
                "Txn {}.{}/{} generating single-input transaction: {}s",
                print_info.round + 1,
                ix,
                print_info.num_txs,
                now.elapsed().as_secs_f32()
            );
        }
        let now = Instant::now();

        let in_key = &self.keys[in_key_ix];
        let (fee_ix, fee_rec) = fee_rec?;

        let out_key_ix = out_key_ix as usize % self.keys.len();
        let out_key = &self.keys[out_key_ix];

        assert_ne!(rec.amount, Amount::from(0u64));
        let out_rec1 = RecordOpening::new(
            prng,
            rec.amount,
            rec.asset_def.clone(),
            out_key.pub_key(),
            FreezeFlag::Unfrozen,
        );

        println!(
            "Txn {}.{}/{} inputs chosen: {}s",
            print_info.round + 1,
            ix,
            print_info.num_txs,
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
                    .1
                    .path,
                root: self.validator.record_merkle_commitment.root_value,
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
                    .1
                    .path,
                root: self.validator.record_merkle_commitment.root_value,
                uid: rec_ix as u64,
            },
        };

        println!(
            "Txn {}.{}/{} inputs generated: {}s",
            print_info.round + 1,
            ix,
            print_info.num_txs,
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        let (fee_info, fee_out_rec) = TxnFeeInfo::new(prng, fee_input, Amount::from(1u64)).unwrap();

        let owner_memos = vec![&fee_out_rec, &out_rec1]
            .into_iter()
            .map(|r| ReceiverMemo::from_ro(prng, r, &[]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let (txn, owner_memo_kp) = TransferNote::generate_non_native(
            prng,
            vec![input],
            &[out_rec1],
            fee_info,
            if expire {
                self.validator.prev_commit_time + 1
            } else {
                2u64.pow(jf_cap::constants::MAX_TIMESTAMP_LEN as u32) - 1
            },
            self.prove_keys.xfr.key_for_size(2, 2).unwrap(),
            vec![],
        )
        .unwrap();
        let sig = sign_receiver_memos(&owner_memo_kp, &owner_memos).unwrap();

        println!(
            "Txn {}.{}/{} inputs generated: {}s",
            print_info.round + 1,
            ix,
            print_info.num_txs,
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
            print_info.round + 1,
            ix,
            print_info.num_txs,
            now.elapsed().as_secs_f32()
        );

        assert_eq!(owner_memos.len(), 2);
        let keys_and_memos = vec![in_key_ix, out_key_ix]
            .into_iter()
            .zip(owner_memos.iter().cloned())
            .collect();

        Some(MultiXfrRecordSpecTransaction {
            index: ix,
            keys_and_memos,
            signature: sig.clone(),
            transaction: ElaboratedTransaction {
                txn: TransactionNote::Transfer(Box::new(txn)),
                proofs: nullifier_pfs,
                memos: owner_memos,
                signature: sig,
            },
        })
    }

    /// Tries to add a transaction to a block.
    #[allow(clippy::too_many_arguments)]
    pub fn try_add_transaction(
        &mut self,
        blk: &mut ElaboratedBlock,
        mut txn: ElaboratedTransaction,
        ix: usize,
        owner_memos: Vec<ReceiverMemo>,
        kixs: Vec<usize>,
        print_info: TxnPrintInfo,
    ) -> Result<(), ValidationError> {
        println!(
            "Block {}/{} trying to add {:?}",
            print_info.round + 1,
            print_info.num_txs,
            ix
        );
        txn.memos = owner_memos.clone();

        let base_ix = self.record_merkle_tree.num_leaves()
            + blk
                .block
                .0
                .iter()
                .map(|x| x.output_commitments().len() as u64)
                .sum::<u64>();
        let newblk = blk.add_transaction_raw(&txn)?;
        println!(
            "Block {}/{:?} adding {:?}",
            print_info.round + 1,
            print_info.num_txs,
            ix
        );
        self.memos.extend(owner_memos);
        self.fee_records[kixs[0]] = base_ix;
        self.owners.extend(kixs);

        *blk = newblk;
        Ok(())
    }

    /// Validates and applys a block.
    pub fn validate_and_apply(
        &mut self,
        blk: ElaboratedBlock,
        generation_time: f32,
        print_info: TxnPrintInfo,
    ) -> Result<(), ValidationError> {
        Self::update_timer(&mut self.inner_timer, |_| ());

        self.validator.validate_block_check(
            self.validator.prev_commit_time + 1,
            blk.block.clone(),
            blk.proofs.clone(),
        )?;
        let new_state = self.validator.append(&blk).unwrap();

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
            self.record_merkle_tree.push(comm.to_field_element());
        }

        self.validator = new_state;

        let mut checking_time: f32 = 0.0;
        Self::update_timer(&mut self.inner_timer, |t| {
            checking_time = t;
        });

        Self::update_timer(&mut self.outer_timer, |t| {
            println!(
                "Block {}/{}: {} transactions, {}s ({}s generation, {}s checking)",
                print_info.round + 1,
                print_info.num_txs,
                blk.block.0.len(),
                t,
                generation_time,
                checking_time
            )
        });

        assert_eq!(self.nullifiers.hash(), self.validator.nullifiers_root());
        Ok(())
    }

    pub fn unspent_memos(&self) -> Vec<(ReceiverMemo, u64)> {
        self.memos
            .iter()
            .enumerate()
            .filter_map(|(uid, memo)| {
                let owner = self.owners[uid];
                let key = &self.keys[owner];
                let comm = RecordCommitment::from_field_element(
                    self.record_merkle_tree
                        .get_leaf(uid as u64)
                        .expect_ok()
                        .unwrap()
                        .1
                        .leaf
                        .0,
                );
                let ro = memo.decrypt(key, &comm, &[]).unwrap();
                let nullifier = key.nullify(
                    ro.asset_def.policy_ref().freezer_pub_key(),
                    uid as u64,
                    &comm,
                );
                let spent = self.nullifiers.contains(nullifier).unwrap().0;
                if spent {
                    None
                } else {
                    Some((memo.clone(), uid as u64))
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct MultiXfrRecordSpecTransaction {
    pub index: usize,
    pub keys_and_memos: Vec<(usize, ReceiverMemo)>,
    pub signature: Signature,
    pub transaction: ElaboratedTransaction,
}

pub fn crypto_rng() -> ChaChaRng {
    ChaChaRng::from_entropy()
}

pub fn crypto_rng_from_seed(seed: [u8; 32]) -> ChaChaRng {
    ChaChaRng::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::canonical::CanonicalBytes;
    use commit::Committable;
    use jf_cap::structs::{NoteType, Nullifier};
    use jf_cap::{utils::compute_universal_param_size, BaseField, MerkleLeafProof, NodeValue};
    use jf_primitives::merkle_tree::LookupResult;
    use quickcheck::QuickCheck;
    use rand::{Rng, RngCore};
    use std::cmp::min;

    #[test]
    fn multixfr_setup() {
        let state = MultiXfrTestState::initialize(
            [0x7au8; 32],
            10,
            10,
            (
                MultiXfrRecordSpec {
                    asset_def_ix: 0,
                    owner_key_ix: 0,
                    asset_amount: 10,
                },
                vec![],
            ),
        )
        .unwrap();

        std::thread::sleep(core::time::Duration::from_millis(60000));

        if rand::thread_rng().gen::<u64>() == 0 {
            println!("{:?}", state)
        }
    }

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
    fn test_multixfr(
        /*
         * multi_input (if false, generates smaller transaction and rec2 is ignored),
         * rec1,rec2 (0-indexed back in time),
         * key1, key2, diff in outputs (out1-out2) if diff
         * can't be achieved with those records, it will
         * saturate the other to zero.
         */
        txs: Vec<Vec<TestTxSpec>>,
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
            assert_eq!(state.validator.nullifiers_root(), state.nullifiers.hash());
            MultiXfrTestState::update_timer(&mut state.outer_timer, |_| {
                println!(
                    "Block {}/{}, {} candidate txns",
                    i + 1,
                    num_txs,
                    block.len()
                )
            });

            // let block = block.into_iter().take(5).collect::<Vec<_>>();
            let txns = state
                .generate_transactions(
                    block.into_iter().map(|tx| (tx, true)).collect(),
                    TxnPrintInfo::new_no_time(i, num_txs),
                )
                .unwrap();

            let mut generation_time: f32 = 0.0;
            MultiXfrTestState::update_timer(&mut state.outer_timer, |t| {
                generation_time = t;
                println!("Block {}/{} txns generated: {}s", i + 1, num_txs, t)
            });

            let mut blk = ElaboratedBlock::default();
            for tx in txns {
                let (owner_memos, kixs) = {
                    let mut owner_memos = vec![];
                    let mut kixs = vec![];

                    for (kix, memo) in tx.keys_and_memos {
                        kixs.push(kix);
                        owner_memos.push(memo);
                    }
                    (owner_memos, kixs)
                };

                let _ = state.try_add_transaction(
                    &mut blk,
                    tx.transaction,
                    tx.index,
                    owner_memos,
                    kixs,
                    TxnPrintInfo::new_no_time(i, num_txs),
                );
            }

            state
                .validate_and_apply(blk, generation_time, TxnPrintInfo::new_no_time(i, num_txs))
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

        let univ = jf_cap::proof::universal_setup(
            compute_universal_param_size(NoteType::Transfer, 1, 1, MERKLE_HEIGHT).unwrap(),
            &mut prng,
        )
        .unwrap();
        let (_prove, _verif, _constraint_count) =
            jf_cap::proof::transfer::preprocess(&univ, 1, 1, MERKLE_HEIGHT).unwrap();

        println!("CRS set up");
    }

    #[test]
    fn test_verifier_key_commit_hash() {
        // Check that ValidatorStates with different verify_crs have different commits.
        println!("generating universal parameters");

        let univ = &*UNIVERSAL_PARAM;
        let (_, mint, _) = jf_cap::proof::mint::preprocess(univ, MERKLE_HEIGHT).unwrap();
        let (_, xfr11, _) = jf_cap::proof::transfer::preprocess(univ, 1, 1, MERKLE_HEIGHT).unwrap();
        let (_, xfr22, _) = jf_cap::proof::transfer::preprocess(univ, 2, 2, MERKLE_HEIGHT).unwrap();
        let (_, freeze2, _) = jf_cap::proof::freeze::preprocess(univ, 2, MERKLE_HEIGHT).unwrap();
        let (_, freeze3, _) = jf_cap::proof::freeze::preprocess(univ, 3, MERKLE_HEIGHT).unwrap();
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
        println!("generating universal parameters");

        let univ = &*UNIVERSAL_PARAM;
        let (_, mint, _) = jf_cap::proof::mint::preprocess(univ, MERKLE_HEIGHT).unwrap();
        let (_, xfr, _) = jf_cap::proof::transfer::preprocess(univ, 1, 1, MERKLE_HEIGHT).unwrap();
        let (_, freeze, _) = jf_cap::proof::freeze::preprocess(univ, 2, MERKLE_HEIGHT).unwrap();
        println!("CRS set up");

        let verif_crs = VerifierKeySet {
            mint: TransactionVerifyingKey::Mint(mint),
            xfr: KeySet::new(vec![TransactionVerifyingKey::Transfer(xfr)].into_iter()).unwrap(),
            freeze: KeySet::new(vec![TransactionVerifyingKey::Freeze(freeze)].into_iter()).unwrap(),
        };
        let mut v1 = ValidatorState::new(verif_crs, MerkleTree::new(MERKLE_HEIGHT).unwrap());
        let mut v2 = v1.clone();

        // Test validators with different history lengths.
        v1.past_record_merkle_roots.0.push_front(NodeValue::from(0));
        assert_ne!(v1.commit(), v2.commit());

        // Test validators with the same length, but different histories.
        v2.past_record_merkle_roots.0.push_front(NodeValue::from(1));
        assert_ne!(v1.commit(), v2.commit());
    }

    // Test historical nullifier verification. Builds two transactions against the same state but
    // submits them in two sequential blocks, so that the second transaction must be validated
    // against a historical nullifier set.
    //
    // If `double_spend`, both transactions try to spend the same nullifier, so the second one
    // should fail. This tests that validation correctly distinguishes between historical and
    // invalid nullifier proofs.
    fn test_sliding_nullifiers(double_spend: bool) {
        let mut state = MultiXfrTestState::initialize(
            [0x7au8; 32],
            2,
            1,
            (
                MultiXfrRecordSpec {
                    asset_def_ix: 1,
                    owner_key_ix: 0,
                    asset_amount: 1,
                },
                vec![MultiXfrRecordSpec {
                    asset_def_ix: 1,
                    owner_key_ix: 1,
                    asset_amount: 1,
                }],
            ),
        )
        .unwrap();

        // Generate 2 transfers at the same time.
        let txns = state
            .generate_transactions(
                vec![
                    (TestTxSpec::OneInput { rec: 0, key: 1 }, true),
                    (
                        TestTxSpec::OneInput {
                            rec: if double_spend { 0 } else { 2 },
                            key: 1,
                        },
                        false,
                    ),
                ],
                TxnPrintInfo::new_no_time(0, 2),
            )
            .unwrap();
        // Submit the transactions in two separate blocks, so that the second one is validated
        // against an updated nullifier set.
        for (i, tx) in txns.into_iter().enumerate() {
            let (owner_memos, kixs) = {
                let mut owner_memos = vec![];
                let mut kixs = vec![];

                for (kix, memo) in tx.keys_and_memos {
                    kixs.push(kix);
                    owner_memos.push(memo);
                }
                (owner_memos, kixs)
            };

            let mut blk = ElaboratedBlock::default();
            let _ = state.try_add_transaction(
                &mut blk,
                tx.transaction,
                tx.index,
                owner_memos,
                kixs,
                TxnPrintInfo::new_no_time(i, 2),
            );
            let res = state.validate_and_apply(blk, 0.0, TxnPrintInfo::new_no_time(i, 2));
            if i == 0 || !double_spend {
                res.unwrap();
            } else {
                res.unwrap_err();
            }
        }
    }

    #[test]
    fn test_sliding_nullifiers_valid() {
        test_sliding_nullifiers(false);
    }

    #[test]
    fn test_sliding_nullifiers_double_spend() {
        test_sliding_nullifiers(true);
    }

    #[test]
    #[allow(unused_variables)]
    fn test_2user() {
        let now = Instant::now();

        println!("generating params");

        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);

        let univ_setup = &*UNIVERSAL_PARAM;

        let (xfr_prove_key, xfr_verif_key, _) =
            jf_cap::proof::transfer::preprocess(univ_setup, 1, 2, MERKLE_HEIGHT).unwrap();
        let (mint_prove_key, mint_verif_key, _) =
            jf_cap::proof::mint::preprocess(univ_setup, MERKLE_HEIGHT).unwrap();
        let (freeze_prove_key, freeze_verif_key, _) =
            jf_cap::proof::freeze::preprocess(univ_setup, 2, MERKLE_HEIGHT).unwrap();

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
            Amount::from(2u64),
            coin.clone(),
            alice_key.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let alice_rec1 = alice_rec_builder;

        let mut t = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        assert_eq!(
            t.commitment(),
            MerkleTree::new(MERKLE_HEIGHT).unwrap().commitment()
        );
        let alice_rec_elem = RecordCommitment::from(&alice_rec1);
        // dbg!(&RecordCommitment::from(&alice_rec1));
        assert_eq!(
            RecordCommitment::from(&alice_rec1),
            RecordCommitment::from(&alice_rec1)
        );
        t.push(RecordCommitment::from(&alice_rec1).to_field_element());
        let alice_rec_path = t.get_leaf(0).expect_ok().unwrap().1.path;
        assert_eq!(alice_rec_path.nodes.len(), MERKLE_HEIGHT as usize);

        let mut nullifiers: SetMerkleTree = Default::default();

        println!("Tree set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let first_root = t.commitment().root_value;

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

        let mut keystore_merkle_tree = t.clone();
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
            validator.record_merkle_commitment.root_value,
            0,
            &MerkleLeafProof::new(alice_rec_elem.to_field_element(), alice_rec_path),
        )
        .unwrap();

        println!("Path checked: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let ((txn1, _, _), bob_rec) = {
            let bob_rec = RecordOpening::new(
                &mut prng,
                /* 1 less, for the transaction fee */
                Amount::from(1u64),
                coin,
                bob_key.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let txn = TransferNote::generate_native(
                &mut prng,
                /* inputs:         */ vec![alice_rec_final],
                /* outputs:        */ &[bob_rec.clone()],
                /* fee:            */ Amount::from(1u64),
                /* valid_until:    */ 2,
                /* proving_key:    */ prove_keys.xfr.key_for_size(1, 2).unwrap(),
            )
            .unwrap();
            (txn, bob_rec)
        };

        println!("Transfer has {} outputs", txn1.output_commitments.len());
        println!(
            "Transfer is {} bytes long",
            canonical::serialize(&txn1).unwrap().len()
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
            )
            .unwrap()
            .0;

        println!(
            "Transfer validated & applied: {}s",
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        assert_eq!(&new_uids[1..], &[2]);
        for r in new_recs {
            keystore_merkle_tree.push(r.to_field_element());
        }

        let bob_rec = TransferNoteInput {
            ro: bob_rec,
            owner_keypair: &bob_key,
            cred: None,
            acc_member_witness: AccMemberWitness {
                merkle_path: keystore_merkle_tree.get_leaf(2).expect_ok().unwrap().1.path,
                root: validator.record_merkle_commitment.root_value,
                uid: 2,
            },
        };

        assert_eq!(nullifiers.hash(), validator.nullifiers_root());

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
            MerkleTree::new(MERKLE_HEIGHT).unwrap(),
            MerkleTree::new(MERKLE_HEIGHT).unwrap(),
        );
        for t in [&mut t1, &mut t2].iter_mut() {
            let mut map = Vec::new();
            for u in updates.iter() {
                match u {
                    Ok(val) => {
                        map.push(val);

                        t.push(BaseField::from(pow3(*val)));

                        // check_path(t.hasher.as_ref(), &path.unwrap(), &leaf_val,
                        //         &leaf_hash, MERKLE_HEIGHT, &t.root_hash)
                        //     .expect("Merkle3Tree generated an invalid proof");

                        // assert_eq!(old_val,old_tree_val.map(|x| x.1));
                    }
                    Err(i) => {
                        match (
                            map.get(*i).cloned().map(|x| BaseField::from(pow3(*x))),
                            t.get_leaf(*i as u64),
                        ) {
                            (None, LookupResult::EmptyLeaf) => {}
                            (Some(map_val), LookupResult::Ok(_tree_val, tree_proof)) => {
                                // assert_eq!(map_val,tree_val);
                                MerkleTree::check_proof(
                                    t.commitment().root_value,
                                    *i as u64,
                                    &MerkleLeafProof::new(map_val, tree_proof.path),
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

        assert_eq!(t1.commitment(), t2.commitment());
    }

    #[test]
    fn quickcheck_multixfr_regression1() {
        test_multixfr(vec![vec![]], 0, 0, (0, 0, 0), vec![])
    }
    #[test]
    fn quickcheck_multixfr_regression2() {
        test_multixfr(
            vec![vec![
                TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: -2,
                },
                TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: 0,
                },
            ]],
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
        test_multixfr(
            vec![vec![TestTxSpec::TwoInput {
                rec0: 3,
                rec1: 0,
                key0: 0,
                key1: 0,
                diff: 0,
            }]],
            0,
            0,
            (0, 0, 0),
            vec![],
        )
    }

    #[test]
    fn quickcheck_multixfr_regression5() {
        test_multixfr(
            vec![
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 1,
                    key1: 1,
                    diff: 0,
                }],
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 0,
                    key0: 0,
                    key1: 0,
                    diff: 0,
                }],
            ],
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
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
                vec![TestTxSpec::OneInput { rec: 0, key: 1 }],
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
            vec![
                vec![TestTxSpec::TwoInput {
                    rec0: 0,
                    rec1: 1,
                    key0: 1,
                    key1: 1,
                    diff: 0,
                }],
                vec![TestTxSpec::OneInput { rec: 5, key: 1 }],
            ],
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

    /// Apply a sequence of blocks of nullifiers to a [NullifierHistory], making a set of
    /// consistency checks at each step along the way.
    ///
    /// `blocks` should be a sequence of blocks. Each block is specified as a list of _proof ages_.
    /// The proof age for a nullifier is the number of blocks which have been committed since the
    /// state with the nullifier set used to create the proof. The test will adjust each age to
    /// avoid overflows, so these can be randomly generated.
    ///
    /// For this test, each block should be non-empty (hence the type `(usize, Vec<usize>)` to
    /// ensure there is at least one nullifier in each block).
    fn test_nullifier_history(seed: u64, blocks: Vec<(usize, Vec<usize>)>) {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        // Past nullifier sets. Each of these Merkle trees is complete -- it contains leaves for
        // each nullifier in the set.
        let mut nullifier_sets = vec![SetMerkleTree::default()];
        // Spent nullifiers and the proofs that were used to spend them.
        let mut spent_nullifiers = vec![];
        // Our sliding window of recent nullifiers.
        let mut history = NullifierHistory::default();
        for (age, ages) in blocks {
            let mut nullifier_proofs = NullifierProofs::default();
            for proof_age in once(age).chain(ages) {
                // Use a proof that might be old, but is no older than the sliding window size or
                // the size of all of history.
                let proof_age =
                    proof_age % min(ValidatorState::HISTORY_SIZE + 1, nullifier_sets.len());
                // Generate a random, fresh nullifier.
                let n = Nullifier::random_for_test(&mut rng);
                // Find a recent nullifier set to generate the proof.
                let set = &nullifier_sets[nullifier_sets.len() - 1 - proof_age];
                let (contains, proof) = set.contains(n).unwrap();
                assert!(!contains);
                nullifier_proofs.push((n, proof, set.hash()));
            }

            // Check the proofs.
            let recent_nullifiers = history.recent_nullifiers();
            for (n, proof, root) in &nullifier_proofs {
                assert_eq!(
                    *root,
                    history
                        .check_unspent(&recent_nullifiers, proof, *n)
                        .unwrap()
                );
            }

            if nullifier_sets.len() > ValidatorState::HISTORY_SIZE + 1 {
                // Check that a proof which is too old fails to validate.
                let n = Nullifier::random_for_test(&mut rng);
                let set =
                    &nullifier_sets[nullifier_sets.len() - 1 - ValidatorState::HISTORY_SIZE - 1];
                let proof = set.contains(n).unwrap().1;
                assert!(matches!(
                    history
                        .check_unspent(&recent_nullifiers, &proof, n)
                        .unwrap_err(),
                    ValidationError::BadNullifierProof {},
                ));
            }

            // Check that past nullifiers fail to validate.
            for (n, proof) in &spent_nullifiers {
                history
                    .check_unspent(&recent_nullifiers, proof, *n)
                    .unwrap_err();
            }

            // Insert the new nullifiers and make sure the commitment changes.
            let prev_commit = history.commit();
            let collected_proofs = history.append_block(nullifier_proofs.clone()).unwrap();
            assert_ne!(prev_commit, history.commit());

            // Check that it returned all the expected proofs.
            for (n, _, _) in &nullifier_proofs {
                let (contains, _proof) = collected_proofs.contains(*n).unwrap();
                assert!(!contains);
            }

            // Generate the new nullifiers set by inserting all of the new nullifiers.
            let mut set = nullifier_sets.last().unwrap().clone();
            for (n, proof, _) in nullifier_proofs.into_iter() {
                set.insert(n).unwrap();
                spent_nullifiers.push((n, proof));
            }
            assert_eq!(set.hash(), history.current_root());
            nullifier_sets.push(set);
        }
    }

    #[test]
    fn test_nullifier_history_small() {
        let mut rng = ChaChaRng::from_seed([1; 32]);
        let blocks = (0..2 * ValidatorState::HISTORY_SIZE)
            .into_iter()
            .map(|_| {
                let block_size = rng.next_u64() % 100;
                (
                    rng.next_u64() as usize,
                    (0..block_size)
                        .into_iter()
                        .map(|_| rng.next_u64() as usize)
                        .collect(),
                )
            })
            .collect();
        test_nullifier_history(rng.next_u64(), blocks);
    }

    #[cfg(feature = "slow-tests")]
    #[test]
    fn quickcheck_nullifier_history() {
        QuickCheck::new()
            .tests(5)
            .quickcheck(test_nullifier_history as fn(u64, Vec<_>) -> ());
    }

    /// Test that applying equivalent blocks to the same [NullifierHistory] yields equal histories
    /// with equal commitments. The blocks can have different nullifier proofs -- as long as the
    /// nullifiers in both blocks are the same and all of the proofs are acceptable, they can be
    /// relative to different historical root hashes, and the blocks are still equivalent.
    ///
    /// `blocks` is a sequence of non-empty lists of nullifier proof ages, similar to the format
    /// accepted by `test_nullifier_history`, except that each proof has a pair of ages. This
    /// defines two equivalent blocks which differ in the ages of their nullifier proofs. The test
    /// applies each sequence of blocks to the same initial state, checking at each step that the
    /// states and their commitments are equal.
    fn test_nullifier_history_commitment(
        seed: u64,
        blocks: Vec<((usize, usize), Vec<(usize, usize)>)>,
    ) {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        // Past nullifier sets. Each of these Merkle trees is complete -- it contains leaves for
        // each nullifier in the set.
        let mut nullifier_sets = vec![SetMerkleTree::default()];
        // Our sliding windows of recent nullifiers. These should always remain equal.
        let mut history1 = NullifierHistory::default();
        let mut history2 = NullifierHistory::default();
        for (age, ages) in blocks {
            let mut proofs1 = NullifierProofs::default();
            let mut proofs2 = NullifierProofs::default();
            for (age1, age2) in once(age).chain(ages) {
                // Generate a random, fresh nullifier.
                let n = Nullifier::random_for_test(&mut rng);
                for (age, proofs) in [(age1, &mut proofs1), (age2, &mut proofs2)] {
                    // Use a proof that might be old, but is no older than the sliding window size
                    // or the size of all of history.
                    let age = age % min(ValidatorState::HISTORY_SIZE + 1, nullifier_sets.len());
                    // Find a recent nullifier set to generate the proof.
                    let set = &nullifier_sets[nullifier_sets.len() - 1 - age];
                    let (contains, proof) = set.contains(n).unwrap();
                    assert!(!contains);
                    proofs.push((n, proof, set.hash()));
                }
            }

            // Insert the new nullifiers and make sure the effect on both histories is the same.
            history1.append_block(proofs1.clone()).unwrap();
            history2.append_block(proofs2).unwrap();
            assert_eq!(history1, history2);
            assert_eq!(history1.commit(), history2.commit());

            // Generate the new nullifiers set by inserting all of the new nullifiers.
            let mut set = nullifier_sets.last().unwrap().clone();
            for (n, _, _) in proofs1.into_iter() {
                set.insert(n).unwrap();
            }
            assert_eq!(set.hash(), history1.current_root());
            assert_eq!(set.hash(), history2.current_root());
            nullifier_sets.push(set);
        }
    }

    #[test]
    fn test_nullifier_history_commitment_regression() {
        test_nullifier_history_commitment(0, vec![((0, 0), vec![]), ((0, 0), vec![(1, 0)])]);
    }

    #[cfg(feature = "slow-tests")]
    #[test]
    fn quickcheck_nullifier_history_commitment() {
        QuickCheck::new()
            .tests(5)
            .quickcheck(test_nullifier_history_commitment as fn(u64, Vec<_>) -> ());
    }
}
