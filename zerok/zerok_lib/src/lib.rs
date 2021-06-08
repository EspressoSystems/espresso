#![deny(warnings)]

mod set_merkle_tree;
mod util;

use core::fmt::Debug;
use hotstuff::BlockContents;
use jf_primitives::merkle_tree;
use jf_txn::errors::TxnApiError;
use jf_txn::keys::UserKeyPair;
use jf_txn::proof::transfer::TransferVerifyingKey;
use jf_txn::structs::{CommitmentValue, Nullifier, ReceiverMemo, RecordCommitment};
use jf_txn::transfer::TransferNote;
use jf_utils::serialize::CanonicalBytes;
use serde::{Deserialize, Serialize};
pub use set_merkle_tree::*;

pub const MERKLE_HEIGHT: usize = 20 /*H*/;

// TODO
pub struct LedgerRecordCommitment(pub RecordCommitment);

// TODO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Transaction(pub TransferNote);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ElaboratedTransaction {
    pub txn: Transaction,
    pub proofs: Vec<SetMerkleProof>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Block(pub Vec<Transaction>);

// A block with nullifier set non-membership proofs
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ElaboratedBlock {
    pub block: Block,
    pub proofs: Vec<Vec<SetMerkleProof>>,
}

impl BlockContents for ElaboratedBlock {
    type State = ValidatorState;
    type Transaction = ElaboratedTransaction;
    type Error = ValidationError;

    fn add_transaction(
        &self,
        _state: &ValidatorState,
        txn: &ElaboratedTransaction,
    ) -> Result<Self, ValidationError> {
        // TODO: testing for nullifiers is not going to be straightforward. Need to talk to crypto team.

        let mut ret = self.clone();

        // TODO: collect nullifiers once we have an accessible transaction API

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

    fn hash(&self) -> [u8; 32] {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "ElaboratedBlock Hash".as_bytes());
        hasher.update(&"Block contents".as_bytes());
        hasher.update(&block_comm::block_commit(&self.block));
        hasher.update(&"Block proofs".as_bytes());
        hasher.update(&serde_json::to_string(&self.proofs).unwrap().as_bytes());
        hasher
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    }

    fn hash_transaction(txn: &ElaboratedTransaction) -> [u8; 32] {
        use blake2::crypto_mac::Mac;
        use std::convert::TryInto;
        let mut hasher =
            blake2::Blake2b::with_params(&[], &[], "ElaboratedTransaction Hash".as_bytes());
        hasher.update(&"Txn contents".as_bytes());
        hasher.update(&txn_comm::txn_commit(&txn.txn));
        hasher.update(&"Txn proofs".as_bytes());
        hasher.update(&serde_json::to_string(&txn.proofs).unwrap().as_bytes());
        hasher
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    }
}

// TODO
#[derive(Debug)]
pub enum ValidationError {
    NullifierAlreadyExists(Nullifier),
    BadNullifierProof(),
    MissingNullifierProof(),
    ConflictingNullifiers(),
    Failed(),
    BadMerkleLength(),
    BadMerkleLeaf(),
    BadMerkleRoot(),
    BadMerklePath(),
    CryptoError(TxnApiError),
}

mod verif_crs_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type VerifCRSCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn verif_crs_commit(p: &TransferVerifyingKey) -> VerifCRSCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "VerifCRS Comm".as_bytes());
        hasher.update(&serde_json::to_string(p).unwrap().as_bytes());
        hasher.finalize().into_bytes()
    }
}

mod txn_comm {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    pub type TxnCommitment = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    pub fn txn_commit(p: &Transaction) -> TxnCommitment {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "Txn Comm".as_bytes());
        hasher.update(&jf_utils::serialize::CanonicalBytes::from(p.0.clone()).0);
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
    pub verif_crs: TransferVerifyingKey,
    pub record_merkle_root: merkle_tree::NodeValue,
    pub record_merkle_frontier: merkle_tree::MerkleTree,
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
        dbg!(&inputs);
        inputs.commit()
    }

    pub fn validate_block(
        &self,
        _now: u64,
        txns: Block,
        null_pfs: Vec<Vec<SetMerkleProof>>,
    ) -> Result<(Block, Vec<Vec<SetMerkleProof>>), ValidationError> {
        Ok((txns, null_pfs))
    }

    pub fn validate_and_apply(
        &mut self,
        now: u64,
        txns: Block,
        null_pfs: Vec<Vec<SetMerkleProof>>,
    ) -> Result<Vec<u64> /* new uids */, ValidationError> {
        let (txns, _null_pfs) = self.validate_block(now, txns, null_pfs.clone())?;
        let _comm = self.commit();
        self.prev_commit_time = now;
        self.prev_block = txns.clone();

        // TODO: getting this working requires getting something into the txn that allows nullifiers to be extracted.

        let nullifiers = txns
            .0
            .iter()
            .zip(null_pfs.into_iter())
            .flat_map(|(txn, null_pfs)| {
                txn.0
                    .inputs_nullifiers
                    .iter()
                    .cloned()
                    .zip(null_pfs.into_iter())
            })
            .collect();

        self.nullifiers_root = set_merkle_lw_multi_insert(nullifiers, self.nullifiers_root)
            .map_err(|_| ValidationError::BadNullifierProof())?
            .0;

        // TODO: make mut when we have working txn contents
        let mut ret = vec![];
        for o in txns.0.iter().flat_map(|x| x.0.output_commitments.iter()) {
            let uid = self.next_uid;
            self.record_merkle_frontier.insert(&(*o).into());
            ret.push(uid);
            self.next_uid += 1;
            assert_eq!(
                self.next_uid as usize,
                self.record_merkle_frontier.num_leaves()
            );
        }

        // self.record_merkle_root = self.record_merkle_frontier.get_root_value();
        // self.prev_state = comm;
        Ok(ret)
    }
}

pub struct TestState {
    pub keys: Vec<UserKeyPair>,
    pub owners: Vec<usize>, // for each record
    pub memos: Vec<ReceiverMemo>,
    pub nullifiers: SetMerkleTree,
    pub record_merkle_vec: Vec<CommitmentValue>,
    // pub asset_defs: Vec<AssetDefinition>,
    pub validator: ValidatorState,
}

// TODO(joe): proper Err returns
#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    // use rayon::prelude::*;
    use std::time::Instant;
    // use jf_txn::proof::transfer::TransferProvingKey;
    use jf_txn::structs::{AssetCode, AssetDefinition, FreezeFlag, RecordOpening};
    use merkle_tree::{AccMemberWitness, MerkleTree, MerkleTreeElem};
    // use jf_txn::parameters::CacheableProverSrs;
    use ark_ff::Field;
    use ark_ff::UniformRand;
    use jf_txn::transfer::TransferNoteInput;
    use merkle_tree::NodeValue;

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
        let now = Instant::now();
        let file_name = format!("setup_params_2x2_mh{}", MERKLE_HEIGHT);
        println!("loading params from file {}", &file_name);

        let user_params =
            TransferProverCRS::from_file(2, 2, Some((MERKLE_HEIGHT) as usize), Some(file_name))
                .unwrap();

        println!("CRS set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        // let mut prng = ChaChaRng::from_entropy();
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);

        let keys: Vec<_> = (0..=(nkeys as usize + 1))
            .map(|_| UserKeyPair::generate(&mut prng))
            .collect();

        let asset_defs: Vec<_> = (0..=(ndefs as usize + 1))
            .map(|_| AssetDefinition::new(AssetCode::random(&mut prng), Default::default()))
            .collect();

        let mut t = AAPMerkleTree::new(MERKLE_HEIGHT);
        let mut t_vec = vec![];

        let mut owners = vec![];
        let mut memos = vec![];

        println!("Keys and defs: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        for (def, key, amt) in std::iter::once(init_rec).chain(init_recs.into_iter()) {
            let amt = if amt < 2 { 2 } else { amt };
            let def = &asset_defs[def as usize % asset_defs.len()];
            let key = key as usize % keys.len();
            owners.push(key);
            let key = &keys[key];
            let rec = RecordOpening::new(&mut prng, amt, def.clone(), key.pub_key(), false);
            t.insert(&rec.derive_record_commitment());
            t_vec.push(rec.derive_record_commitment());

            memos.push(ReceiverMemo::from_oar(&mut prng, &rec).unwrap());
        }

        let first_root = t.get_root_value();

        println!("initial records: {}s", now.elapsed().as_secs_f32());

        let next_uid = owners.len() as u64;
        let nullifiers: SetMerkleTree = Default::default();
        let nullifiers_root = nullifiers.hash();

        let mut state = TestState {
            keys,
            owners,
            memos,
            nullifiers, /*asset_defs,*/
            record_merkle_vec: t_vec,
            validator: ValidatorState {
                prev_commit_time: 0u64,
                prev_state: *state_comm::INITIAL_PREV_COMM,
                verif_crs: TransferVerifierCRS::from(user_params.clone()),
                record_merkle_root: first_root,
                record_merkle_frontier: t,
                nullifiers_root,
                next_uid,
                prev_block: Default::default(),
            },
        };

        let mut now;

        let num_txs = txs.len();

        println!("{} blocks", num_txs);

        for (i, block) in txs.into_iter().enumerate() {
            assert_eq!(state.owners.len(), state.memos.len());
            assert_eq!(state.validator.nullifiers_root, state.nullifiers.hash());
            now = Instant::now();

            println!(
                "Block {}/{}, {} candidate txns",
                i + 1,
                num_txs,
                block.len()
            );

            // let block = block.into_iter().take(5).collect::<Vec<_>>();
            let splits = block
                .into_iter()
                .enumerate()
                .map(|x| (x, ChaChaRng::from_rng(&mut prng).unwrap()))
                .collect::<Vec<_>>();

            let mut txns = splits
                .into_par_iter()
                .map(|((ix, (in1, in2, k1, k2, amt_diff)), mut prng)| {
                    let now = Instant::now();

                    println!("Txn {}.{}/{}", i + 1, ix, num_txs);

                    let mut rec1 = None;
                    let mut rec2 = None;

                    let mut in1 = in1 as usize % state.owners.len();
                    let in2 = in2 as usize % state.owners.len();
                    for i in (0..(state.owners.len() - in1)).rev() {
                        let memo = &state.memos[i];
                        let kix = state.owners[i];
                        let key = &state.keys[kix];

                        let comm = state.record_merkle_vec.get(i).unwrap();
                        let rec = RecordCommitment { commitment: *comm };
                        let proof = state.validator.record_merkle_frontier.prove(i).unwrap();

                        let mut open_rec = RecordOpening::from_ar(&rec, &memo, &key).unwrap();

                        let nullifier = key.nullify(&FreezerPubKey::dummy(), i as u64, comm);
                        if !state.nullifiers.contains(nullifier).0 {
                            in1 = i;
                            open_rec.update_acc_member_witness(&AccMemberWitness {
                                path: proof,
                                root: state.validator.record_merkle_root.clone(),
                                uid: i as u64,
                            });
                            rec1 = Some((open_rec, kix));
                            break;
                        }
                    }

                    let owner_memos_key = schnorr::KeyPair::generate(&mut prng);

                    // TODO; factor this into a local closure or something instead
                    // of a pasted block
                    for i in (0..(state.owners.len() - in2)).rev() {
                        if i == in1 {
                            continue;
                        }

                        let memo = &state.memos[i];
                        let kix = state.owners[i];
                        let key = &state.keys[kix];

                        let comm = state.record_merkle_vec.get(i).unwrap();
                        let rec = RecordCommitment { commitment: *comm };
                        let proof = state.validator.record_merkle_frontier.prove(i).unwrap();

                        let mut open_rec = RecordOpening::from_ar(&rec, memo, &key).unwrap();

                        let nullifier = key.nullify(&FreezerPubKey::dummy(), i as u64, comm);
                        if !state.nullifiers.contains(nullifier).0 {
                            open_rec.update_acc_member_witness(&AccMemberWitness {
                                path: proof,
                                root: state.validator.record_merkle_root.clone(),
                                uid: i as u64,
                            });
                            rec2 = Some((open_rec, kix));
                            break;
                        }
                    }

                    if rec1.is_none() || rec2.is_none() {
                        println!(
                            "Txn {}.{}/{}: No records found, {}s",
                            i + 1,
                            ix,
                            num_txs,
                            now.elapsed().as_secs_f32()
                        );
                        return None;
                    }

                    let ((rec1, in_key1), (rec2, in_key2)) = (rec1.unwrap(), rec2.unwrap());
                    let in_key1 = &state.keys[in_key1];
                    let in_key2 = &state.keys[in_key2];

                    let k1 = k1 as usize % state.keys.len();
                    let k1_ix = k1;
                    let k1 = &state.keys[k1];
                    let k2 = k2 as usize % state.keys.len();
                    let k2_ix = k2;
                    let k2 = &state.keys[k2];

                    let out_def1 = rec1.asset_def();
                    let out_def2 = rec2.asset_def();

                    let (out_amt1, out_amt2) = {
                        if out_def1 == out_def2 {
                            let total = rec1.amount() + rec2.amount();
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
                            (rec1.amount() - 1, rec2.amount())
                        }
                    };

                    if out_amt1 <= 1 {
                        println!(
                            "Txn {}.{}/{}: not enough for a fee, skipping {}s",
                            i + 1,
                            ix,
                            num_txs,
                            now.elapsed().as_secs_f32()
                        );
                        return None;
                    }

                    let out_amt1 = out_amt1 - 1;

                    let out_rec1 =
                        RecordOpening::new(&mut prng, out_amt1, out_def1, k1.pub_key(), false);

                    let out_rec2 =
                        RecordOpening::new(&mut prng, out_amt2, out_def2, k2.pub_key(), false);

                    // state.memos.push(ReceiverMemo::from_oar(&mut prng, &out_rec1).unwrap());
                    // state.memos.push(ReceiverMemo::from_oar(&mut prng, &out_rec2).unwrap());

                    let new_time = state.validator.prev_commit_time + 1;

                    println!(
                        "Txn {}.{}/{} inputs chosen: {}",
                        i + 1,
                        ix,
                        num_txs,
                        now.elapsed().as_secs_f32()
                    );
                    let now2 = Instant::now();

                    let (txn, owner_memos, _owner_memos_sig) = TransferNote::generate(
                        &mut prng,
                        &TransferNoteInputsRef {
                            prover_crs: &user_params,
                            verifier_crs: &state.validator.verif_crs,
                            inputs: vec![&rec1, &rec2],
                            outputs: vec![&out_rec1, &out_rec2],
                            keypairs_in: vec![in_key1, in_key2],
                            keypairs_out: vec![],
                            in_creds: vec![&None, &None],
                            root_value: state.validator.record_merkle_root,
                            valid_until: new_time + 1,
                            receiver_memos_signing_keypair: &owner_memos_key,
                            now: new_time,
                        },
                        &state.validator.record_merkle_root,
                    )
                    .unwrap();

                    // owner_memos_key
                    // .verify(&helpers::get_owner_memos_digest(&owner_memos),
                    //     &owner_memos_sig).unwrap();
                    println!(
                        "Txn {}.{}/{} note generated: {}",
                        i + 1,
                        ix,
                        num_txs,
                        now2.elapsed().as_secs_f32()
                    );
                    let now2 = Instant::now();

                    let nullifier_pfs = txn
                        .inputs
                        .iter()
                        .map(|n| state.nullifiers.contains(*n).1)
                        .collect();

                    println!(
                        "Txn {}.{}/{} nullifier proofs generated: {}s",
                        i + 1,
                        ix,
                        num_txs,
                        now2.elapsed().as_secs_f32()
                    );

                    Some((
                        ix,
                        (owner_memos, k1_ix, k2_ix),
                        ElaboratedTransaction {
                            txn: Transaction(txn),
                            proofs: nullifier_pfs,
                        },
                    ))
                })
                .filter_map(|x| x)
                .collect::<Vec<_>>();

            txns.sort_by(|(i, _, _), (j, _, _)| i.cmp(j));

            println!(
                "Block {}/{} txns generated: {}s",
                i + 1,
                num_txs,
                now.elapsed().as_secs_f32()
            );
            let generation_time = now.elapsed().as_secs_f32();
            let now2 = Instant::now();

            let mut blk = ElaboratedBlock::default();
            for (ix, (owner_memos, k1_ix, k2_ix), txn) in txns {
                println!("Block {}/{} trying to add {}", i + 1, num_txs, ix);

                if let Ok(newblk) = blk.add_transaction(&state.validator, &txn) {
                    println!("Block {}/{} adding {}", i + 1, num_txs, ix);
                    state.memos.extend(owner_memos);
                    state.owners.push(k1_ix);
                    state.owners.push(k2_ix);
                    state
                        .record_merkle_vec
                        .extend(txn.txn.0.outputs.iter().map(|o| o.commitment));

                    blk = newblk;
                }
            }

            assert!(blk.validate_block(&state.validator));
            let new_state = blk.append_to(&state.validator).unwrap();

            for n in blk.block.0.iter().flat_map(|x| x.0.inputs.iter()) {
                assert!(!state.nullifiers.contains(*n).0);
                state.nullifiers.insert(*n);
            }
            state.validator = new_state;
            println!(
                "Block {}/{}: {} transactions, {}s ({}s generation, {}s checking)",
                i + 1,
                num_txs,
                blk.block.0.len(),
                now.elapsed().as_secs_f32(),
                generation_time,
                now2.elapsed().as_secs_f32()
            );

            assert_eq!(state.nullifiers.hash(), state.validator.nullifiers_root);
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

        let univ = jf_txn::proof::universal_setup(jf_txn::MAX_UNIVERSAL_DEGREE, &mut prng).unwrap();
        let (_prove, _verif) =
            jf_txn::proof::transfer::preprocess(&mut prng, &univ, 1, 1, MERKLE_HEIGHT as usize)
                .unwrap();

        println!("CRS set up");
    }

    #[test]
    #[allow(unused_variables)]
    fn test_2user() {
        let now = Instant::now();

        println!("generating params");

        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);

        let univ_setup =
            jf_txn::proof::universal_setup(jf_txn::MAX_UNIVERSAL_DEGREE, &mut prng).unwrap();
        let (prove_key, verif_key) = jf_txn::proof::transfer::preprocess(
            &mut prng,
            &univ_setup,
            1,
            1,
            MERKLE_HEIGHT as usize,
        )
        .unwrap();

        println!("CRS set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let alice_key = UserKeyPair::generate(&mut prng);
        let bob_key = UserKeyPair::generate(&mut prng);

        let coin = AssetDefinition::new(
            AssetCode::native(), /* other returns? */
            Default::default(),
        );

        let alice_rec_builder = RecordOpening::new(
            &mut prng,
            2,
            coin.clone(),
            alice_key.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let alice_rec1 = alice_rec_builder;

        let mut t = MerkleTree::new(MERKLE_HEIGHT);
        let mut t_vec: Vec<RecordCommitment> = vec![];
        assert_eq!(
            t.get_root_value(),
            MerkleTree::new(MERKLE_HEIGHT).get_root_value()
        );
        let alice_rec_elem =
            MerkleTreeElem::new(<_>::from(0), RecordCommitment::from_ro(&alice_rec1).into());
        dbg!(&RecordCommitment::from_ro(&alice_rec1));
        assert_eq!(
            RecordCommitment::from_ro(&alice_rec1),
            RecordCommitment::from_ro(&alice_rec1)
        );
        t.insert(&RecordCommitment::from_ro(&alice_rec1).into());
        t_vec.push(RecordCommitment::from_ro(&alice_rec1).into());
        let alice_rec_path = t.prove(0).unwrap();
        // assert_eq!(alice_rec_elem.arc,t.get_leaf_value(0).unwrap());

        let mut nullifiers: SetMerkleTree = Default::default();

        println!("Tree set up: {}s", now.elapsed().as_secs_f32());
        let now = Instant::now();

        let first_root = t.get_root_value();

        let alice_rec_final = TransferNoteInput::create(
            alice_rec1.clone(),
            &alice_key,
            None,
            AccMemberWitness {
                merkle_path: alice_rec_path.clone(),
                root: first_root.clone(),
                uid: 0,
            },
        )
        .unwrap();

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

        assert!(MerkleTree::verify(
            &validator.record_merkle_root,
            &alice_rec_elem,
            &alice_rec_path
        ));

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
            let txn = TransferNote::generate(
                &mut prng,
                /* inputs:         */ vec![alice_rec_final],
                /* outputs:        */ &[bob_rec.clone()],
                /* proving_key:    */ &prove_key,
                /* valid_until:    */ 2,
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
            .map(|n| nullifiers.contains(*n).1)
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
            .validate_and_apply(1, Block(vec![Transaction(txn1)]), vec![nullifier_pfs])
            .unwrap();

        println!(
            "Transfer validated & applied: {}s",
            now.elapsed().as_secs_f32()
        );
        let now = Instant::now();

        assert_eq!(&new_uids, &vec![1]);

        let bob_rec = TransferNoteInput::create(
            bob_rec,
            &bob_key,
            None,
            AccMemberWitness {
                merkle_path: validator.record_merkle_frontier.prove(1).unwrap(),
                root: validator.record_merkle_frontier.get_root_value(),
                uid: 1,
            },
        )
        .unwrap();

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

    fn test_merkle_tree(updates: Vec<Result<u64, usize>>) {
        println!("Iter: {} updates", updates.len());
        let (mut t1, mut t2) = (
            MerkleTree::new(MERKLE_HEIGHT),
            MerkleTree::new(MERKLE_HEIGHT),
        );
        let base_scalar = CommitmentValue::rand(&mut ChaChaRng::from_seed([0u8; 32]));
        for t in [&mut t1, &mut t2].iter_mut() {
            let mut map = Vec::new();
            for u in updates.iter() {
                match u {
                    Ok(val) => {
                        map.push(val);

                        t.insert(&NodeValue::from(base_scalar.pow(&[*val])));

                        // check_path(t.hasher.as_ref(), &path.unwrap(), &leaf_val,
                        //         &leaf_hash, MERKLE_HEIGHT, &t.root_hash)
                        //     .expect("Merkle3Tree generated an invalid proof");

                        // assert_eq!(old_val,old_tree_val.map(|x| x.1));
                    }
                    Err(i) => {
                        match (
                            map.get(*i).cloned().map(|x| base_scalar.pow(&[*x as u64])),
                            t.get_leaf_value(*i),
                            t.prove(*i),
                        ) {
                            (None, None, None) => {}
                            (Some(map_val), Some(_tree_val), Some(tree_proof)) => {
                                // assert_eq!(map_val,tree_val);
                                assert!(
                                    MerkleTree::verify(
                                        &t.get_root_value(),
                                        &MerkleTreeElem::new(
                                            <_>::from(CommitmentValue::from(*i as u64)),
                                            map_val.into()
                                        ),
                                        &tree_proof
                                    ),
                                    "Merkle path verification failed"
                                );
                            }
                            (l, m, r) => {
                                panic!(
                                    "Mismatch: map_val = {:?}, tree_val = {:?} tree_proof = {:?}",
                                    l, m, r
                                );
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(t1.get_root_value(), t2.get_root_value());
    }

    #[test]
    fn quickcheck_multixfr_regressions() {
        test_multixfr(
            vec![vec![(0, 0, 0, 0, -2), (0, 0, 0, 0, 0)]],
            0,
            0,
            (0, 0, 0),
            vec![(0, 0, 0)],
        )
    }

    #[test]
    #[ignore]
    fn quickcheck_multixfr() {
        QuickCheck::new()
            .tests(10)
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
