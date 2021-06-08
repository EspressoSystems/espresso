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

    //     #[test]
    //     fn quickcheck_multixfr_regressions() {
    //         test_multixfr(
    //             vec![vec![(0, 0, 0, 0, -2), (0, 0, 0, 0, 0)]],
    //             0,
    //             0,
    //             (0, 0, 0),
    //             vec![(0, 0, 0)],
    //         )
    //     }

    //     #[test]
    //     #[ignore]
    //     fn quickcheck_multixfr() {
    //         QuickCheck::new()
    //             .tests(10)
    //             .quickcheck(test_multixfr as fn(Vec<_>, u8, u8, _, Vec<_>) -> ());
    //     }

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
