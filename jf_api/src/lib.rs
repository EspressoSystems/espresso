#[derive(Clone,Copy,Debug)]
pub struct Nullifier();

pub struct RecordOpening();
pub struct RecordCommitment();

pub mod ads {
    use serde::{Serialize,de::DeserializeOwned};
    use core::fmt::Debug;
    use super::Nullifier;

    pub trait RecordArray: Default + Serialize + DeserializeOwned
                                   + Clone + Debug {
        type Proof: Debug;
        type Commitment: Copy + Debug + PartialEq + Eq;
        type Index: Copy + Into<u64> + From<u64> + Debug;
        type Elem: Copy + Debug;

        // arr.get(i) returns:
        //  - None if i is outside the array range
        //  - Some(None) if i is inside the array range but we don't have
        //    the full path for i available
        //  - Some(Some(comm,pf)) if i is inside the array range and the
        //    full path is available.
        fn get(&self, ix: Self::Index) -> Option<Option<(Self::Elem,Self::Proof)>>;

        fn len(&self) -> Self::Index;
        fn commitment(&self) -> Self::Commitment;

        fn insert(&mut self, val: Self::Elem) -> Self::Proof;
        fn batch_insert(&mut self, vals: Vec<Self::Elem>) -> Vec<Self::Proof>;

        // this should always work:
        //     if let Some(Some(elem,pf)) = arr.get(i) {
        //         check_proof(arr.commitment(), pf, elem, i).unwrap();
        //     }
        fn check_proof(root: Self::Commitment, pf: &Self::Proof, val: Self::Elem, ix: Self::Index) -> Result<(),Self::Commitment>;

        // sparse operations.

        // "forget" a particular index. This hints the underlying
        // information to remove `i` from availability. The implementation
        // is not required to _actually_ remove `i`, but the following
        // should always work:
        //     let v1 = arr.get(i);
        //     let v2 = arr.forget(i);
        //     assert_eq!(v1,v2);
        // if the implementation _does_ forget `i`, this will work:
        //     if arr.forget(i).is_some() {
        //         assert!(arr.get(i).unwrap().is_none());
        //     }
        fn forget(&mut self, ix: Self::Index) -> Option<Option<(Self::Elem,Self::Proof)>>;
        // "remember" a particular index. This should always work:
        //     if check_proof(arr.commitment(), elem, pf, i).is_ok() {
        //          let old_comm = arr.commitment();
        //          arr.remember(elem,pf,i).unwrap();
        //          assert_eq!(old_comm,arr.commitment());
        //          let (elem,pf) = arr.get(i).unwrap().unwrap();
        //          check_proof(arr.commitment(), pf, elem, i).unwrap();
        //     }
        fn remember(&mut self, pf: Self::Proof, val: Self::Elem, ix: Self::Index) -> Result<(),Self::Commitment>;
    }

    pub fn test_record_array<RA, F>(updates: Vec<Result<u64, usize>>,
                                    into_elem: F)
        where RA: RecordArray,
              F: Fn(u64) -> RA::Elem
    {
        println!("Iter: {} updates", updates.len());
        let (mut t1, mut t2): (RA,RA) = Default::default();
        for t in [&mut t1, &mut t2].iter_mut() {
            let mut map = Vec::new();
            for u in updates.iter() {
                match u {
                    Ok(val) => {
                        map.push(val);

                        t.insert(into_elem(*val));

                        // check_path(t.hasher.as_ref(), &path.unwrap(), &leaf_val,
                        //         &leaf_hash, MERKLE_HEIGHT, &t.root_hash)
                        //     .expect("Merkle3Tree generated an invalid proof");

                        // assert_eq!(old_val,old_tree_val.map(|x| x.1));
                    }
                    Err(i) => {
                        match (
                            map.get(*i).cloned().map(|x| into_elem(*x as u64)),
                            t.get((*i as u64).into()),
                        ) {
                            (None, None) => {}
                            (Some(map_val), Some(Some((_tree_val,tree_proof)))) => {
                                // assert_eq!(map_val,tree_val);
                                    RA::check_proof(
                                        t.commitment(),
                                        &tree_proof,
                                        map_val,
                                        (*i as u64).into(),
                                    ).expect("Merkle path verification failed");
                            }
                            (l, r) => {
                                panic!(
                                    "Mismatch: map_val = {:?}, (tree_val,tree_proof) = {:?}",
                                    l, r
                                );
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(t1.commitment(), t2.commitment());
    }

    pub trait NullifierSet: Default + Serialize + DeserializeOwned + Clone {
        type Proof: Clone + Debug;
        type Commitment: Copy + PartialEq + Eq + Debug;

        fn commitment(&self) -> Self::Commitment;
        fn query(&self, val: Nullifier) -> (bool,Self::Proof);
        fn check_proof(pf: &Self::Proof, val: Nullifier, root: Self::Commitment) -> Result<bool,Self::Commitment>;
        fn insert(&mut self, val: Nullifier) -> Self::Proof;
        fn lw_insert(root: Self::Commitment, val: Nullifier, pf: &Self::Proof) -> Result<(Self::Commitment,Self::Proof),Self::Commitment>;
        fn lw_insert_and_update(root: Self::Commitment, val: Nullifier, pf: &Self::Proof, other_val: Nullifier, other_pf: &Self::Proof)
            -> Result<(Self::Commitment,Self::Proof,Self::Proof),Self::Commitment>;
        fn lw_multi_insert(root: Self::Commitment, vals: Vec<(Nullifier, Self::Proof)>) -> Result<(Self::Commitment,Vec<Self::Proof>),(Nullifier,Self::Proof,Self::Commitment)>;
    }

    pub fn test_nullifier_set<NS, F>(updates: Vec<u16>, checks: Vec<Result<u16, u8>>, into_elem: F)
        where NS: NullifierSet,
              F: Fn(u64) -> Nullifier
    {
        use std::collections::HashSet;
        let mut hset = HashSet::new();
        let mut t = NS::default();
        let mut lw_t = t.commitment();
        assert_eq!(t.commitment(), lw_t);

        let update_elems: Vec<_> = updates
            .iter()
            .map(|u| into_elem(*u as u64))
            .collect();
        let mut update_proofs: Vec<_> = update_elems.iter().map(|x| t.query(*x).1).collect();

        for (u, elem) in updates.iter().zip(update_elems.iter()) {
            let elem = *elem;
            hset.insert(u);
            let (in_set, pf) = t.query(elem);
            t.insert(elem);
            assert_eq!(NS::check_proof(&pf, elem, lw_t).unwrap(), in_set);

            let (new_lw_t, new_lw_pf) = NS::lw_insert(lw_t, elem, &pf).unwrap();
            assert!(NS::check_proof(&new_lw_pf, elem, new_lw_t).unwrap());

            for (i, other_pf) in update_proofs.iter_mut().enumerate() {
                NS::check_proof(&other_pf, update_elems[i], lw_t).unwrap();

                let (_, _new_pf, new_other_pf) =
                    NS::lw_insert_and_update(lw_t,elem,&pf,update_elems[i],other_pf)
                    .unwrap();
                *other_pf = new_other_pf;
            }

            lw_t = new_lw_t;
            assert_eq!(t.commitment(), lw_t);
        }

        for c in checks {
            let (val, should_be_there) = match c {
                Ok(val) => (val, false),
                Err(ix) => {
                    if updates.is_empty() {
                        continue;
                    }

                    let val = updates[ix as usize % updates.len()];
                    (val, true)
                }
            };
            let elem = into_elem(val as u64);

            let (t_contains, pf) = t.query(elem);

            if should_be_there {
                assert!(hset.contains(&val));
                assert!(t_contains);
            }

            assert_eq!(hset.contains(&val), t_contains);
            assert_eq!(
                t_contains,
                NS::check_proof(&pf, elem, t.commitment()).unwrap()
            );
        }
    }
}

pub struct TransferProverCRS();
pub struct TransferVerifierCRS();
pub struct TransferNote();

impl TransferNote {
    // fn verify(&self, &TransferVerifierCRS, ...);
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
