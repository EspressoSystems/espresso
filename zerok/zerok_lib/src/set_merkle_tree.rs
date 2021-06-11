#![deny(warnings)]
#![allow(dead_code)]

use crate::util::byte_array_to_bits;
use bitvec::vec::BitVec;
use core::mem;
use jf_txn::structs::Nullifier;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub mod set_hash {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    use jf_utils::serialize::CanonicalBytes;
    pub type Hash = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;
    lazy_static::lazy_static! {
        pub static ref EMPTY_HASH: Hash = GenericArray::<_,_>::default();
    }

    pub fn elem_hash(x: Nullifier) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Elem".as_bytes());
        hasher.update(&CanonicalBytes::from(x).0);
        hasher.finalize().into_bytes()
    }

    pub fn leaf_hash(x: Nullifier) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Leaf".as_bytes());
        hasher.update(&CanonicalBytes::from(x).0);
        hasher.finalize().into_bytes()
    }

    pub fn branch_hash(l: Hash, r: Hash) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Branch".as_bytes());
        hasher.update("l".as_bytes());
        hasher.update(&l);
        hasher.update("r".as_bytes());
        hasher.update(&r);
        hasher.finalize().into_bytes()
    }
}

#[derive(Debug, Clone)]
pub enum SetMerkleTree {
    Empty(),
    Leaf(set_hash::Hash, Nullifier),
    Branch(set_hash::Hash, Box<SetMerkleTree>, Box<SetMerkleTree>),
}

impl Default for SetMerkleTree {
    fn default() -> Self {
        Self::Empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SetMerkleProof {
    is_present: bool,
    path: Vec<set_hash::Hash>,
}

// TODO: an optimization can be done where instead of expanding the whole tree for each element,
// you expand until that element would be the only element in that subtree. This requires different
// logic in the proof checking to distinguish between "Not in the tree because the path to the
// element ends in Empty" and "Not in the tree because the path to the element abruptly ends at a
// different element". I think it requires a slightly different proof structure as well -- for
// example, instead of `is_present`, you have something with 3 options: Present, EmptyPath, and
// NonemptyPath(Nullifier).
impl SetMerkleProof {
    pub fn check(&self, elem: Nullifier, root: &set_hash::Hash) -> Result<bool, set_hash::Hash> {
        let mut running_hash = if self.is_present {
            set_hash::leaf_hash(elem)
        } else {
            *set_hash::EMPTY_HASH
        };

        let elem_bit_vec = byte_array_to_bits(set_hash::elem_hash(elem));

        // For non-membership proofs, the path only goes until an empty
        // subtree is reached, so skip part of the bit-vec
        let start_bit = elem_bit_vec.len() - self.path.len();
        let elem_bits = elem_bit_vec.into_iter().skip(start_bit);

        for (sib, sib_is_left) in self.path.iter().zip(elem_bits) {
            let sib = *sib;
            // dbg!(&sib_is_left);
            // dbg!(&format!("{:x?}",running_hash));
            // dbg!(&format!("{:x?}",sib));
            running_hash = {
                let l = if sib_is_left { sib } else { running_hash };
                let r = if sib_is_left { running_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
        }
        // dbg!(&format!("{:x?}",running_hash));

        if &running_hash == root {
            Ok(self.is_present)
        } else {
            Err(running_hash)
        }
    }

    pub fn lightweight_insert(
        &self,
        elem: Nullifier,
        root: &set_hash::Hash,
    ) -> Result<(set_hash::Hash, Self), set_hash::Hash> {
        let mut running_hash = if self.is_present {
            set_hash::leaf_hash(elem)
        } else {
            *set_hash::EMPTY_HASH
        };

        let mut running_new_hash = set_hash::leaf_hash(elem);

        let elem_bit_vec = byte_array_to_bits(set_hash::elem_hash(elem));

        // For non-membership proofs, the path only goes until an empty
        // subtree is reached, so skip part of the bit-vec
        let start_bit = elem_bit_vec.len() - self.path.len();

        let elem_bits_before_start = elem_bit_vec.clone().into_iter().take(start_bit);
        let elem_bits = elem_bit_vec.into_iter().skip(start_bit);
        let mut new_path = vec![];

        for sib_is_left in elem_bits_before_start {
            let sib = *set_hash::EMPTY_HASH;
            running_new_hash = {
                let l = if sib_is_left { sib } else { running_new_hash };
                let r = if sib_is_left { running_new_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
            new_path.push(sib);
        }

        for (sib, sib_is_left) in self.path.iter().zip(elem_bits) {
            let sib = *sib;
            // dbg!(&sib_is_left);
            // dbg!(&format!("{:x?}",running_hash));
            // dbg!(&format!("{:x?}",sib));
            running_hash = {
                let l = if sib_is_left { sib } else { running_hash };
                let r = if sib_is_left { running_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
            running_new_hash = {
                let l = if sib_is_left { sib } else { running_new_hash };
                let r = if sib_is_left { running_new_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
            new_path.push(sib);
        }
        // dbg!(&format!("{:x?}",running_hash));

        if &running_hash == root {
            Ok((
                running_new_hash,
                Self {
                    is_present: true,
                    path: new_path,
                },
            ))
        } else {
            Err(running_hash)
        }
    }

    pub fn update_proof_for_lw_insert(
        &self,
        elem: Nullifier,
        other: Self,
        other_elem: Nullifier,
        root: &set_hash::Hash,
    ) -> Result<(set_hash::Hash, Self), set_hash::Hash> {
        if elem == other_elem {
            other.check(elem, root)?;
            return self.lightweight_insert(elem, root);
        }

        let elem_bit_vec = byte_array_to_bits(set_hash::elem_hash(elem));
        let other_bit_vec = byte_array_to_bits(set_hash::elem_hash(other_elem));

        // the lowest value i such that elem_bit_vec[i:] == other_bit_vec[i:]
        let unique_prefix_len = {
            assert_eq!(elem_bit_vec.len(), other_bit_vec.len());

            let mut i = elem_bit_vec.len();

            while i > 0 && elem_bit_vec[i - 1] == other_bit_vec[i - 1] {
                i -= 1;
            }
            i
        };

        let mut running_old_hash = if self.is_present {
            set_hash::leaf_hash(elem)
        } else {
            *set_hash::EMPTY_HASH
        };

        let mut running_old_other_hash = if other.is_present {
            set_hash::leaf_hash(other_elem)
        } else {
            *set_hash::EMPTY_HASH
        };

        let mut running_new_hash = set_hash::leaf_hash(elem);
        let mut running_new_other_hash = running_old_other_hash;

        // which bit our old proof starts on
        let start_bit = elem_bit_vec.len() - self.path.len();
        // which bit other's old proof starts on
        let other_start_bit = other_bit_vec.len() - other.path.len();

        let mut new_path = vec![];

        let loop_iter = elem_bit_vec
            .into_iter()
            .zip(other_bit_vec.into_iter())
            .enumerate();

        for (i, (sib_is_left, other_sib_is_left)) in loop_iter {
            // update our running old hash
            let next_old_hash = if i < start_bit {
                running_old_hash
            } else {
                let sib = self.path[i - start_bit];
                let l = if sib_is_left { sib } else { running_old_hash };
                let r = if sib_is_left { running_old_hash } else { sib };
                set_hash::branch_hash(l, r)
            };

            // update our running new hash
            let next_new_hash = if i < start_bit {
                let sib = *set_hash::EMPTY_HASH;
                let l = if sib_is_left { sib } else { running_new_hash };
                let r = if sib_is_left { running_new_hash } else { sib };
                set_hash::branch_hash(l, r)
            } else {
                let sib = self.path[i - start_bit];
                let l = if sib_is_left { sib } else { running_new_hash };
                let r = if sib_is_left { running_new_hash } else { sib };
                set_hash::branch_hash(l, r)
            };

            // update other's running old hash
            let next_old_other_hash = if i < other_start_bit {
                running_old_other_hash
            } else {
                let sib = other.path[i - other_start_bit];
                let sib_is_left = other_sib_is_left;
                let l = if sib_is_left {
                    sib
                } else {
                    running_old_other_hash
                };
                let r = if sib_is_left {
                    running_old_other_hash
                } else {
                    sib
                };
                set_hash::branch_hash(l, r)
            };

            // update other's running new hash
            let next_new_other_hash = match (i < other_start_bit, (i + 1).cmp(&unique_prefix_len)) {
                (true, std::cmp::Ordering::Less) => {
                    // Proof in an undisturbed empty subtree
                    running_new_other_hash
                }
                (false, std::cmp::Ordering::Less) => {
                    // Proof in an undisturbed subtree
                    let sib = other.path[i - other_start_bit];
                    let sib_is_left = other_sib_is_left;
                    let l = if sib_is_left {
                        sib
                    } else {
                        running_new_other_hash
                    };
                    let r = if sib_is_left {
                        running_new_other_hash
                    } else {
                        sib
                    };
                    new_path.push(sib);
                    set_hash::branch_hash(l, r)
                }
                (_, std::cmp::Ordering::Equal) => {
                    assert_eq!(!sib_is_left, other_sib_is_left);
                    // this insert disturbs our path.
                    let sib_is_left = other_sib_is_left;
                    let sib = running_new_hash;
                    let l = if sib_is_left {
                        sib
                    } else {
                        running_new_other_hash
                    };
                    let r = if sib_is_left {
                        running_new_other_hash
                    } else {
                        sib
                    };
                    let ret = set_hash::branch_hash(l, r);
                    // assert_eq!(ret,next_new_hash);
                    // if i >= start_bit {
                    //     assert_eq!(running_old_other_hash,self.path[i-start_bit]);
                    // }
                    new_path.push(sib);
                    ret
                }
                (_, std::cmp::Ordering::Greater) => {
                    // TODO: this seems wrong?
                    let sib = if i < start_bit {
                        *set_hash::EMPTY_HASH
                    } else {
                        self.path[i - start_bit]
                    };
                    new_path.push(sib);
                    next_new_hash
                }
            };

            running_old_hash = next_old_hash;
            running_new_hash = next_new_hash;
            running_old_other_hash = next_old_other_hash;
            running_new_other_hash = next_new_other_hash;
        }

        if &running_old_hash != root {
            dbg!("fail1");
            Err(running_old_hash)
        } else if &running_old_other_hash != root {
            dbg!("fail2");
            Err(running_old_other_hash)
        } else {
            Ok((
                running_new_hash,
                Self {
                    is_present: other.is_present,
                    path: new_path,
                },
            ))
        }
    }
}

pub fn set_merkle_lw_multi_insert(
    inserts: Vec<(Nullifier, SetMerkleProof)>,
    mut root: set_hash::Hash,
) -> Result<(set_hash::Hash, Vec<SetMerkleProof>), set_hash::Hash> {
    let elems: Vec<_> = inserts.iter().map(|(x, _)| *x).collect();
    let mut pfs: Vec<_> = inserts.into_iter().map(|(_, y)| y).collect();
    for i in 0..pfs.len() {
        let old_pf = pfs[i].clone();
        let (new_root, new_pf) = old_pf.lightweight_insert(elems[i], &root)?;
        pfs[i] = new_pf;

        for j in (0..i).chain((i + 1)..pfs.len()) {
            let old_other_pf = pfs[j].clone();
            let (_, new_other_pf) =
                old_pf.update_proof_for_lw_insert(elems[i], old_other_pf, elems[j], &root)?;
            pfs[j] = new_other_pf;
        }
        root = new_root;
    }
    Ok((root, pfs))
}

impl SetMerkleTree {
    pub fn hash(&self) -> set_hash::Hash {
        use SetMerkleTree::*;
        match self {
            Empty() => *set_hash::EMPTY_HASH,
            Leaf(h, _) => *h,
            Branch(h, _, _) => *h,
        }
    }

    pub fn contains(&self, elem: Nullifier) -> (bool, SetMerkleProof) {
        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let elem_bits = elem_bit_vec.into_iter().rev();

        let mut path = vec![];
        let mut end_branch = self;
        for sib_is_left in elem_bits {
            match end_branch {
                Branch(_, l, r) => {
                    path.push(if sib_is_left { l.hash() } else { r.hash() });
                    end_branch = if sib_is_left { r.as_ref() } else { l.as_ref() };
                }
                Empty() => {
                    path.reverse();
                    return (
                        false,
                        SetMerkleProof {
                            is_present: false,
                            path,
                        },
                    );
                }
                Leaf(_, _) => {
                    panic!("This tree has an occupied leaf in a branch position");
                }
            }
        }

        match end_branch {
            Empty() => {
                path.reverse();
                (
                    false,
                    SetMerkleProof {
                        is_present: false,
                        path,
                    },
                )
            }
            Leaf(_, leaf_elem) => {
                assert_eq!(leaf_elem, &elem);
                path.reverse();
                (
                    true,
                    SetMerkleProof {
                        is_present: true,
                        path,
                    },
                )
            }
            Branch(_, _, _) => panic!("This tree has more levels than my hash has bits!"),
        }
    }

    pub fn insert(&mut self, elem: Nullifier) {
        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let elem_bits = elem_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, Empty());
        for sib_is_left in elem_bits {
            let sib = match end_branch {
                Empty() => {
                    end_branch = Empty();
                    Box::new(Empty())
                }
                Branch(_, l, r) => {
                    let (sib, next) = if sib_is_left { (l, r) } else { (r, l) };
                    end_branch = *next;
                    sib
                }
                Leaf(_, _) => {
                    panic!("This tree has fewer levels than my hash has bits!")
                }
            };

            siblings.push((sib_is_left, sib));
        }
        end_branch = Leaf(set_hash::leaf_hash(elem), elem);

        siblings.reverse();
        for (sib_is_left, sib) in siblings {
            let (l, r) = if sib_is_left {
                (sib, Box::new(end_branch))
            } else {
                (Box::new(end_branch), sib)
            };
            let h = set_hash::branch_hash(l.hash(), r.hash());
            end_branch = Branch(h, l, r);
        }
        *self = end_branch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;
    use quickcheck::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::time::Instant; //????/

    #[test]
    fn test_set_merkle_speed() {
        use blake2::crypto_mac::Mac;

        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let elems = (1..1000)
            .map(|_| Nullifier::random_for_test(&mut prng))
            .collect::<Vec<_>>();
        let pfs = elems
            .into_iter()
            .map(|elem| {
                let elem_bit_vec = byte_array_to_bits(set_hash::elem_hash(elem));
                let pf = elem_bit_vec
                    .iter()
                    .map(|_| {
                        let mut buf = [0u8; 32];
                        prng.fill_bytes(&mut buf);
                        let mut hasher = blake2::Blake2b::with_params(&[], &[], "".as_bytes());
                        hasher.update(&buf);
                        hasher.finalize().into_bytes()
                    })
                    .collect();
                let pf = SetMerkleProof {
                    is_present: false,
                    path: pf,
                };
                let root = pf
                    .check(elem, &SetMerkleTree::default().hash())
                    .unwrap_err();
                (elem, pf, root)
            })
            .collect::<Vec<_>>();

        let now = Instant::now();
        let mut tot = 0;
        for (elem, pf, root) in pfs {
            let new_root = pf.check(elem, &root);
            if new_root.unwrap() {
                tot += 1;
            }
        }
        println!("proofs: {}/1000 in {}s", tot, now.elapsed().as_secs_f32());
    }

    fn test_merkle_tree_set(updates: Vec<u16>, checks: Vec<Result<u16, u8>>) {
        use std::collections::{HashMap, HashSet};
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let update_vals = updates
            .iter()
            .cloned()
            .chain(checks.iter().filter_map(|x| x.ok().clone()))
            .map(|u| (u, Nullifier::random_for_test(&mut prng)))
            .collect::<HashMap<_, _>>();
        let mut hset = HashSet::new();
        let mut t = SetMerkleTree::default();
        let mut lw_t = t.hash();
        assert_eq!(t.hash(), lw_t);

        let update_elems: Vec<_> = updates.iter().map(|u| update_vals[u]).collect();
        let mut update_proofs: Vec<_> = update_elems.iter().map(|x| t.contains(*x).1).collect();

        for (u, elem) in updates.iter().zip(update_elems.iter()) {
            let elem = *elem;
            hset.insert(u);
            let (in_set, pf) = t.contains(elem);
            t.insert(elem);
            assert_eq!(pf.check(elem, &lw_t).unwrap(), in_set);

            let (new_lw_t, new_lw_pf) = pf.lightweight_insert(elem, &lw_t).unwrap();
            assert!(new_lw_pf.check(elem, &new_lw_t).unwrap());

            for (i, other_pf) in update_proofs.iter_mut().enumerate() {
                other_pf.check(update_elems[i], &lw_t).unwrap();

                let (_, new_pf) = pf
                    .update_proof_for_lw_insert(elem, other_pf.clone(), update_elems[i], &lw_t)
                    .unwrap();
                *other_pf = new_pf;
            }

            lw_t = new_lw_t;
            assert_eq!(t.hash(), lw_t);
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
            let elem = update_vals[&val];

            let (t_contains, pf) = t.contains(elem);

            if should_be_there {
                assert!(hset.contains(&val));
                assert!(t_contains);
            }

            assert_eq!(hset.contains(&val), t_contains);
            assert_eq!(
                t_contains,
                SetMerkleProof::check(&pf, elem, &t.hash()).unwrap()
            );
        }
    }

    #[test]
    fn quickcheck_merkle_tree_set() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_merkle_tree_set as fn(Vec<_>, Vec<_>) -> ());
    }
}
