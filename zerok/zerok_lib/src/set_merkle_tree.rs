#![deny(warnings)]
#![allow(dead_code)]

use crate::util::{byte_array_to_bits, canonical};
use ark_serialize::*;
use bitvec::vec::BitVec;
use core::mem;
use jf_txn::structs::Nullifier;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub mod set_hash {
    use super::*;
    use blake2::crypto_mac::Mac;
    use generic_array::GenericArray;
    use jf_utils::tagged_blob;
    use std::ops::Deref;

    type Array = GenericArray<u8, <blake2::Blake2b as Mac>::OutputSize>;

    #[tagged_blob("HASH")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Hash(Array);

    lazy_static::lazy_static! {
        pub static ref EMPTY_HASH: Hash = Hash(GenericArray::<_,_>::default());
    }

    impl Hash {
        pub fn new(bytes: Array) -> Self {
            Self(bytes)
        }

        pub fn into_bits(self) -> BitVec<bitvec::order::Lsb0, u8> {
            byte_array_to_bits(self.0)
        }
    }

    impl CanonicalSerialize for Hash {
        fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
            w.write_all(&self.0).map_err(SerializationError::from)
        }

        fn serialized_size(&self) -> usize {
            self.0.len()
        }
    }

    impl CanonicalDeserialize for Hash {
        fn deserialize<R: Read>(mut r: R) -> Result<Self, SerializationError> {
            let mut buf = GenericArray::default();
            r.read_exact(&mut buf)?;
            Ok(Hash(buf))
        }
    }

    impl IntoIterator for Hash {
        type Item = u8;
        type IntoIter = <Array as IntoIterator>::IntoIter;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl Deref for Hash {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &*self.0
        }
    }

    pub fn elem_hash(x: Nullifier) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Elem".as_bytes());
        hasher.update(&canonical::serialize(&x).unwrap());
        Hash(hasher.finalize().into_bytes())
    }

    pub fn leaf_hash(x: Nullifier) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Leaf".as_bytes());
        hasher.update(&canonical::serialize(&x).unwrap());
        Hash(hasher.finalize().into_bytes())
    }

    pub fn branch_hash(l: Hash, r: Hash) -> Hash {
        let mut hasher = blake2::Blake2b::with_params(&[], &[], "AAPSet Branch".as_bytes());
        hasher.update("l".as_bytes());
        hasher.update(&l.0);
        hasher.update("r".as_bytes());
        hasher.update(&r.0);
        Hash(hasher.finalize().into_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SetMerkleTree {
    EmptySubtree,
    ForgottenSubtree {
        value: set_hash::Hash,
    },
    Leaf {
        value: set_hash::Hash,
        /// how far above the "true" leaf level this leaf is
        height: usize,
        elem: Nullifier,
    },
    Branch {
        value: set_hash::Hash,
        l: Box<SetMerkleTree>,
        r: Box<SetMerkleTree>,
    },
}

impl SetMerkleTree {
    fn new_leaf(height: usize, elem: Nullifier) -> Self {
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let elem_bits = elem_bit_vec.into_iter();

        let mut h = set_hash::leaf_hash(elem);
        for sib_is_left in elem_bits.into_iter().take(height) {
            let (l, r) = if sib_is_left {
                (*set_hash::EMPTY_HASH, h)
            } else {
                (h, *set_hash::EMPTY_HASH)
            };
            h = set_hash::branch_hash(l, r)
        }

        Self::Leaf {
            value: h,
            height,
            elem,
        }
    }

    fn new_branch(l: Box<Self>, r: Box<Self>) -> Self {
        Self::Branch {
            value: set_hash::branch_hash(l.hash(), r.hash()),
            l,
            r,
        }
    }
}

impl Default for SetMerkleTree {
    fn default() -> Self {
        Self::EmptySubtree
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SetMerkleTerminalNode {
    EmptySubtree,
    Leaf {
        /// how far above the "true" leaf level this leaf is
        height: usize,
        elem: Nullifier,
    },
}

impl CanonicalSerialize for SetMerkleTerminalNode {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            SetMerkleTerminalNode::EmptySubtree => {
                writer.write_all(&[0]).map_err(SerializationError::from)
            }
            SetMerkleTerminalNode::Leaf { height, elem } => {
                writer.write_all(&[1]).map_err(SerializationError::from)?;
                CanonicalSerialize::serialize(height, &mut writer)?;
                CanonicalSerialize::serialize(elem, &mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            SetMerkleTerminalNode::EmptySubtree => 0,
            SetMerkleTerminalNode::Leaf { height, elem } => {
                height.serialized_size() + elem.serialized_size()
            }
        }
    }
}

impl CanonicalDeserialize for SetMerkleTerminalNode {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut flag = [0u8];
        reader.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(SetMerkleTerminalNode::EmptySubtree),
            1 => {
                let height = CanonicalDeserialize::deserialize(&mut reader)?;
                let elem = CanonicalDeserialize::deserialize(&mut reader)?;
                Ok(SetMerkleTerminalNode::Leaf { height, elem })
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl SetMerkleTerminalNode {
    fn value(&self) -> set_hash::Hash {
        use SetMerkleTerminalNode::*;
        match self {
            EmptySubtree => *set_hash::EMPTY_HASH,
            Leaf { height, elem } => {
                let elem_bit_vec = set_hash::elem_hash(*elem).into_bits();

                // the path only goes until a terminal node is reached, so skip
                // part of the bit-vec
                let elem_bits = elem_bit_vec.into_iter();

                let mut running_hash = set_hash::leaf_hash(*elem);

                // if the height is too large, keep hashing
                for sib_is_left in elem_bits.chain(core::iter::repeat(false)).take(*height) {
                    let sib = *set_hash::EMPTY_HASH;
                    running_hash = {
                        let l = if sib_is_left { sib } else { running_hash };
                        let r = if sib_is_left { running_hash } else { sib };
                        set_hash::branch_hash(l, r)
                    };
                }

                running_hash
            }
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct SetMerkleProof {
    terminal_node: SetMerkleTerminalNode,
    path: Vec<set_hash::Hash>,
}

impl SetMerkleProof {
    pub fn check(&self, elem: Nullifier, root: &set_hash::Hash) -> Result<bool, set_hash::Hash> {
        let mut running_hash = self.terminal_node.value();

        let elem_bit_vec = set_hash::elem_hash(elem).into_bits();

        // the path only goes until a terminal node is reached, so skip
        // part of the bit-vec
        let start_bit = elem_bit_vec.len() - self.path.len();
        let elem_bits = elem_bit_vec.into_iter().skip(start_bit);

        for (sib, sib_is_left) in self.path.iter().zip(elem_bits) {
            let sib = *sib;
            running_hash = {
                let l = if sib_is_left { sib } else { running_hash };
                let r = if sib_is_left { running_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
        }

        if &running_hash == root {
            Ok(match &self.terminal_node {
                SetMerkleTerminalNode::EmptySubtree {} => false,
                SetMerkleTerminalNode::Leaf {
                    elem: leaf_elem, ..
                } => (leaf_elem == &elem),
            })
        } else {
            Err(running_hash)
        }
    }
}

impl SetMerkleTree {
    pub fn sparse(root: set_hash::Hash) -> Self {
        Self::ForgottenSubtree { value: root }
    }

    pub fn hash(&self) -> set_hash::Hash {
        use SetMerkleTree::*;
        match self {
            EmptySubtree => *set_hash::EMPTY_HASH,
            Leaf { value, .. } => *value,
            ForgottenSubtree { value, .. } => *value,
            Branch { value, .. } => *value,
        }
    }

    /// Returns `None` if the element is in a forgotten subtree
    pub fn contains(&self, elem: Nullifier) -> Option<(bool, SetMerkleProof)> {
        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let elem_bits = elem_bit_vec.into_iter().rev();

        let mut path = vec![];
        let mut end_branch = self;
        for sib_is_left in elem_bits {
            match end_branch {
                Branch { l, r, .. } => {
                    path.push(if sib_is_left { l.hash() } else { r.hash() });
                    end_branch = if sib_is_left { r.as_ref() } else { l.as_ref() };
                }
                _ => {
                    break;
                }
            }
        }

        match end_branch {
            ForgottenSubtree { .. } => None,
            EmptySubtree => {
                path.reverse();
                Some((
                    false,
                    SetMerkleProof {
                        terminal_node: SetMerkleTerminalNode::EmptySubtree,
                        path,
                    },
                ))
            }
            Leaf {
                height,
                elem: leaf_elem,
                ..
            } => {
                path.reverse();
                Some((
                    &elem == leaf_elem,
                    SetMerkleProof {
                        terminal_node: SetMerkleTerminalNode::Leaf {
                            height: *height,
                            elem: *leaf_elem,
                        },
                        path,
                    },
                ))
            }
            Branch { .. } => panic!("This tree has more levels than my hash has bits!"),
        }
    }

    pub fn insert(&mut self, elem: Nullifier) -> Option<()> {
        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let mut end_height = elem_bit_vec.len();
        let elem_bits = elem_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);
        for sib_is_left in elem_bits {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    break;
                }
                EmptySubtree => {
                    break;
                }
                Branch { l, r, .. } => {
                    let (sib, next) = if sib_is_left { (l, r) } else { (r, l) };
                    end_branch = *next;
                    sib
                }

                Leaf { height, elem, .. } => {
                    debug_assert_eq!(height, end_height);
                    // Figure out if this leaf is down the same tree or if it's a sibling
                    let leaf_is_left = {
                        debug_assert!(height > 0);
                        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
                        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> =
                            BitVec::try_from(elem_bytes).unwrap();
                        !elem_bit_vec[height - 1]
                    };

                    let new_leaf = Box::new(Self::new_leaf(height - 1, elem));
                    let (new_end_branch, new_sib) = if leaf_is_left == sib_is_left {
                        (Box::new(EmptySubtree), new_leaf)
                    } else {
                        (new_leaf, Box::new(EmptySubtree))
                    };

                    end_branch = *new_end_branch;
                    new_sib
                }
            };
            end_height -= 1;

            siblings.push((sib_is_left, sib));
        }

        let mut ret = Some(());

        end_branch = match end_branch {
            ForgottenSubtree { value } => {
                ret = None;
                ForgottenSubtree { value }
            }
            EmptySubtree => Self::new_leaf(end_height, elem),
            Branch { .. } => panic!("This tree has more levels than my hash has bits!"),
            Leaf {
                value,
                height,
                elem: leaf_elem,
            } => {
                assert_eq!(height, end_height);
                assert_eq!(elem, leaf_elem);
                Leaf {
                    value,
                    height,
                    elem: leaf_elem,
                }
            }
        };

        siblings.reverse();
        for (sib_is_left, sib) in siblings {
            let (l, r) = if sib_is_left {
                (sib, Box::new(end_branch))
            } else {
                (Box::new(end_branch), sib)
            };

            end_branch = Self::new_branch(l, r);
        }
        *self = end_branch;

        ret
    }

    pub fn forget(&mut self, elem: Nullifier) -> Option<SetMerkleProof> {
        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();
        let elem_bits = elem_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);
        for sib_is_left in elem_bits {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    break;
                }
                EmptySubtree => {
                    break;
                }
                Branch { l, r, .. } => {
                    let (sib, next) = if sib_is_left { (l, r) } else { (r, l) };
                    end_branch = *next;
                    sib
                }
                Leaf { .. } => {
                    break;
                }
            };

            siblings.push((sib_is_left, sib));
        }

        let mut ret = None;
        if let Leaf {
            height,
            elem: leaf_elem,
            ..
        } = end_branch
        {
            if leaf_elem == elem {
                ret = Some(SetMerkleProof {
                    terminal_node: SetMerkleTerminalNode::Leaf {
                        height,
                        elem: leaf_elem,
                    },
                    path: siblings.iter().map(|(_, s)| s.hash()).rev().collect(),
                });
                end_branch = ForgottenSubtree {
                    value: end_branch.hash(),
                };
            }
        }

        siblings.reverse();
        for (sib_is_left, sib) in siblings {
            let (l, r) = if sib_is_left {
                (sib, Box::new(end_branch))
            } else {
                (Box::new(end_branch), sib)
            };
            end_branch = match (l.as_ref(), r.as_ref()) {
                (ForgottenSubtree { .. }, ForgottenSubtree { .. }) => ForgottenSubtree {
                    value: Self::new_branch(l, r).hash(),
                },
                _ => Self::new_branch(l, r),
            };
        }
        *self = end_branch;

        ret
    }

    pub fn remember(
        &mut self,
        elem: Nullifier,
        proof: SetMerkleProof,
    ) -> Result<(), set_hash::Hash> {
        // Check the proof before we do anything. After checking, we can
        // safely assume that all the values along the path match.
        let elem_in_set = proof.check(elem, &self.hash())?;

        use SetMerkleTree::*;
        let elem_bytes: Vec<u8> = set_hash::elem_hash(elem).into_iter().collect();
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = BitVec::try_from(elem_bytes).unwrap();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);

        // TODO: this is redundant with the checking
        let path_hashes = {
            let mut running_hash = proof.terminal_node.value();

            let mut ret = vec![];
            ret.reserve(proof.path.len() + 1);

            for (sib_is_left, sib_hash) in
                elem_bit_vec.iter().rev().zip(proof.path.iter().rev()).rev()
            {
                let (l, r) = if *sib_is_left {
                    (*sib_hash, running_hash)
                } else {
                    (running_hash, *sib_hash)
                };
                ret.push((running_hash, sib_hash));
                running_hash = Self::new_branch(
                    Box::new(ForgottenSubtree { value: l }),
                    Box::new(ForgottenSubtree { value: r }),
                )
                .hash();
            }

            ret.reverse();
            ret
        };

        let elem_bits = elem_bit_vec.into_iter().rev();

        for (sib_is_left, (node_hash, sib_hash)) in elem_bits.zip(path_hashes.into_iter()) {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    end_branch = ForgottenSubtree { value: node_hash };
                    Box::new(ForgottenSubtree { value: *sib_hash })
                }
                EmptySubtree => {
                    unreachable!();
                } // TODO: is this unreachable?
                Branch { l, r, .. } => {
                    let (sib, next) = if sib_is_left { (l, r) } else { (r, l) };
                    end_branch = *next;
                    sib
                }
                Leaf {
                    height,
                    elem: leaf_elem,
                    ..
                } => {
                    assert!(!elem_in_set);
                    end_branch = EmptySubtree;
                    Box::new(Self::new_leaf(height - 1, leaf_elem))
                }
            };

            siblings.push((sib_is_left, sib));
        }

        end_branch = match end_branch {
            ForgottenSubtree { value } => {
                match proof.terminal_node {
                    SetMerkleTerminalNode::EmptySubtree => {
                        // TODO: should this be possible????? it feels like it
                        // shouldn't be
                        assert_eq!(value, *set_hash::EMPTY_HASH);
                        EmptySubtree
                    }

                    SetMerkleTerminalNode::Leaf { height, elem } => Self::new_leaf(height, elem),
                }
            }
            _ => end_branch,
        };

        siblings.reverse();
        for (sib_is_left, sib) in siblings {
            let (l, r) = if sib_is_left {
                (sib, Box::new(end_branch))
            } else {
                (Box::new(end_branch), sib)
            };
            end_branch = Self::new_branch(l, r);
        }
        *self = end_branch;

        Ok(())
    }
}

pub fn set_merkle_lw_multi_insert(
    inserts: Vec<(Nullifier, SetMerkleProof)>,
    root: set_hash::Hash,
) -> Result<(set_hash::Hash, Vec<SetMerkleProof>), set_hash::Hash> {
    let mut nulls = vec![];
    let mut s = SetMerkleTree::ForgottenSubtree { value: root };
    for (n, proof) in inserts {
        s.remember(n, proof)?;
        nulls.push(n);
    }
    for n in nulls.iter() {
        s.insert(*n).unwrap();
    }
    Ok((
        s.hash(),
        nulls
            .into_iter()
            .map(|n| s.contains(n).unwrap().1)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
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
                let elem_bit_vec = set_hash::elem_hash(elem).into_bits();
                let pf = elem_bit_vec
                    .iter()
                    .map(|_| {
                        let mut buf = [0u8; 32];
                        prng.fill_bytes(&mut buf);
                        let mut hasher = blake2::Blake2b::with_params(&[], &[], "".as_bytes());
                        hasher.update(&buf);
                        set_hash::Hash::new(hasher.finalize().into_bytes())
                    })
                    .collect();
                let pf = SetMerkleProof {
                    terminal_node: SetMerkleTerminalNode::EmptySubtree,
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
        let mut lw_t = SetMerkleTree::ForgottenSubtree { value: t.hash() };
        assert_eq!(t.hash(), lw_t.hash());

        let update_elems: Vec<_> = updates.iter().map(|u| update_vals[u]).collect();

        for (u, elem) in updates.iter().zip(update_elems.iter()) {
            let elem = *elem;
            hset.insert(u);
            let (in_set, pf) = t.contains(elem).unwrap();
            t.insert(elem);
            assert_eq!(pf.check(elem, &lw_t.hash()).unwrap(), in_set);
            lw_t.remember(elem, pf).unwrap();
            lw_t.insert(elem).unwrap();
            let (in_new_lw_t, new_lw_pf) = lw_t.contains(elem).unwrap();
            assert!(in_new_lw_t);

            assert!(t.contains(elem).unwrap().0);

            assert_eq!(lw_t.hash(), t.hash());
            lw_t.forget(elem).unwrap();
            assert!(lw_t.contains(elem).is_none());

            assert!(new_lw_pf.check(elem, &lw_t.hash()).unwrap());
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

            let (t_contains, pf) = t.contains(elem).unwrap();

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
    fn quickcheck_merkle_tree_set_regressions() {
        test_merkle_tree_set(vec![20, 0], vec![Ok(20)]);
        test_merkle_tree_set(vec![0, 38], vec![Err(0), Ok(1), Ok(38)])
    }

    #[test]
    fn quickcheck_merkle_tree_set() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_merkle_tree_set as fn(Vec<_>, Vec<_>) -> ());
    }
}
