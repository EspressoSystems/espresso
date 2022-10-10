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
#![allow(dead_code)]

use crate::util::canonical;
use arbitrary_wrappers::*;
use ark_serialize::*;
use bitvec::vec::BitVec;
use core::mem;
use jf_cap::structs::Nullifier;
use serde::{Deserialize, Serialize};

pub mod set_hash {
    use super::*;
    use commit::Committable;
    use jf_utils::tagged_blob;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
    struct Elem(Nullifier);

    impl commit::Committable for Elem {
        fn commit(&self) -> commit::Commitment<Self> {
            commit::RawCommitmentBuilder::new("CAPSet Elem")
                .var_size_bytes(&canonical::serialize(&self.0).unwrap())
                .finalize()
        }
    }

    pub enum SetMerkleTreeNode {
        EmptySubtree,
        Leaf { elem: Nullifier },
        Branch { l: Hash, r: Hash },
    }

    impl SetMerkleTreeNode {
        fn hash(&self) -> Hash {
            Hash(self.commit())
        }
    }

    impl commit::Committable for SetMerkleTreeNode {
        fn commit(&self) -> commit::Commitment<Self> {
            use commit::RawCommitmentBuilder;
            use SetMerkleTreeNode::*;
            match self {
                EmptySubtree => RawCommitmentBuilder::new("CAPSet Empty").finalize(),
                Leaf { elem } => RawCommitmentBuilder::new("CAPSet Leaf")
                    .var_size_bytes(&canonical::serialize(elem).unwrap())
                    .finalize(),

                Branch { l, r } => RawCommitmentBuilder::new("CAPSet Branch")
                    .field("l", l.0)
                    .field("r", r.0)
                    .finalize(),
            }
        }
    }

    #[tagged_blob("SET")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Hash(commit::Commitment<SetMerkleTreeNode>);

    impl From<Hash> for commit::Commitment<SetMerkleTreeNode> {
        fn from(h: Hash) -> Self {
            h.0
        }
    }

    lazy_static::lazy_static! {
        pub static ref EMPTY_HASH: Hash = Hash(SetMerkleTreeNode::EmptySubtree.commit());
    }

    pub fn leaf_hash(elem: Nullifier) -> Hash {
        SetMerkleTreeNode::Leaf { elem }.hash()
    }

    pub fn branch_hash(l: Hash, r: Hash) -> Hash {
        SetMerkleTreeNode::Branch { l, r }.hash()
    }

    pub fn elem_bits(x: Nullifier) -> BitVec<u8, bitvec::order::Lsb0> {
        Elem(x).commit().into_bits()
    }
}

/// Note: this type implements PartialEq so that containing types can derive PartialEq, mostly for
/// testing purposes. The implementation tests for logical equality of the represented set, ignoring
/// sparseness. That is, any two sets with the same root hash will compare equal, even if the
/// elements retained in memory are different between the two sets.
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

impl PartialEq<Self> for SetMerkleTree {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl<'a> arbitrary::Arbitrary<'a> for SetMerkleTree {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut s = Self::default();
        for n in u.arbitrary_iter::<ArbitraryNullifier>()? {
            s.insert(n?.into());
        }
        Ok(s)
    }
}

impl SetMerkleTree {
    fn new_leaf(height: usize, elem: Nullifier) -> Self {
        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> = set_hash::elem_bits(elem);
        let elem_bits = elem_bit_vec.into_iter();

        let mut h = set_hash::leaf_hash(elem);
        for sib_is_left in elem_bits.into_iter().take(height) {
            let (l, r) = if sib_is_left {
                (*set_hash::EMPTY_HASH, h)
            } else {
                (h, *set_hash::EMPTY_HASH)
            };
            h = set_hash::branch_hash(l, r);
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
                let elem_bit_vec = set_hash::elem_bits(*elem);

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

        let elem_bit_vec = set_hash::elem_bits(elem);

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
                } => leaf_elem == &elem,
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
        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> = set_hash::elem_bits(elem);
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
        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> = set_hash::elem_bits(elem);
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
                        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> =
                            set_hash::elem_bits(elem);
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
        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> = set_hash::elem_bits(elem);
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
        // Check the proof before we do anything.
        //After checking, we can safely assume that all the values along the path match.
        //This first check can be removed as an optimization opportunity if we really need to,
        //but keeping it in is defensive programming
        let elem_in_set = proof.check(elem, &self.hash())?;

        use SetMerkleTree::*;
        let elem_bit_vec: BitVec<u8, bitvec::order::Lsb0> = set_hash::elem_bits(elem);

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);

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
                    // This is unreachable because if there are any steps
                    // in the non-inclusion path, the tree cannot be empty.
                    unreachable!();
                }
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
                        // NOTE: this looks unreachable, but in fact can be
                        // reached by
                        // `test_merkle_tree_set(vec![0], vec![])`
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

    pub fn multi_insert(
        &mut self,
        inserts: impl IntoIterator<Item = (Nullifier, SetMerkleProof)>,
    ) -> Result<Vec<SetMerkleProof>, set_hash::Hash> {
        let mut nulls = vec![];
        for (n, proof) in inserts {
            self.remember(n, proof)?;
            nulls.push(n);
        }
        for n in nulls.iter() {
            self.insert(*n).unwrap();
        }
        Ok(nulls
            .into_iter()
            .map(|n| self.contains(n).unwrap().1)
            .collect())
    }
}

pub fn set_merkle_lw_multi_insert(
    inserts: Vec<(Nullifier, SetMerkleProof)>,
    root: set_hash::Hash,
) -> Result<(set_hash::Hash, Vec<SetMerkleProof>), set_hash::Hash> {
    let mut s = SetMerkleTree::ForgottenSubtree { value: root };
    let proofs = s.multi_insert(inserts)?;
    Ok((s.hash(), proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::time::Instant; //????/

    #[test]
    fn test_set_merkle_speed() {
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let elems = (1..1000)
            .map(|_| Nullifier::random_for_test(&mut prng))
            .collect::<Vec<_>>();
        let pfs = elems
            .into_iter()
            .map(|elem| {
                let elem_bit_vec = set_hash::elem_bits(elem);
                let pf = elem_bit_vec
                    .iter()
                    .map(|_| set_hash::leaf_hash(Nullifier::random_for_test(&mut prng)))
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
            .chain(checks.iter().filter_map(|x| x.ok()))
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
        test_merkle_tree_set(vec![0, 38], vec![Err(0), Ok(1), Ok(38)]);
        test_merkle_tree_set(vec![0], vec![])
    }

    #[test]
    fn quickcheck_merkle_tree_set() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_merkle_tree_set as fn(Vec<_>, Vec<_>) -> ());
    }
}
