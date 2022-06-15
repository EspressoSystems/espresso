#![deny(warnings)]
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
    struct Key(Nullifier);
    struct Value(Nullifier);

    impl commit::Committable for Key {
        fn commit(&self) -> commit::Commitment<Self> {
            commit::RawCommitmentBuilder::new("CAPkv Key")
                .var_size_bytes(&canonical::serialize(&self.0).unwrap())
                .finalize()
        }
    }

    pub enum KVMerkleTreeNode {
        EmptySubtree,
        Leaf { key: Nullifier, value: Nullifier },
        Branch { l: Hash, r: Hash },
    }

    impl KVMerkleTreeNode {
        fn hash(&self) -> Hash {
            Hash(self.commit())
        }
    }

    impl commit::Committable for KVMerkleTreeNode {
        fn commit(&self) -> commit::Commitment<Self> {
            use commit::RawCommitmentBuilder;
            use KVMerkleTreeNode::*;
            match self {
                EmptySubtree => RawCommitmentBuilder::new("CAPkv Empty").finalize(),
                Leaf { key, value } => RawCommitmentBuilder::new("CAPkv Leaf")
                    .var_size_bytes(&canonical::serialize(key).unwrap())
                    .finalize(),

                Branch { l, r } => RawCommitmentBuilder::new("CAPkv Branch")
                    .field("l", l.0)
                    .field("r", r.0)
                    .finalize(),
            }
        }
    }

    #[tagged_blob("KV")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Hash(commit::Commitment<KVMerkleTreeNode>);

    impl From<Hash> for commit::Commitment<KVMerkleTreeNode> {
        fn from(h: Hash) -> Self {
            h.0
        }
    }

    lazy_static::lazy_static! {
        pub static ref EMPTY_HASH: Hash = Hash(KVMerkleTreeNode::EmptySubtree.commit());
    }

    pub fn leaf_hash(key: Nullifier, value: Nullifier) -> Hash {
        KVMerkleTreeNode::Leaf { key, value }.hash()
    }

    pub fn branch_hash(l: Hash, r: Hash) -> Hash {
        KVMerkleTreeNode::Branch { l, r }.hash()
    }

    pub fn key_bits(x: Nullifier) -> BitVec<bitvec::order::Lsb0, u8> {
        Key(x).commit().into_bits()
    }
}

/// Note: this type implements PartialEq so that containing types can derive PartialEq, mostly for
/// testing purposes. The implementation tests for logical equality of the represented set, ignoring
/// sparseness. That is, any two sets with the same root hash will compare equal, even if the
/// elements retained in memory are different between the two sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KVMerkleTree {
    EmptySubtree,
    ForgottenSubtree {
        key: set_hash::Hash,
    },
    Leaf {
        key: set_hash::Hash,
        value: Nullifier,
        /// how far above the "true" leaf level this leaf is
        height: usize,
    },
    Branch {
        key: set_hash::Hash,
        l: Box<KVMerkleTree>,
        r: Box<KVMerkleTree>,
    },
}

impl PartialEq<Self> for KVMerkleTree {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl<'a> arbitrary::Arbitrary<'a> for KVMerkleTree {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut s = Self::default();
        for n in u.arbitrary_iter::<ArbitraryNullifier>()? {
            s.insert(n?.into());
        }
        Ok(s)
    }
}

impl KVMerkleTree {
    fn new_leaf(height: usize, key: Nullifier, value: Nullifier) -> Self {
        let key_bit_vec: BitVec<bitvec::order::Lsb0, u8> = set_hash::elem_bits(key);
        let key_bits = key_bit_vec.into_iter();

        let mut h = set_hash::leaf_hash(key);
        for sib_is_left in key_bits.into_iter().take(height) {
            let (l, r) = if sib_is_left {
                (*set_hash::EMPTY_HASH, h)
            } else {
                (h, *set_hash::EMPTY_HASH)
            };
            h = set_hash::branch_hash(l, r);
        }

        Self::Leaf {
            key: h,
            value,
            height,
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

impl Default for KVMerkleTree {
    fn default() -> Self {
        Self::EmptySubtree
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KVMerkleTerminalNode {
    EmptySubtree,
    Leaf {
        /// how far above the "true" leaf level this leaf is
        height: usize,
        key: Nullifier,
        value: Nullifier,
    },
}

impl CanonicalSerialize for KVMerkleTerminalNode {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            KVMerkleTerminalNode::EmptySubtree => {
                writer.write_all(&[0]).map_err(SerializationError::from)
            }
            SetMerkleTerminalNode::Leaf { key, value, height } => {
                writer.write_all(&[1]).map_err(SerializationError::from)?;
                CanonicalSerialize::serialize(height, &mut writer)?;
                CanonicalSerialize::serialize(key, &mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            KVMerkleTerminalNode::EmptySubtree => 0,
            KVMerkleTerminalNode::Leaf { key, value, height } => {
                height.serialized_size() + key.serialized_size()
            }
        }
    }
}

impl CanonicalDeserialize for KVMerkleTerminalNode {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut flag = [0u8];
        reader.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(KVMerkleTerminalNode::EmptySubtree),
            1 => {
                let height = CanonicalDeserialize::deserialize(&mut reader)?;
                let key = CanonicalDeserialize::deserialize(&mut reader)?;
                Ok(KVMerkleTerminalNode::Leaf { key, value, height })
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl KVMerkleTerminalNode {
    fn value(&self) -> set_hash::Hash {
        use KVMerkleTerminalNode::*;
        match self {
            EmptySubtree => *set_hash::EMPTY_HASH,
            Leaf { key, value, height } => {
                let key_bit_vec = set_hash::elem_bits(*key);

                // the path only goes until a terminal node is reached, so skip
                // part of the bit-vec
                let key_bits = key_bit_vec.into_iter();

                let mut running_hash = set_hash::leaf_hash(*key);

                // if the height is too large, keep hashing
                for sib_is_left in key_bits.chain(core::iter::repeat(false)).take(*height) {
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
pub struct KVMerkleProof {
    terminal_node: KVMerkleTerminalNode,
    path: Vec<set_hash::Hash>,
}

impl KVMerkleProof {
    pub fn check(&self, key: Nullifier, root: &set_hash::Hash) -> Result<bool, set_hash::Hash> {
        let mut running_hash = self.terminal_node.value();

        let key_bit_vec = set_hash::key_bits(key);

        // the path only goes until a terminal node is reached, so skip
        // part of the bit-vec
        let start_bit = key_bit_vec.len() - self.path.len();
        let key_bits = key_bit_vec.into_iter().skip(start_bit);

        for (sib, sib_is_left) in self.path.iter().zip(key_bits) {
            let sib = *sib;
            running_hash = {
                let l = if sib_is_left { sib } else { running_hash };
                let r = if sib_is_left { running_hash } else { sib };
                set_hash::branch_hash(l, r)
            };
        }

        if &running_hash == root {
            Ok(match &self.terminal_node {
                KVMerkleTerminalNode::EmptySubtree {} => false,
                KVMerkleTerminalNode::Leaf {
                    key: leaf_key, ..
                } => (leaf_key == &key),
            })
        } else {
            Err(running_hash)
        }
    }
}

impl KVMerkleTree {
    pub fn sparse(root: set_hash::Hash) -> Self {
        Self::ForgottenSubtree { key: root }
    }

    pub fn hash(&self) -> set_hash::Hash {
        use KVMerkleTree::*;
        match self {
            EmptySubtree => *set_hash::EMPTY_HASH,
            Leaf { key, .. } => *key,
            ForgottenSubtree { key, .. } => *key,
            Branch { key, .. } => *key,
        }
    }

    /// Returns `None` if the element is in a forgotten subtree
    pub fn contains(&self, key: Nullifier, value: Nullifier) -> Option<(bool, KVMerkleProof)> {
        use KVMerkleTree::*;
        let key_bit_vec: BitVec<bitvec::order::Lsb0, u8> = set_hash::key_bits(key);
        let key_bits = key_bit_vec.into_iter().rev();

        let mut path = vec![];
        let mut end_branch = self;
        for sib_is_left in key_bits {
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
                    KVMerkleProof {
                        terminal_node: KVMerkleTerminalNode::EmptySubtree,
                        path,
                    },
                ))
            }
            Leaf {
                height,
                key: leaf_key,
                ..
            } => {
                path.reverse();
                Some((
                    &key == leaf_key,
                    KVMerkleProof {
                        terminal_node: KVMerkleTerminalNode::Leaf {
                            height: *height,
                            key: *leaf_key,
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
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = set_hash::elem_bits(elem);
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
                        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> =
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
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = set_hash::elem_bits(elem);
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
        let elem_bit_vec: BitVec<bitvec::order::Lsb0, u8> = set_hash::elem_bits(elem);

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
