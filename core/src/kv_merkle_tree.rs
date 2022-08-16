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

#![deny(warnings)]
#![allow(dead_code)]

use crate::tree_hash::*;
use ark_serialize::*;
use core::fmt::Debug;
use core::mem;
use generic_array::{arr::AddLength, ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use typenum::{Unsigned, U1};

/// The core enum of the key-value Merkle tree. Making use of KVTreeHash, it is generic over branch-arity (number of branches).
/// Note: this type implements PartialEq so that containing types can derive PartialEq, mostly for
/// testing purposes. The implementation tests for logical equality of the represented set, ignoring
/// sparseness. That is, any two sets with the same root hash will compare equal, even if the
/// elements retained in memory are different between the two sets.
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KVMerkleTree<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    EmptySubtree,
    ForgottenSubtree {
        digest: KVHash::Digest,
    },
    Leaf {
        digest: KVHash::Digest,
        /// how far above the "true" leaf level this leaf is
        height: usize,
        key: KVHash::Key,
        value: KVHash::Value,
    },
    Branch {
        digest: KVHash::Digest,
        children: Box<
            GenericArray<
                KVMerkleTree<KVHash>,
                <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output,
            >,
        >,
    },
}

impl<KVHash> PartialEq<Self> for KVMerkleTree<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl<KVHash> KVMerkleTree<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    /// Create a new leaf in the tree
    fn new_leaf(height: usize, key: KVHash::Key, value: KVHash::Value) -> Self {
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));
        let key_bits = key_bit_vec.into_iter();

        let mut h = KVHash::hash_leaf(key.clone(), value.clone());

        for sib in key_bits.into_iter().take(height) {
            let mut children = GenericArray::from_iter(vec![
                KVHash::empty_digest();
                <KVHash::BranchArityMinus1>::to_usize()
                    + 1
            ]);
            children[sib as usize] = h;
            h = KVHash::hash_branch(&children);
        }

        Self::Leaf {
            digest: h,
            height,
            key,
            value,
        }
    }

    /// Create a new branch in the tree
    fn new_branch(
        children: GenericArray<
            Self,
            <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output,
        >,
    ) -> Self {
        let child_hashes = GenericArray::from_iter(children.clone().into_iter().map(|d| d.hash()));
        Self::Branch {
            digest: KVHash::hash_branch(&child_hashes),
            children: Box::new(children),
        }
    }
}

impl<KVHash> Default for KVMerkleTree<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    /// The default tree is an empty subtree
    fn default() -> Self {
        Self::EmptySubtree
    }
}

/// Terminal nodes in a KVMT are either a leaf or an empty subtree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    EmptySubtree,
    Leaf {
        /// How far above the "true" leaf level this leaf is. This
        /// is used for reducing the memory footprint of a tree and proof when a leaf
        /// is the only element in a subtree, indicated by a height of 0.
        height: usize,
        key: KVHash::Key,
        value: KVHash::Value,
    },
}

impl<KVHash> CanonicalSerialize for KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            KVMerkleTerminalNode::<KVHash>::EmptySubtree => {
                writer.write_all(&[0]).map_err(SerializationError::from)
            }
            KVMerkleTerminalNode::<KVHash>::Leaf { height, key, value } => {
                writer.write_all(&[1]).map_err(SerializationError::from)?;
                CanonicalSerialize::serialize(height, &mut writer)?;
                CanonicalSerialize::serialize(key, &mut writer)?;
                CanonicalSerialize::serialize(value, &mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            KVMerkleTerminalNode::<KVHash>::EmptySubtree => 0,
            KVMerkleTerminalNode::<KVHash>::Leaf { height, key, value } => {
                height.serialized_size() + key.serialized_size() + value.serialized_size()
            }
        }
    }
}

impl<KVHash> CanonicalDeserialize for KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut flag = [0u8];
        reader.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(KVMerkleTerminalNode::<KVHash>::EmptySubtree),
            1 => {
                let height = CanonicalDeserialize::deserialize(&mut reader)?;
                let key = CanonicalDeserialize::deserialize(&mut reader)?;
                let value = CanonicalDeserialize::deserialize(&mut reader)?;
                Ok(KVMerkleTerminalNode::<KVHash>::Leaf { height, key, value })
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl<KVHash> KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    fn value(&self) -> KVHash::Digest {
        use KVMerkleTerminalNode::*;
        match self {
            EmptySubtree => KVHash::empty_digest(),
            Leaf { height, key, value } => {
                let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));

                // the path only goes until a terminal node is reached, so skip
                // part of the bit-vec
                let key_bits = key_bit_vec.into_iter();

                let mut running_hash = KVHash::hash_leaf(key.clone(), value.clone());

                // if the height is too large, keep hashing
                for sib in key_bits.chain(core::iter::repeat(0)).take(*height) {
                    let mut children = GenericArray::from_iter(vec![
                        KVHash::empty_digest();
                        <KVHash::BranchArityMinus1>::to_usize()
                            + 1
                    ]);
                    children[sib as usize] = running_hash;
                    running_hash = KVHash::hash_branch(&children);
                }
                running_hash
            }
        }
    }
}

/// Structure for proofs in the KVMT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KVMerkleProof<KVHash>
where
    KVHash: KVTreeHash,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    terminal_node: KVMerkleTerminalNode<KVHash>,
    //each level of path in the tree includes all but 1 of the siblings,
    //hence BranchArityMinus1
    path: Vec<GenericArray<KVHash::Digest, KVHash::BranchArityMinus1>>,
}

impl<KVHash> KVMerkleProof<KVHash>
where
    KVHash: KVTreeHash,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    /// Checks correctness of a proof by recreating the proof path from the given key
    pub fn check(
        &self,
        key: KVHash::Key,
        root: KVHash::Digest,
    ) -> Option<(Option<KVHash::Value>, KVHash::Digest)> {
        let mut running_hash = self.terminal_node.value();

        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));

        // the path only goes until a terminal node is reached, so skip
        // part of the bit-vec
        let start_bit = key_bit_vec.len() - self.path.len();
        let key_bits = key_bit_vec.into_iter().skip(start_bit);

        for (sibs, sib_position) in self.path.iter().zip(key_bits) {
            let mut sibs_vec: Vec<_> = sibs.to_vec();
            running_hash = {
                sibs_vec.insert(sib_position as usize, running_hash);
                let sibs_arr: GenericArray<
                    KVHash::Digest,
                    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output,
                > = GenericArray::from_exact_iter(sibs_vec).unwrap();
                KVHash::hash_branch(&sibs_arr)
            };
        }

        if running_hash == root {
            match &self.terminal_node {
                KVMerkleTerminalNode::<KVHash>::EmptySubtree {} => Some((None, running_hash)),
                KVMerkleTerminalNode::<KVHash>::Leaf {
                    key: leaf_key,
                    value: leaf_value,
                    ..
                } => {
                    if leaf_key == &key {
                        Some((Some(leaf_value.clone()), running_hash))
                    } else {
                        Some((None, running_hash))
                    }
                }
            }
        } else {
            Some((None, running_hash))
        }
    }
}

impl<KVHash> KVMerkleTree<KVHash>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    /// Representation for a sparse Merkle tree
    pub fn sparse(root: KVHash::Digest) -> Self {
        Self::ForgottenSubtree { digest: root }
    }

    /// Returns the digest for a node in a KVMT
    pub fn hash(&self) -> KVHash::Digest {
        use KVMerkleTree::*;
        match self {
            EmptySubtree => KVHash::empty_digest(),
            Leaf { digest, .. } => *digest,
            ForgottenSubtree { digest, .. } => *digest,
            Branch { digest, .. } => *digest,
        }
    }

    /// Returns the value and proof for a queried key. If the key exists in a forgotten subtree,
    /// returns None.
    pub fn lookup(
        &self,
        key: KVHash::Key,
    ) -> Option<(Option<KVHash::Value>, KVMerkleProof<KVHash>)> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));
        let key_bits = key_bit_vec.into_iter().rev();

        let mut path = Vec::new();
        let mut end_branch = self;
        for sib in key_bits {
            match end_branch {
                Branch { children, .. } => {
                    let mut children_l: Vec<_> =
                        children[0..sib as usize].iter().map(|d| d.hash()).collect();
                    let mut children_r: Vec<_> = children[sib as usize + 1..]
                        .iter()
                        .map(|d| d.hash())
                        .collect();
                    children_l.append(&mut children_r);
                    let all_children = GenericArray::from_iter(children_l.into_iter());
                    path.push(all_children);
                    end_branch = &children[sib as usize];
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
                    None,
                    KVMerkleProof::<KVHash> {
                        terminal_node: KVMerkleTerminalNode::<KVHash>::EmptySubtree,
                        path,
                    },
                ))
            }
            Leaf {
                height,
                key: leaf_key,
                value: leaf_value,
                ..
            } => {
                path.reverse();
                let proof = KVMerkleProof::<KVHash> {
                    terminal_node: KVMerkleTerminalNode::<KVHash>::Leaf {
                        height: *height,
                        key: leaf_key.clone(),
                        value: leaf_value.clone(),
                    },
                    path,
                };
                if key == leaf_key.clone() {
                    Some((Some(leaf_value.clone()), proof))
                } else {
                    Some((None, proof))
                }
            }
            Branch { .. } => panic!("This tree has more levels than my hash has bits!"),
        }
    }

    /// Inserts a (key, value) pair into the KVMT. If a (key, value1) pair exists and (key, value2) is
    /// inserted, value1 is overwritten by value2.
    pub fn insert(&mut self, key: KVHash::Key, value: KVHash::Value) -> Option<()> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));
        let mut end_height = key_bit_vec.len();
        let key_bits = key_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);
        for pos in key_bits {
            let sibs = match end_branch {
                ForgottenSubtree { .. } => {
                    break;
                }
                EmptySubtree => {
                    break;
                }
                Branch { children, .. } => {
                    let target = children[pos as usize].clone();
                    end_branch = target;
                    children
                }

                Leaf {
                    height,
                    key: leaf_key,
                    value: leaf_value,
                    ..
                } => {
                    debug_assert_eq!(height, end_height);
                    // Figure out if this leaf is down the same tree or if it's a sibling
                    let leaf_pos = {
                        debug_assert!(height > 0);
                        let key_bit_vec =
                            KVHash::traversal_of_digest(KVHash::hash_key(leaf_key.clone()));
                        key_bit_vec[height - 1]
                    };

                    let new_leaf = Self::new_leaf(height - 1, leaf_key, leaf_value);
                    let (new_end_branch, new_sibs) = if leaf_pos != pos {
                        let mut new_branches =
                            vec![EmptySubtree; <KVHash::BranchArityMinus1>::to_usize() + 1];
                        new_branches[leaf_pos as usize] = new_leaf.clone();
                        (EmptySubtree, new_branches)
                    } else {
                        let new_branches =
                            vec![EmptySubtree; <KVHash::BranchArityMinus1>::to_usize() + 1];
                        (new_leaf, new_branches)
                    };
                    end_branch = new_end_branch;
                    let sibs_arr: GenericArray<
                        KVMerkleTree<KVHash>,
                        <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output,
                    > = GenericArray::from_exact_iter(new_sibs).unwrap();
                    Box::new(sibs_arr)
                }
            };
            end_height -= 1;

            siblings.push((pos, sibs));
        }

        let mut ret = Some(());

        end_branch = match end_branch {
            ForgottenSubtree { digest } => {
                ret = None;
                ForgottenSubtree { digest }
            }
            EmptySubtree => Self::new_leaf(end_height, key, value),
            Branch { .. } => panic!("This tree has more levels than my hash has bits!"),
            Leaf {
                digest,
                height,
                key: leaf_key,
                ..
            } => {
                assert_eq!(height, end_height);
                assert_eq!(key, leaf_key);
                //rewrites value if (k,v1) exists and (k,v2) is inserted
                Leaf {
                    digest,
                    height,
                    key: leaf_key,
                    value,
                }
            }
        };

        siblings.reverse();
        for (pos, mut sibs) in siblings {
            sibs[pos as usize] = end_branch;
            end_branch = Self::new_branch(*sibs);
        }
        *self = end_branch;

        ret
    }

    pub fn forget(&mut self, key: KVHash::Key) -> Option<KVMerkleProof<KVHash>> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key.clone()));
        let key_bits = key_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);
        for pos in key_bits {
            let sibs = match end_branch {
                ForgottenSubtree { .. } => {
                    break;
                }
                EmptySubtree => {
                    break;
                }
                Branch { children, .. } => {
                    let target = children[pos as usize].clone();
                    end_branch = target;
                    children
                }
                Leaf { .. } => {
                    break;
                }
            };

            siblings.push((pos, sibs));
        }

        let mut ret = None;
        if let Leaf {
            height,
            key: leaf_key,
            value: leaf_value,
            ..
        } = end_branch.clone()
        {
            if leaf_key == key {
                ret = Some(KVMerkleProof::<KVHash> {
                    terminal_node: KVMerkleTerminalNode::<KVHash>::Leaf {
                        height,
                        key: leaf_key,
                        value: leaf_value,
                    },
                    //for each sibling vector, remove the target
                    //and iterate through remaining elements and get their hashes, then reverse
                    path: {
                        let mut path_vec = vec![];
                        for (pos, sibs) in siblings.clone() {
                            path_vec.push(
                                sibs.into_iter()
                                    .enumerate()
                                    .filter_map(|(i, dig)| {
                                        if i != pos as usize {
                                            Some(dig.hash())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect(),
                            );
                        }
                        path_vec.into_iter().rev().collect()
                    },
                });
                end_branch = ForgottenSubtree {
                    digest: end_branch.hash(),
                };
            }
        }

        siblings.reverse();
        for (pos, mut sibs) in siblings.clone() {
            sibs[pos as usize] = end_branch;
            let mut all_forgotten = true;
            for s in sibs.clone().into_iter() {
                match s {
                    ForgottenSubtree { .. } => (),
                    _ => all_forgotten = false,
                };
            }
            end_branch = if all_forgotten {
                ForgottenSubtree {
                    digest: Self::new_branch(*sibs.clone()).hash(),
                }
            } else {
                Self::new_branch(*sibs.clone())
            };
        }
        *self = end_branch;

        ret
    }

    pub fn remember(
        &mut self,
        key: KVHash::Key,
        proof: KVMerkleProof<KVHash>,
    ) -> Result<(), KVHash::Digest> {
        // Check the proof before we do anything. After checking, we can
        // safely assume that all the values along the path match. This first
        //check can be removed as an optimization opportunity if we really need
        //to, but keeping it in is defensive programming

        let key_in_set = matches!(proof.check(key.clone(), self.hash()), Some((Some(_), ..)));

        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);

        let path_hashes = {
            let mut running_hash = proof.terminal_node.value();

            let mut ret = vec![];
            ret.reserve(proof.path.len() + 1);

            for (sib, sib_hashes) in key_bit_vec.iter().rev().zip(proof.path.iter().rev()).rev() {
                let mut sibs_vec: Vec<_> = sib_hashes.to_vec();

                sibs_vec.insert(*sib as usize, running_hash);

                ret.push((running_hash, sibs_vec.clone()));
                let mut children = vec![];
                for branch in sibs_vec {
                    children.push(ForgottenSubtree { digest: branch })
                }
                running_hash =
                    Self::new_branch(GenericArray::from_exact_iter(children).unwrap()).hash();
            }

            ret.reverse();
            ret
        };

        let key_bits = key_bit_vec.into_iter().rev();

        for (pos, (node_hash, sib_hashes)) in key_bits.zip(path_hashes.into_iter()) {
            let sibs = match end_branch {
                ForgottenSubtree { .. } => {
                    end_branch = ForgottenSubtree { digest: node_hash };
                    let mut sib_branches = vec![];
                    for s in sib_hashes.iter() {
                        sib_branches.push(ForgottenSubtree { digest: *s });
                    }
                    Box::new(GenericArray::from_iter(sib_branches))
                }
                EmptySubtree => {
                    // This is unreachable because if there are any steps
                    // in the non-inclusion path, the tree cannot be empty.
                    unreachable!();
                }
                Branch { children, .. } => {
                    end_branch = children[pos as usize].clone();
                    children
                }
                Leaf {
                    height,
                    key: leaf_key,
                    value: leaf_value,
                    ..
                } => {
                    assert!(!key_in_set);
                    end_branch = EmptySubtree;
                    let mut sib_branches =
                        vec![EmptySubtree; <KVHash::BranchArityMinus1>::to_usize() + 1];
                    sib_branches[pos as usize] = Self::new_leaf(height, leaf_key, leaf_value);
                    Box::new(GenericArray::from_iter(sib_branches))
                }
            };

            siblings.push((pos, sibs));
        }

        end_branch = match end_branch {
            ForgottenSubtree { digest } => match proof.terminal_node {
                KVMerkleTerminalNode::<KVHash>::EmptySubtree => {
                    assert_eq!(digest, KVHash::empty_digest());
                    EmptySubtree
                }

                KVMerkleTerminalNode::<KVHash>::Leaf { height, key, value } => {
                    Self::new_leaf(height, key, value)
                }
            },
            _ => end_branch,
        };

        siblings.reverse();
        for (pos, mut sibs) in siblings {
            sibs[pos as usize] = end_branch;
            end_branch = Self::new_branch(*sibs);
        }
        *self = end_branch;

        Ok(())
    }
}

#[allow(clippy::type_complexity)]
pub fn kv_merkle_lw_multi_insert<KVHash>(
    inserts: Vec<(KVHash::Key, KVHash::Value, KVMerkleProof<KVHash>)>,
    root: KVHash::Digest,
) -> Result<(KVHash::Digest, Vec<KVMerkleProof<KVHash>>), KVHash::Digest>
where
    KVHash: KVTreeHash + Clone,
    <KVHash::BranchArityMinus1 as AddLength<KVHash::Digest, U1>>::Output:
        ArrayLength<KVMerkleTree<KVHash>>,
{
    let mut kvs = vec![];
    let mut s = KVMerkleTree::ForgottenSubtree { digest: root };
    for (k, v, proof) in inserts {
        s.remember(k.clone(), proof)?;
        kvs.push((k, v));
    }
    for (k, v) in kvs.iter() {
        s.insert(k.clone(), v.clone()).unwrap();
    }
    Ok((
        s.hash(),
        kvs.into_iter()
            .map(|(k, _)| s.lookup(k).unwrap().1)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_hash::committable_hash::*;
    use generic_array::arr;
    use jf_cap::structs::Nullifier;
    use quickcheck::QuickCheck;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::time::Instant;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
    struct TestNulls(Nullifier);
    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    struct TestNullsTag();

    impl CommitableHashTag for TestNullsTag {
        fn commitment_diversifier() -> &'static str {
            "CAP NullifierTest"
        }
    }

    type TestTreeHash = CommitableHash<TestNulls, TestNulls, TestNullsTag>;

    #[test]
    fn test_kv_merkle_speed() {
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let elems = (1..1000)
            .map(|_| Nullifier::random_for_test(&mut prng))
            .collect::<Vec<_>>();
        let pfs = elems
            .into_iter()
            .map(|elem| {
                let elem_bit_vec = <TestTreeHash as KVTreeHash>::traversal_of_digest(<TestTreeHash as KVTreeHash>::hash_key(TestNulls(elem)));
                let pf = elem_bit_vec
                    .iter()
                    .map(|_| {let n = Nullifier::random_for_test(&mut prng); arr![<TestTreeHash as KVTreeHash>::Digest; <TestTreeHash as KVTreeHash>::hash_leaf(TestNulls(n),TestNulls(n))]})
                    .collect::<Vec<_>>();
                let pf = KVMerkleProof::<TestTreeHash> {
                    terminal_node: KVMerkleTerminalNode::<TestTreeHash>::EmptySubtree,
                    path: pf,
                };
                let root = match pf.check(TestNulls(elem), KVMerkleTree::<TestTreeHash>::default().hash()) {
                    Some((_, hash)) => hash,
                    _ => panic!("Should always receive digest from check!"),
                };
                (elem, pf, root)
            })
            .collect::<Vec<_>>();

        let now = Instant::now();
        let mut tot = 0;
        for (elem, pf, root) in pfs {
            let new_root = pf.check(TestNulls(elem), root);
            if new_root.unwrap().0.is_some() {
                tot += 1;
            }
        }
        println!("proofs: {}/1000 in {}s", tot, now.elapsed().as_secs_f32());
    }

    fn test_merkle_tree_set_kv(updates: Vec<u16>, checks: Vec<Result<u16, u8>>) {
        use std::collections::{HashMap, HashSet};
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let update_vals = updates
            .iter()
            .cloned()
            .chain(checks.iter().filter_map(|x| x.ok()))
            .map(|u| (u, Nullifier::random_for_test(&mut prng)))
            .collect::<HashMap<_, _>>();
        let mut hset = HashSet::new();
        let mut t = KVMerkleTree::<TestTreeHash>::default();
        let mut lw_t = KVMerkleTree::<TestTreeHash>::ForgottenSubtree { digest: t.hash() };
        assert_eq!(t.hash(), lw_t.hash());

        let update_elems: Vec<_> = updates.iter().map(|u| update_vals[u]).collect();

        for (u, elem) in updates.iter().zip(update_elems.iter()) {
            let elem = *elem;
            hset.insert(u);

            let (val, pf) = t.lookup(TestNulls(elem)).unwrap();
            let in_set = val.is_some();
            t.insert(TestNulls(elem), TestNulls(elem));
            let pf_check = matches!(pf.check(TestNulls(elem), lw_t.hash()), Some((Some(_), ..)));
            assert_eq!(pf_check, in_set);
            lw_t.remember(TestNulls(elem), pf).unwrap();
            lw_t.insert(TestNulls(elem), TestNulls(elem)).unwrap();
            let (lw_t_val, new_lw_pf) = lw_t.lookup(TestNulls(elem)).unwrap();
            let in_new_lw_t = lw_t_val.is_some();

            assert!(in_new_lw_t);
            assert!(t.lookup(TestNulls(elem)).unwrap().0.is_some());

            assert_eq!(lw_t.hash(), t.hash());
            lw_t.forget(TestNulls(elem)).unwrap();
            assert!(lw_t.lookup(TestNulls(elem)).is_none());

            let new_lw_pf_check = matches!(
                new_lw_pf.check(TestNulls(elem), lw_t.hash()),
                Some((Some(_), ..))
            );
            assert!(new_lw_pf_check);
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
            let (t_val, pf) = t.lookup(TestNulls(elem)).unwrap();
            let t_contains = t_val.is_some();

            if should_be_there {
                assert!(hset.contains(&val));
                assert!(t_contains);
            }
            assert_eq!(hset.contains(&val), t_contains);

            let check = matches!(
                KVMerkleProof::<TestTreeHash>::check(&pf, TestNulls(elem), t.hash()),
                Some((Some(_), ..))
            );
            assert_eq!(t_contains, check);
        }
    }

    #[test]
    fn quickcheck_merkle_tree_kv_regressions() {
        test_merkle_tree_set_kv(vec![20, 0], vec![Ok(20)]);
        test_merkle_tree_set_kv(vec![0, 38], vec![Err(0), Ok(1), Ok(38)]);
        test_merkle_tree_set_kv(vec![0, 0, 0], vec![])
    }

    #[test]
    fn quickcheck_merkle_tree_kv() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_merkle_tree_set_kv as fn(Vec<_>, Vec<_>) -> ());
    }
}
