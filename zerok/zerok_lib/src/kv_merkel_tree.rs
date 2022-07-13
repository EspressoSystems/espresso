#![deny(warnings)]
#![allow(dead_code)]

//use crate::util::canonical;
//use arbitrary_wrappers::*;
use ark_serialize::*;
//use bitvec::vec::BitVec;
use core::mem;
//use jf_cap::structs::Nullifier;
use serde::{Deserialize, Serialize};
use crate::tree_hash::{*};
use generic_array::{GenericArray,ArrayLength};
use core::fmt::Debug;




/// Note: this type implements PartialEq so that containing types can derive PartialEq, mostly for
/// testing purposes. The implementation tests for logical equality of the represented set, ignoring
/// sparseness. That is, any two sets with the same root hash will compare equal, even if the
/// elements retained in memory are different between the two sets.
#[derive(Debug, Clone)]
pub enum KVMerkleTree<KVHash, Arity> 
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
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
        //children: GenericArray<Hash::Digest, Hash::BranchArity>,
        children: Box<GenericArray<KVMerkleTree<KVHash,Arity>, Arity>>,
    },
}

impl<KVHash, Arity> PartialEq<Self> for KVMerkleTree<KVHash, Arity>
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
 {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }

}
/* KALEY: don't need arbitrary?
impl<'a,K,V,D,A> arbitrary::Arbitrary<'a> for KVMerkleTree<K,V,D,A,T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut s = Self::default();
        for n in u.arbitrary_iter::<ArbitraryNullifier>()? {
            s.insert(n?.into());
        }
        Ok(s)
    }
}
*/
impl<KVHash, Arity> KVMerkleTree<KVHash, Arity>
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq  + ArrayLength<KVHash::Digest>,
 {
    fn new_leaf(height: usize, key: KVHash::Key, value: KVHash::Value) -> Self {
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));
        let key_bits = key_bit_vec.into_iter();

        let mut h = KVHash::hash_leaf(key, value);

        for sib in key_bits.into_iter().take(height) {
            let mut childs = GenericArray::from_iter(vec![KVHash::empty_digest(); Arity::to_usize()]);
            childs[sib as usize] = h;
            h = KVHash::hash_branch(childs);
            
        }

        Self::Leaf {
            digest: h,
            height,
            key,
            value,
        }
    }

    fn new_branch(children: Box<GenericArray<Self, Arity>>) -> Self {
        let childs = GenericArray::from_iter(children.into_iter().map(|d| d.hash()));
        Self::Branch {
            digest: KVHash::hash_branch(childs),
            children,
        }
    }
}

impl <KVHash, Arity> Default for KVMerkleTree<KVHash,Arity> 
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq  + ArrayLength<KVHash::Digest>,
{
    fn default() -> Self {
        Self::EmptySubtree
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KVMerkleTerminalNode<KVHash> 
where
    KVHash: KVTreeHash + Clone,
 {
    EmptySubtree,
    Leaf {
        /// how far above the "true" leaf level this leaf is
        height: usize,
        key: KVHash::Key,
        value: KVHash::Value,
    },
}

impl<KVHash> CanonicalSerialize for KVMerkleTerminalNode<KVHash> 
where
    KVHash: KVTreeHash + Clone,
 {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            KVMerkleTerminalNode::EmptySubtree => {
                writer.write_all(&[0]).map_err(SerializationError::from)
            }
            KVMerkleTerminalNode::Leaf { height, key, value } => {
                writer.write_all(&[1]).map_err(SerializationError::from)?;
                CanonicalSerialize::serialize(height, &mut writer)?;
                CanonicalSerialize::serialize(key, &mut writer);
                CanonicalSerialize::serialize(value, &mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        1 + match self {
            KVMerkleTerminalNode::EmptySubtree => 0,
            KVMerkleTerminalNode::Leaf { height, key, value } => {
                height.serialized_size() + key.serialized_size() + value.serialized_size()
            }
        }
    }
}

impl<KVHash> CanonicalDeserialize for KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
 {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut flag = [0u8];
        reader.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(KVMerkleTerminalNode::EmptySubtree),
            1 => {
                let height = CanonicalDeserialize::deserialize(&mut reader)?;
                let key = CanonicalDeserialize::deserialize(&mut reader)?;
                let value = CanonicalDeserialize::deserialize(&mut reader)?;
                Ok(KVMerkleTerminalNode::Leaf { height, key, value })
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl<KVHash> KVMerkleTerminalNode<KVHash>
where
    KVHash: KVTreeHash + Clone,
{
    fn value<Arity>(&self) -> KVHash::Digest 
    where
        Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq  + ArrayLength<KVHash::Digest>,
    {
        use KVMerkleTerminalNode::*;
        match self {
            EmptySubtree => KVHash::empty_digest(),
            Leaf { height, key, value } => {
                let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(*key));

                // the path only goes until a terminal node is reached, so skip
                // part of the bit-vec
                let key_bits = key_bit_vec.into_iter();

                let mut running_hash = KVHash::hash_leaf(*key, *value);

                // if the height is too large, keep hashing
                for sib in key_bits.chain(core::iter::repeat(0)).take(*height) {
                    let mut childs = GenericArray::from_iter(vec![KVHash::empty_digest(); Arity::to_usize()]);
                    childs[sib as usize] = running_hash;
                    running_hash = KVHash::hash_branch(childs);
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
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct KVMerkleProof<KVHash,Arity> 
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
 {
    terminal_node: KVMerkleTerminalNode<KVHash>,
    path: Vec<GenericArray<KVHash::Digest, Arity>>,
}

impl<KVHash,Arity> KVMerkleProof<KVHash,Arity>
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
 {
    pub fn check(&self, key: KVHash::Key, value: KVHash::Value, root: KVHash::Digest) -> Result<bool, KVHash::Digest> {
        let mut running_hash = self.terminal_node.value::<Arity>();

        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));

        // the path only goes until a terminal node is reached, so skip
        // part of the bit-vec
        let start_bit = key_bit_vec.len() - self.path.len();
        let key_bits = key_bit_vec.into_iter().skip(start_bit);

        for (sibs, sib_position) in self.path.iter().zip(key_bits) {
            let sibs_vec: Vec<_> = sibs.to_vec();
            running_hash = {
                sibs_vec.insert(sib_position as usize, running_hash);
                KVHash::hash_branch(GenericArray::from_iter(sibs_vec))
            };
        }

        if running_hash == root {
            Ok(match &self.terminal_node {
                KVMerkleTerminalNode::EmptySubtree {} => false,
                KVMerkleTerminalNode::Leaf {
                    key: leaf_key, 
                    value: leaf_value,
                    ..
                } => (leaf_key == &key && leaf_value == &value),
            })
        } else {
            Err(running_hash)
        }
    }
}

impl<KVHash,Arity> KVMerkleTree<KVHash,Arity>
where
    KVHash: KVTreeHash + Clone,
    Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
 {
    pub fn sparse(root: KVHash::Digest) -> Self {
        Self::ForgottenSubtree { digest: root }
    }

    pub fn hash(&self) -> KVHash::Digest {
        use KVMerkleTree::*;
        match self {
            EmptySubtree => KVHash::empty_digest(),
            Leaf { digest, .. } => *digest,
            ForgottenSubtree { digest, .. } => *digest,
            Branch { digest, .. } => *digest,
        }
    }

    /// Returns `None` if the element is in a forgotten subtree
    pub fn contains(&self, key: KVHash::Key, value: KVHash::Value) -> Option<(bool, KVMerkleProof<KVHash,Arity>)> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));
        let key_bits = key_bit_vec.into_iter().rev();

        let mut path = Vec::new();
        let mut end_branch = self;
        for sib in key_bits {
            match end_branch {
                Branch { children, .. } => {
                    let children_l: Vec<_> = children[0..sib as usize].into_iter().map(|d| d.hash()).collect();
                    let children_r: Vec<_> = children[sib as usize + 1 ..].into_iter().map(|d| d.hash()).collect();
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
                value: leaf_value,
                ..
            } => {
                path.reverse();
                Some((
                    &key == leaf_key,
                    KVMerkleProof {
                        terminal_node: KVMerkleTerminalNode::Leaf {
                            height: *height,
                            key: *leaf_key,
                            value: *leaf_value,
                        },
                        path,
                    },
                ))
            }
            Branch { .. } => panic!("This tree has more levels than my hash has bits!"),
        }
    }

    pub fn insert(&mut self, key: KVHash::Key, value: KVHash::Value) -> Option<()> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));
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
                    //let (target, next) = if sib_is_left { (children[0], children[1]) } else { (children[1], children[0]) };
                    let target = children[pos as usize];
                    let children_l: Vec<_> = children[0..pos as usize].into_iter().map(|x | *x).collect();
                    let children_r: Vec<_> = children[pos as usize + 1 ..].into_iter().map(|x| *x).collect();
                    children_l.append(&mut children_r);
                    //let all_other_children = GenericArray::from_iter(children_l.into_iter());
                    end_branch = target;
                    children_l
                }

                Leaf { height, key, value, .. } => {
                    debug_assert_eq!(height, end_height);
                    // Figure out if this leaf is down the same tree or if it's a sibling
                    let leaf_pos = {
                        debug_assert!(height > 0);
                        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));
                        !key_bit_vec[height - 1]
                    };

                    let new_leaf = Self::new_leaf(height - 1, key, value);
                    //needs to be arity+1?
                    let (new_end_branch, new_sibs) = if leaf_pos == pos {
                        let new_branches = vec![&EmptySubtree; Arity::to_usize()];
                        //KALEY: if leaf_pos == pos == maxsize, something may get weird?
                        new_branches[pos as usize] = &new_leaf;
                        (EmptySubtree, new_branches.into_iter().map(|x| *x).collect::<Vec<_>>())
                    } else {
                        (new_leaf, vec![EmptySubtree; Arity::to_usize()])
                    };
                    end_branch = new_end_branch;
                    new_sibs
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
                value: leaf_value,
            } => {
                assert_eq!(height, end_height);
                assert_eq!(key, leaf_key);
                //KALEY: add update/deal with same key but different value
                assert_eq!(value, leaf_value);
                Leaf {
                    digest,
                    height,
                    key: leaf_key,
                    value: leaf_value,
                }
            }
        };

        siblings.reverse();
        for (pos, sibs) in siblings {
            sibs.insert(pos as usize, end_branch);
            let sibs_arr: GenericArray<KVMerkleTree<KVHash,Arity>,Arity> = GenericArray::from_exact_iter(sibs).unwrap();
            end_branch = Self::new_branch(Box::new(sibs_arr));
        }
        *self = end_branch;

        ret
    }

    pub fn forget(&mut self, key: KVHash::Key, value: KVHash::Value) -> Option<KVMerkleProof<KVHash,Arity>> {
        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));
        let key_bits = key_bit_vec.into_iter().rev();

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);
        for sib_is_left in key_bits {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    break;
                }
                EmptySubtree => {
                    break;
                }
                Branch { children, .. } => {
                    let (sib, next) = if sib_is_left { (children[0], children[1]) } else { (children[1], children[0]) };
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
            key: leaf_key,
            value: leaf_value,
            ..
        } = end_branch
        {
            if leaf_key == key {
                ret = Some(KVMerkleProof {
                    terminal_node: KVMerkleTerminalNode::Leaf {
                        height,
                        key: leaf_key,
                        value: leaf_value,
                    },
                    path: siblings.iter().map(|(_, s)| s.hash()).rev().collect(),
                });
                end_branch = ForgottenSubtree {
                    digest: end_branch.hash(),
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
                    digest: Self::new_branch([l, r]).hash(),
                },
                _ => Self::new_branch([l, r]),
            };
        }
        *self = end_branch;

        ret
    }

    pub fn remember(
        &mut self,
        key: KVHash::Key,
        value: KVHash::Value,
        proof: KVMerkleProof<KVHash,Arity>,
    ) -> Result<(), KVHash::Digest> {
        // Check the proof before we do anything. After checking, we can
        // safely assume that all the values along the path match. This first 
        //check can be removed as an optimization opportunity if we really need 
        //to, but keeping it in is defensive programming
        let key_in_set = proof.check(key, value, self.hash())?;

        use KVMerkleTree::*;
        let key_bit_vec = KVHash::traversal_of_digest(KVHash::hash_key(key));

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);

        let path_hashes = {
            let mut running_hash = proof.terminal_node.value::<Arity>();

            let mut ret = vec![];
            ret.reserve(proof.path.len() + 1);

            for (sib, sib_hashes) in
                key_bit_vec.iter().rev().zip(proof.path.iter().rev()).rev()
            {
                let sibs_vec: Vec<_> = sib_hashes.to_vec();
                
                sibs_vec.insert(*sib as usize, running_hash);
                let branch_hash = KVHash::hash_branch(GenericArray::from_iter(sibs_vec));

                ret.push((running_hash, branch_hash));
                let children = vec![];
                for branch in sib_hashes {
                    children.push(ForgottenSubtree { digest: *branch })
                };
                running_hash = Self::new_branch(Box::new(GenericArray::from_iter(children)))
                .hash();
            }

            ret.reverse();
            ret
        };

        let key_bits = key_bit_vec.into_iter().rev();

        for (pos, (node_hash, sib_hash)) in key_bits.zip(path_hashes.into_iter()) {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    end_branch = ForgottenSubtree { digest: node_hash };
                    let sib_branches = vec![];

                    Box::new(ForgottenSubtree { digest: sib_hash })
                }
                EmptySubtree => {
                    unreachable!();
                } // TODO: is this unreachable?
                Branch { children, .. } => {
                    let children_l: Vec<_> = children[0..pos as usize].into_iter().map(|d| d.hash()).collect();
                    let children_r: Vec<_> = children[pos as usize + 1 ..].into_iter().map(|d| d.hash()).collect();
                    children_l.append(&mut children_r);
                    let all_children = GenericArray::from_iter(children_l.into_iter());
                    end_branch = &children[pos as usize];
                    all_children
                }
                //KALEY: existing key/diff value problem?
                Leaf {
                    height,
                    key: leaf_key,
                    value: leaf_value,
                    ..
                } => {
                    assert!(!key_in_set);
                    end_branch = EmptySubtree;
                    Box::new(Self::new_leaf(height - 1, key, value))
                }
            };

            siblings.push((pos, sib));
        }

        end_branch = match end_branch {
            ForgottenSubtree { digest } => {
                match proof.terminal_node {
                    KVMerkleTerminalNode::EmptySubtree => {
                        // TODO: should this be possible????? it feels like it
                        // shouldn't be
                        assert_eq!(digest, KVHash::empty_digest());
                        EmptySubtree
                    }

                    KVMerkleTerminalNode::Leaf { height, key, value } => Self::new_leaf(height, key, value),
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
            end_branch = Self::new_branch([l, r]);
        }
        *self = end_branch;

        Ok(())
    }
}

pub fn set_merkle_lw_multi_insert<KVHash,Arity>(
    inserts: Vec<KVMerkleProof<KVHash,Arity>>,
    root: KVHash::Digest,
) -> Result<(KVHash::Digest, Vec<KVMerkleProof<KVHash,Arity>>), KVHash::Digest> 
where
   KVHash: KVTreeHash + Clone,
   Arity: ArrayLength<KVMerkleTree<KVHash, Arity>> + Debug + PartialEq + ArrayLength<KVHash::Digest>,
 {
    let mut kvs = vec![];
    let mut s = KVMerkleTree::ForgottenSubtree { digest: root };
    for (k, v, proof) in inserts {
        s.remember(k,v, proof)?;
        kvs.push((k,v));
    }
    for (k,v) in kvs.iter() {
        s.insert(*k,*v).unwrap();
    }
    Ok((
        s.hash(),
        kvs
            .into_iter()
            .map(|(k,v)| s.contains(k,v).unwrap().1)
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
    fn test_kv_merkle_speed() {
        let mut prng = ChaChaRng::from_seed([0x8au8; 32]);
        let kvs = (1..1000)
            .map(|k| (k, prng.next_u32()))
            .collect::<Vec<_>>();
        let pfs = kvs
            .into_iter()
            .map(|key,value| {
                let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
                let pf = key_bit_vec
                    .iter()
                    .map(|_| KVTreeHash::hash_leaf(key,value))
                    .collect();
                let pf = KVMerkleProof {
                    terminal_node: KVMerkleTerminalNode::EmptySubtree,
                    path: pf,
                };
                let root = pf
                    .check(key, value, &KVMerkleTree::default().hash())
                    .unwrap_err();
                (key, value, pf, root)
            })
            .collect::<Vec<_>>();

        let now = Instant::now();
        let mut tot = 0;
        for (key, value, pf, root) in pfs {
            let new_root = pf.check(key, value, &root);
            if new_root.unwrap() {
                tot += 1;
            }
        }
        println!("proofs: {}/1000 in {}s", tot, now.elapsed().as_secs_f32());
    }

    fn test_merkle_tree_kv(updates: Vec<(u16, u16)>, checks: Vec<Result<u16, u8>>) {
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
