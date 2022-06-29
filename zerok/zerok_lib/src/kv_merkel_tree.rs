#![deny(warnings)]
#![allow(dead_code)]

//use crate::util::canonical;
//use arbitrary_wrappers::*;
use ark_serialize::*;
//use bitvec::vec::BitVec;
use core::mem;
//use jf_cap::structs::Nullifier;
use serde::{Deserialize, Serialize};
use crate::tree_hash::*;
use generic_array::{GenericArray, ArrayLength};
use core::fmt::Debug;


/// Note: this type implements PartialEq so that containing types can derive PartialEq, mostly for
/// testing purposes. The implementation tests for logical equality of the represented set, ignoring
/// sparseness. That is, any two sets with the same root hash will compare equal, even if the
/// elements retained in memory are different between the two sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KVMerkleTree<K, V, D, A> 

{
    EmptySubtree,
    ForgottenSubtree {
        digest: <D as KVTreeHash>::Digest,
    },
    Leaf {
        digest: <D as KVTreeHash>::Digest,
        /// how far above the "true" leaf level this leaf is
        height: usize,
        key: <K as KVTreeHash>::Key,
        value: <V as KVTreeHash>::Value,
    },
    Branch {
        digest: <D as KVTreeHash>::Digest,
        children: GenericArray<<D as KVTreeHash>::Digest, <A as KVTreeHash>::BranchArity>,
    },
}

impl<K,V,D,A> PartialEq<Self> for KVMerkleTree<K,V,D,A> {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}
/* KALEY: don't need arbitrary?
impl<'a,K,V,D,A> arbitrary::Arbitrary<'a> for KVMerkleTree<K,V,D,A> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut s = Self::default();
        for n in u.arbitrary_iter::<ArbitraryNullifier>()? {
            s.insert(n?.into());
        }
        Ok(s)
    }
}
*/
impl<K,V,D,A> KVMerkleTree<K,V,D,A> {
    fn new_leaf(height: usize, key: <K as KVTreeHash>::Key, value: <V as KVTreeHash>::Value) -> Self {
        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
        let key_bits = key_bit_vec.into_iter();

        let mut h = KVTreeHash::hash_leaf(key, value);
        //KALEY: what happens when >2 siblings??
        //KALEY: .into_iter() needed again?
        for sib_is_left in key_bits.into_iter().take(height) {
            let (l, r) = if sib_is_left {
                (KVTreeHash::empty_digest(), h)
            } else {
                (h, KVTreeHash::empty_digest())
            };
            h = KVTreeHash::hash_branch([l, r]);
        }

        Self::Leaf {
            digest: h,
            key,
            value,
            height,
        }
    }

    //fn new_branch(l: Box<Self>, r: Box<Self>) -> Self {
    fn new_branch(children: GenericArray<<D as KVTreeHash>::Digest, <A as KVTreeHash>::BranchArity>) -> Self {
        Self::Branch {
            digest: KVTreeHash::hash_branch(children),
            children,
        }
    }
}

impl<K,V,D,A> Default for KVMerkleTree<K,V,D,A> {
    fn default() -> Self {
        Self::EmptySubtree
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KVMerkleTerminalNode<K,V,D,A> {
    EmptySubtree,
    Leaf {
        /// how far above the "true" leaf level this leaf is
        height: usize,
        key: <K as KVTreeHash>::Key,
        value: <V as KVTreeHash>::Value,
    },
}

impl<K,V,D,A> CanonicalSerialize for KVMerkleTerminalNode<K,V,D,A> {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        match self {
            KVMerkleTerminalNode::EmptySubtree => {
                writer.write_all(&[0]).map_err(SerializationError::from)
            }
            KVMerkleTerminalNode::Leaf { height, key, value } => {
                writer.write_all(&[1]).map_err(SerializationError::from)?;
                CanonicalSerialize::serialize(height, &mut writer)?;
                CanonicalSerialize::serialize(key, &mut writer);
                CanonicalSerialize::serialize(value, &mut value)
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

impl<K,V,D,A> CanonicalDeserialize for KVMerkleTerminalNode<K,V,D,A> {
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

impl<K,V,D,A> KVMerkleTerminalNode<K,V,D,A> {
    fn value(&self) -> <D as KVTreeHash>::Digest {
        use KVMerkleTerminalNode::*;
        match self {
            EmptySubtree => KVTreeHash::empty_digest(),
            Leaf { height, key, value } => {
                //KALEY: reminder to check *'s if weird build errors
                //KALEY: double check that this is correct (using hash_key here)
                let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));

                // the path only goes until a terminal node is reached, so skip
                // part of the bit-vec
                let key_bits = key_bit_vec.into_iter();

                let mut running_hash = KVTreeHash::hash_leaf(key, value);

                // if the height is too large, keep hashing
                //KALEY: more than 2 children issue?
                for sib_is_left in key_bits.chain(core::iter::repeat(false)).take(*height) {
                    let sib = KVTreeHash::empty_digest();
                    running_hash = {
                        let l = if sib_is_left { sib } else { running_hash };
                        let r = if sib_is_left { running_hash } else { sib };
                        KVTreeHash::hash_branch([l, r])
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
pub struct KVMerkleProof<K,V,D,A> {
    terminal_node: KVMerkleTerminalNode<K,V,D,A>,
    path: Vec<<D as KVTreeHash>::Digest>,
}

impl<K,V,D,A> KVMerkleProof<K,V,D,A> {
    pub fn check(&self, key: <K as KVTreeHash>::Key, value: <V as KVTreeHash>::Value, root: <D as KVTreeHash>::Digest) -> Result<bool, <D as KVTreeHash>::Digest> {
        let mut running_hash = self.terminal_node.value();

        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));

        // the path only goes until a terminal node is reached, so skip
        // part of the bit-vec
        let start_bit = key_bit_vec.len() - self.path.len();
        let key_bits = key_bit_vec.into_iter().skip(start_bit);

        //KALEY: fix for >2 children?
        for (sib, sib_is_left) in self.path.iter().zip(key_bits) {
            let sib = *sib;
            running_hash = {
                let l = if sib_is_left { sib } else { running_hash };
                let r = if sib_is_left { running_hash } else { sib };
                KVTreeHash::hash_branch([l, r])
            };
        }

        if &running_hash == root {
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

impl<K,V,D,A> KVMerkleTree<K,V,D,A> {
    pub fn sparse(root: <D as KVTreeHash>::Digest) -> Self {
        Self::ForgottenSubtree { digest: root }
    }

    pub fn hash(&self) -> <D as KVTreeHash>::Digest {
        use KVMerkleTree::*;
        match self {
            EmptySubtree => KVTreeHash::empty_digest(),
            Leaf { digest, .. } => *digest,
            ForgottenSubtree { digest, .. } => *digest,
            Branch { digest, .. } => *digest,
        }
    }

    /// Returns `None` if the element is in a forgotten subtree
    pub fn contains(&self, key: <K as KVTreeHash>::Key, value: <V as KVTreeHash>::Value) -> Option<(bool, KVMerkleProof<K,V,D,A>)> {
        use KVMerkleTree::*;
        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
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

    pub fn insert(&mut self, key: <K as KVTreeHash>::Key, value: <V as KVTreeHash>::Value) -> Option<()> {
        use KVMerkleTree::*;
        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
        let mut end_height = key_bit_vec.len();
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

                Leaf { height, key, value, .. } => {
                    debug_assert_eq!(height, end_height);
                    // Figure out if this leaf is down the same tree or if it's a sibling
                    let leaf_is_left = {
                        debug_assert!(height > 0);
                        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
                        !key_bit_vec[height - 1]
                    };

                    let new_leaf = Box::new(Self::new_leaf(height - 1, key, value));
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
        for (sib_is_left, sib) in siblings {
            let (l, r) = if sib_is_left {
                (sib, Box::new(end_branch))
            } else {
                (Box::new(end_branch), sib)
            };

            end_branch = Self::new_branch([l, r]);
        }
        *self = end_branch;

        ret
    }

    pub fn forget(&mut self, key: <K as KVTreeHash>::Key, value: <V as KVTreeHash>::Value) -> Option<KVMerkleProof<K,V,D,A>> {
        use KVMerkleTree::*;
        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));
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
        key: <K as KVTreeHash>::Key,
        value: <V as KVTreeHash>::Value,
        proof: KVMerkleProof<K,V,D,A>,
    ) -> Result<(), <D as KVTreeHash>::Digest> {
        // Check the proof before we do anything. After checking, we can
        // safely assume that all the values along the path match.
        let key_in_set = proof.check(key, value, &self.hash())?;

        use KVMerkleTree::*;
        let key_bit_vec = KVTreeHash::traversal_of_digest(KVTreeHash::hash_key(key));

        let mut siblings = vec![];
        let mut end_branch = mem::replace(self, EmptySubtree);

        // TODO: this is redundant with the checking
        let path_hashes = {
            let mut running_hash = proof.terminal_node.value();

            let mut ret = vec![];
            ret.reserve(proof.path.len() + 1);

            for (sib_is_left, sib_hash) in
                key_bit_vec.iter().rev().zip(proof.path.iter().rev()).rev()
            {
                let (l, r) = if *sib_is_left {
                    (*sib_hash, running_hash)
                } else {
                    (running_hash, *sib_hash)
                };
                ret.push((running_hash, sib_hash));
                running_hash = Self::new_branch([
                    Box::new(ForgottenSubtree { digest: l }),
                    Box::new(ForgottenSubtree { digest: r }),
                ])
                .hash();
            }

            ret.reverse();
            ret
        };

        let key_bits = key_bit_vec.into_iter().rev();

        for (sib_is_left, (node_hash, sib_hash)) in key_bits.zip(path_hashes.into_iter()) {
            let sib = match end_branch {
                ForgottenSubtree { .. } => {
                    end_branch = ForgottenSubtree { digest: node_hash };
                    Box::new(ForgottenSubtree { digest: *sib_hash })
                }
                EmptySubtree => {
                    unreachable!();
                } // TODO: is this unreachable?
                Branch { children, .. } => {
                    let (sib, next) = if sib_is_left { (children[0], children[1]) } else { (children[1], children[0]) };
                    end_branch = *next;
                    sib
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

            siblings.push((sib_is_left, sib));
        }

        end_branch = match end_branch {
            ForgottenSubtree { digest } => {
                match proof.terminal_node {
                    KVMerkleTerminalNode::EmptySubtree => {
                        // TODO: should this be possible????? it feels like it
                        // shouldn't be
                        assert_eq!(digest, KVTreeHash::empty_digest());
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

pub fn set_merkle_lw_multi_insert<K,V,D,A>(
    inserts: Vec<(<K as KVTreeHash>::Key, <V as KVTreeHash>::Value, KVMerkleProof<K,V,D,A>)>,
    root: <D as KVTreeHash>::Digest,
) -> Result<(<D as KVTreeHash>::Digest, Vec<KVMerkleProof<K,V,D,A>>), <D as KVTreeHash>::Digest> {
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
            .map(|k,v| s.contains(k,v).unwrap().1)
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
