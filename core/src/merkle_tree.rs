#![allow(missing_docs)]
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

//! Implementation of the Merkle tree data structure.
//!
//! At a high level the Merkle tree is a ternary tree and the hash function H
//! used is SHA3_256 function. The node values are 32 bytes and each
//! internal node value is obtained by computing v:=H(1u8,a,b,c) where a,b,c are
//! the values of the left,middle and right child respectively. Leaf values
//! for an element (uid,elem) is obtained as H(0u8,little_endian(uid),CanonicalSerialize(elem)).
//! The tree height is fixed during initial instantiation and a new leaf will
//! be inserted at the leftmost available slot in the tree.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    boxed::Box,
    hash::Hash,
    mem,
    rand::{
        distributions::{Distribution, Standard},
        Rng,
    },
    string::ToString,
    vec,
    vec::Vec,
};
use core::{convert::TryFrom, fmt::Debug};
use jf_primitives::errors::PrimitivesError;
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};
use sha3::Digest;

pub const NODE_VALUE_LEN: usize = 32usize;

pub const DOM_SEP_INT_NODE: u8 = 1u8;
pub const DOM_SEP_LEAF_NODE: u8 = 0u8;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Deserialize, Serialize)]
/// Enum for identifying a position of a node (left, middle or right).
pub enum NodePos {
    /// Left.
    Left,
    /// Middle.
    Middle,
    /// Right.
    Right,
}

impl CanonicalSerialize for NodePos
where
    u8: From<NodePos>,
{
    fn serialize<W>(&self, mut writer: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        CanonicalSerialize::serialize(&u8::from(*self), &mut writer)
    }
    fn serialized_size(&self) -> usize {
        1
    }
}

impl CanonicalDeserialize for NodePos {
    fn deserialize<R>(mut reader: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let buf = <u8 as CanonicalDeserialize>::deserialize(&mut reader)?;
        if buf > 2 {
            return Err(SerializationError::InvalidData);
        }
        Ok(buf.into())
    }
}

impl From<NodePos> for usize {
    fn from(pos: NodePos) -> Self {
        use NodePos::*;
        match pos {
            Left => 0,
            Middle => 1,
            Right => 2,
        }
    }
}

impl From<NodePos> for u8 {
    fn from(pos: NodePos) -> Self {
        use NodePos::*;
        match pos {
            Left => 0,
            Middle => 1,
            Right => 2,
        }
    }
}

impl From<u8> for NodePos {
    fn from(pos: u8) -> Self {
        match pos {
            0 => NodePos::Left,
            1 => NodePos::Middle,
            2 => NodePos::Right,
            _ => panic!("unable to cast an u8 ({}) to node position", pos),
        }
    }
}

impl Default for NodePos {
    fn default() -> Self {
        Self::Left
    }
}

/// A 3-ary Merkle tree node.
///
/// It consists of the following:
/// * `sibling1` - the 1st sibling of the tree node
/// * `sibling2` - the 2nd sibling of the tree node
/// * `pos` - indicates whether the tree node is the left, middle or right child of its
///   parent
#[derive(
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerklePathNode {
    /// First sibling.
    pub sibling1: NodeValue,
    /// Second sibling.
    pub sibling2: NodeValue,
    /// Position.
    pub pos: NodePos,
}

impl MerklePathNode {
    /// Creates a new node on some Merkle path given the position of the node
    /// and the value of the siblings
    /// * `pos` - position of the node (left, middle or right)
    /// * `sibling1` - first sibling value
    /// * `sibling2` - second sibling value
    /// * `returns` - Merkle path node
    pub fn new(pos: NodePos, sibling1: NodeValue, sibling2: NodeValue) -> Self {
        MerklePathNode {
            sibling1,
            sibling2,
            pos,
        }
    }
}

/// An authentication path of a ternary Merkle tree.
/// While node information can come in any order, in this implementation we
/// expect the first item to correspond to the leaf and the last to the root.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerklePath {
    /// Nodes along the path.
    pub nodes: Vec<MerklePathNode>,
}

impl MerklePath {
    /// Create a Merkle path from the list of nodes
    /// * `nodes` - ordered list of Merkle path nodes
    /// * `returns - Merkle path
    pub fn new(nodes: Vec<MerklePathNode>) -> Self {
        Self { nodes }
    }
}

/// Represents the value for a node in the merkle tree.
#[tagged_blob("NODE")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, Copy)]
pub struct NodeValue(pub(crate) [u8; NODE_VALUE_LEN]);

impl CanonicalSerialize for NodeValue {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer.write_all(&self.0).map_err(SerializationError::from)
    }

    fn serialized_size(&self) -> usize {
        NODE_VALUE_LEN
    }
}

impl CanonicalDeserialize for NodeValue {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; NODE_VALUE_LEN];
        reader
            .read(&mut buf[..])
            .map_err(SerializationError::from)?;
        Ok(Self(buf))
    }
}

impl Distribution<NodeValue> for Standard
where
    Standard: Distribution<[u8; NODE_VALUE_LEN]>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NodeValue {
        NodeValue(rng.gen())
    }
}

// TODO: those APIs can be replaced with From/Into and Default?
impl NodeValue {
    #[allow(dead_code)]
    fn to_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Empty node.
    pub fn empty_node_value() -> Self {
        Self([0u8; NODE_VALUE_LEN])
    }
}

impl TryFrom<usize> for NodePos {
    type Error = ();

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(NodePos::Left),
            1 => Ok(NodePos::Middle),
            2 => Ok(NodePos::Right),
            _ => Err(()),
        }
    }
}

/// Hash function used to compute an internal node value
/// * `a` - first input value (e.g.: left child value)
/// * `b` - second input value (e.g.: middle child value)
/// * `c` - third input value (e.g.: right child value)
/// * `returns` - rescue_sponge_no_padding(a,b,c)
fn hash(a: &NodeValue, b: &NodeValue, c: &NodeValue) -> NodeValue {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&[DOM_SEP_INT_NODE]);
    hasher.update(&a.0);
    hasher.update(&b.0);
    hasher.update(&c.0);
    let digest = hasher.finalize();
    let mut value = [0u8; NODE_VALUE_LEN];
    value.copy_from_slice(&digest[0..NODE_VALUE_LEN]);
    NodeValue(value)
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
/// The result of querying at an index in the tree
pub enum LookupResult<E, P> {
    /// The value at the given index, and a proof of validity
    Ok(E, P),
    /// The index is valid but we do not have the leaf in memory
    NotInMemory,
    /// The index is outside the occupied range in the tree
    EmptyLeaf,
}

impl<E, P> LookupResult<E, P> {
    /// Assert the lookup result is Ok.
    pub fn expect_ok(self) -> Result<(E, P), PrimitivesError> {
        match self {
            LookupResult::Ok(x, proof) => Ok((x, proof)),
            LookupResult::NotInMemory => Err(PrimitivesError::InternalError(
                "Expected Ok, found NotInMemory".to_string(),
            )),
            LookupResult::EmptyLeaf => Err(PrimitivesError::InternalError(
                "Expected Ok, found EmptyLeaf".to_string(),
            )),
        }
    }

    pub fn map<Fn, T2, P2>(self, f: Fn) -> LookupResult<T2, P2>
    where
        Fn: FnOnce(E, P) -> (T2, P2),
    {
        match self {
            LookupResult::Ok(x, proof) => {
                let (x, proof) = f(x, proof);
                LookupResult::Ok(x, proof)
            }
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }
}

impl<E, P> From<LookupResult<E, P>> for Option<Option<(E, P)>> {
    fn from(v: LookupResult<E, P>) -> Self {
        match v {
            LookupResult::Ok(x, proof) => Some(Some((x, proof))),
            LookupResult::NotInMemory => None,
            LookupResult::EmptyLeaf => Some(None),
        }
    }
}

/// Data structure storing the information of a node in the Merkle tree.
/// The node has at most three children.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) enum MerkleNode<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    EmptySubtree,
    Branch {
        value: NodeValue,
        children: [Box<MerkleNode<E>>; 3],
    },
    /// A forgotten subtree fully occupied in the merkle tree, but we don't
    /// have its contents in memory
    ForgottenSubtree {
        value: NodeValue,
    },
    Leaf {
        value: NodeValue,
        uid: u64,
        #[serde(with = "jf_utils::field_elem")]
        // this just implement serde for any type that implements ark_serialize traits
        elem: E,
    },
}

impl<E> MerkleNode<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    fn new_leaf(uid: u64, elem: E) -> Self {
        let mut elem_bytes = vec![0u8; elem.serialized_size()];
        elem.serialize(&mut elem_bytes).unwrap();
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&[DOM_SEP_LEAF_NODE]);
        hasher.update(&uid.to_le_bytes());
        hasher.update(&elem_bytes);
        let digest = hasher.finalize();
        let mut value = [0u8; NODE_VALUE_LEN];
        value.copy_from_slice(&digest[0..NODE_VALUE_LEN]);
        MerkleNode::Leaf {
            value: NodeValue(value),
            uid,
            elem,
        }
    }

    fn new_branch(l: Box<Self>, m: Box<Self>, r: Box<Self>) -> Option<Self> {
        // Required to prevent tree extension attacks
        if l.value() == NodeValue::empty_node_value() {
            None
        } else {
            let value = hash(&l.value(), &m.value(), &r.value());
            let children = [l, m, r];
            Some(MerkleNode::Branch { value, children })
        }
    }

    fn is_empty_subtree(&self) -> bool {
        matches!(self, MerkleNode::EmptySubtree)
    }

    // Getter for the value of the MerkleNode
    fn value(&self) -> NodeValue {
        match self {
            MerkleNode::EmptySubtree => NodeValue::empty_node_value(),
            MerkleNode::Branch { value, .. } => *value,
            MerkleNode::ForgottenSubtree { value } => *value,
            MerkleNode::Leaf { value, .. } => *value,
        }
    }

    fn insert_at_right(self, capacity: u64, ix: u64, elem: E) -> Self {
        if capacity <= 1 {
            assert!(self.is_empty_subtree(), "Exceeded capacity of Merkle tree");
            Self::new_leaf(ix, elem)
        } else {
            let next_capacity = capacity / 3;
            match self {
                MerkleNode::EmptySubtree => {
                    let child = (MerkleNode::EmptySubtree).insert_at_right(next_capacity, ix, elem);
                    Self::new_branch(
                        Box::new(child),
                        Box::new(MerkleNode::EmptySubtree),
                        Box::new(MerkleNode::EmptySubtree),
                    )
                    .unwrap() // `child` is not empty, so child.value() !=
                              // EMPTY_LEAF_VALUE
                }

                MerkleNode::Branch { children, .. } => {
                    let [mut l, mut m, mut r] = children;
                    match (ix / next_capacity) % 3 {
                        0 => {
                            l = Box::new(l.insert_at_right(next_capacity, ix, elem));
                        }
                        1 => {
                            m = Box::new(m.insert_at_right(next_capacity, ix, elem));
                        }
                        2 => {
                            r = Box::new(r.insert_at_right(next_capacity, ix, elem));
                        }
                        _ => {
                            unreachable!();
                        }
                    }
                    // `child` is not empty, so child.value() != EMPTY_LEAF_VALUE
                    Self::new_branch(l, m, r).unwrap()
                }

                _ => unreachable!(),
            }
        }
    }

    fn get_leaf(&self, capacity: u64, ix: u64) -> LookupResult<E, Vec<MerklePathNode>> {
        if capacity <= 1 {
            match self {
                MerkleNode::Leaf { uid, elem, .. } => {
                    debug_assert_eq!(*uid, ix);
                    LookupResult::Ok(elem.clone(), vec![])
                }
                MerkleNode::ForgottenSubtree { .. } => LookupResult::NotInMemory,
                MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
                _ => unreachable!(),
            }
        } else {
            let next_capacity = capacity / 3;
            match self {
                MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
                MerkleNode::ForgottenSubtree { .. } => LookupResult::NotInMemory,
                MerkleNode::Leaf { .. } => unreachable!(),

                MerkleNode::Branch { children, .. } => {
                    let [l, m, r] = children;
                    let (node, child) = match (ix / next_capacity) % 3 {
                        0 => (
                            MerklePathNode {
                                sibling1: m.value(),
                                sibling2: r.value(),
                                pos: NodePos::Left,
                            },
                            &l,
                        ),
                        1 => (
                            MerklePathNode {
                                sibling1: l.value(),
                                sibling2: r.value(),
                                pos: NodePos::Middle,
                            },
                            &m,
                        ),
                        2 => (
                            MerklePathNode {
                                sibling1: l.value(),
                                sibling2: m.value(),
                                pos: NodePos::Right,
                            },
                            &r,
                        ),
                        _ => unreachable!(),
                    };

                    // Add nodes to the end of the subtree's path (paths are leaf -> root)
                    child.get_leaf(next_capacity, ix).map(|x, mut path| {
                        path.push(node);
                        (x, path)
                    })
                }
            }
        }
    }

    fn rebuild_to_root(
        capacity: u64,
        branching: u64,
        path: &[MerklePathNode],
        uid: u64,
        elem: E,
    ) -> Option<Self> {
        // requires match between capacity and path length
        if capacity <= 1 {
            if path.is_empty() {
                Some(Self::new_leaf(uid, elem))
            } else {
                None
            }
        } else if path.is_empty() {
            None
        } else {
            let next_capacity = capacity / 3;
            let next_branching = branching % next_capacity;
            let branching_pos = branching / next_capacity;
            let (this_piece, next_path) = path.split_last().unwrap();
            let MerklePathNode {
                sibling1,
                sibling2,
                pos,
            } = this_piece;
            let built_child =
                Self::rebuild_to_root(next_capacity, next_branching, next_path, uid, elem)?;
            let (l, m, r) = match (
                pos,
                branching_pos,
                *sibling1 == NodeValue::empty_node_value(),
                *sibling2 == NodeValue::empty_node_value(),
            ) {
                (NodePos::Left, 0, true, true) => {
                    (built_child, Self::EmptySubtree, Self::EmptySubtree)
                }
                (NodePos::Middle, 1, false, true) => (
                    Self::ForgottenSubtree { value: *sibling1 },
                    built_child,
                    Self::EmptySubtree,
                ),
                (NodePos::Right, 2, false, false) => (
                    Self::ForgottenSubtree { value: *sibling1 },
                    Self::ForgottenSubtree { value: *sibling2 },
                    built_child,
                ),
                _ => {
                    return None;
                }
            };
            Self::new_branch(Box::new(l), Box::new(m), Box::new(r))
        }
    }

    // `capacity` is the maximum number of leaves below this node (ie, 3^height)
    fn internal_forget(
        self,
        capacity: u64,
        ix: u64,
    ) -> (Self, LookupResult<E, Vec<MerklePathNode>>) {
        if capacity <= 1 {
            match self {
                // Forgetting a leaf removes its `elem` from the tree
                MerkleNode::Leaf { value, uid, elem } => {
                    debug_assert_eq!(uid, ix);
                    (
                        MerkleNode::ForgottenSubtree { value },
                        LookupResult::Ok(elem, vec![]),
                    )
                }
                // The index is already forgotten
                MerkleNode::ForgottenSubtree { value } => (
                    MerkleNode::ForgottenSubtree { value },
                    LookupResult::NotInMemory,
                ),
                // The index is out of range
                MerkleNode::EmptySubtree => (MerkleNode::EmptySubtree, LookupResult::EmptyLeaf),
                // A branch in a leaf position
                MerkleNode::Branch { .. } => unreachable!(),
            }
        } else {
            let next_capacity = capacity / 3;
            match self {
                // The index is out of range
                MerkleNode::EmptySubtree => (MerkleNode::EmptySubtree, LookupResult::EmptyLeaf),
                // The index is already forgotten
                MerkleNode::ForgottenSubtree { value } => (
                    MerkleNode::ForgottenSubtree { value },
                    LookupResult::NotInMemory,
                ),
                // A leaf in a branch position
                MerkleNode::Leaf { .. } => unreachable!(),

                MerkleNode::Branch { value, children } => {
                    let [mut l, mut m, mut r] = children;

                    // Add nodes to the end of the subtree's path (paths are leaf -> root)
                    let res = match (ix / next_capacity) % 3 {
                        0 => {
                            let (new_l, res) = l.internal_forget(next_capacity, ix);
                            l = Box::new(new_l);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: m.value(),
                                    sibling2: r.value(),
                                    pos: NodePos::Left,
                                });
                                (t, path)
                            })
                        }

                        1 => {
                            let (new_m, res) = m.internal_forget(next_capacity, ix);
                            m = Box::new(new_m);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: l.value(),
                                    sibling2: r.value(),
                                    pos: NodePos::Middle,
                                });
                                (t, path)
                            })
                        }

                        2 => {
                            let (new_r, res) = r.internal_forget(next_capacity, ix);
                            r = Box::new(new_r);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: l.value(),
                                    sibling2: m.value(),
                                    pos: NodePos::Right,
                                });
                                (t, path)
                            })
                        }

                        // (x%3) other than 0, 1, 2
                        _ => unreachable!(),
                    };

                    match (*l, *m, *r) {
                        // If every child has been forgotten, forget this node too
                        (
                            MerkleNode::ForgottenSubtree { .. },
                            MerkleNode::ForgottenSubtree { .. },
                            MerkleNode::ForgottenSubtree { .. },
                        ) => (MerkleNode::ForgottenSubtree { value }, res),
                        // Otherwise, some leaf below this branch is either live or empty, so we
                        // can't forget it.
                        (l, m, r) => {
                            debug_assert_eq!(
                                Self::new_branch(
                                    Box::new(l.clone()),
                                    Box::new(m.clone()),
                                    Box::new(r.clone())
                                )
                                .unwrap(),
                                MerkleNode::Branch {
                                    value,
                                    children: [
                                        Box::new(l.clone()),
                                        Box::new(m.clone()),
                                        Box::new(r.clone()),
                                    ]
                                }
                            );
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [Box::new(l), Box::new(m), Box::new(r)],
                                },
                                res,
                            )
                        }
                    }
                }
            }
        }
    }

    // `base_ix` is the leftmost leaf index in this subtree. When `path` is empty,
    // `base_ix` will equal the correct index for that leaf.
    #[allow(clippy::type_complexity)]
    fn internal_remember(
        self,
        base_ix: u64,
        elem: E,
        path: &[(NodeValue, MerklePathNode)],
    ) -> (Self, Result<(), Option<(usize, NodeValue)>>) {
        match path.last() {
            None => {
                let new_leaf = Self::new_leaf(base_ix, elem.clone());
                let self_val = self.value();
                if self_val != new_leaf.value() {
                    (self, Err(Some((0, self_val))))
                } else {
                    match self {
                        MerkleNode::Leaf {
                            uid, elem: lelem, ..
                        } => {
                            debug_assert_eq!(lelem, elem);
                            debug_assert_eq!(uid, base_ix);
                            (new_leaf, Ok(()))
                        }
                        MerkleNode::ForgottenSubtree { value: _ } => (new_leaf, Ok(())),
                        _ => unreachable!(),
                    }
                }
            }

            Some((child_val, last_node)) => {
                let child_val = *child_val;

                let this_val = self.value();
                match self {
                    MerkleNode::EmptySubtree => {
                        (MerkleNode::EmptySubtree, Err(Some((path.len(), this_val))))
                    }
                    MerkleNode::ForgottenSubtree { value } => {
                        let (l, m, r) = match last_node.pos {
                            NodePos::Left => (child_val, last_node.sibling1, last_node.sibling2),
                            NodePos::Middle => (last_node.sibling1, child_val, last_node.sibling2),
                            NodePos::Right => (last_node.sibling1, last_node.sibling2, child_val),
                        };

                        let new_node = Self::new_branch(
                            Box::new(MerkleNode::ForgottenSubtree { value: l }),
                            Box::new(MerkleNode::ForgottenSubtree { value: m }),
                            Box::new(MerkleNode::ForgottenSubtree { value: r }),
                        );
                        match new_node {
                            None => (self, Err(None)),
                            Some(new_node) => {
                                if new_node.value() != value {
                                    (self, Err(Some((path.len(), value))))
                                } else {
                                    new_node.internal_remember(base_ix, elem, path)
                                }
                            }
                        }
                    }
                    MerkleNode::Leaf { .. } => unreachable!(),

                    MerkleNode::Branch { value, children } => {
                        let [mut l, mut m, mut r] = children;

                        let (path_l, path_m, path_r) = match last_node.pos {
                            NodePos::Left => (child_val, last_node.sibling1, last_node.sibling2),
                            NodePos::Middle => (last_node.sibling1, child_val, last_node.sibling2),
                            NodePos::Right => (last_node.sibling1, last_node.sibling2, child_val),
                        };
                        if path_l != l.value() || path_m != m.value() || path_r != r.value() {
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [l, m, r],
                                },
                                Err(Some((path.len(), value))),
                            )
                        } else {
                            let res = match last_node.pos {
                                NodePos::Left => {
                                    let (new_l, res) = l.internal_remember(
                                        3 * base_ix,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    l = Box::new(new_l);
                                    res
                                }
                                NodePos::Middle => {
                                    let (new_m, res) = m.internal_remember(
                                        3 * base_ix + 1,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    m = Box::new(new_m);
                                    res
                                }
                                NodePos::Right => {
                                    let (new_r, res) = r.internal_remember(
                                        3 * base_ix + 2,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    r = Box::new(new_r);
                                    res
                                }
                            };
                            debug_assert_eq!(
                                Self::new_branch(l.clone(), m.clone(), r.clone())
                                    .unwrap()
                                    .value(),
                                value
                            );
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [l, m, r],
                                },
                                res,
                            )
                        }
                    }
                }
            }
        }
    }
}

/// A wrapper of the merkle root, together with the tree information.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerkleCommitment {
    /// Root of the tree.
    pub root_value: NodeValue,
    /// Height of the tree.
    pub height: u8,
    /// #leaves of the tree.
    pub num_leaves: u64,
}

/// Data struct for a merkle leaf.
#[tagged_blob("LEAF")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleLeaf<
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
>(pub E);

/// Inclusive proof of a merkle leaf.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerkleLeafProof<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    /// The leaf node.
    pub leaf: MerkleLeaf<E>,
    /// The path.
    pub path: MerklePath,
}

impl<E> MerkleLeafProof<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    /// Input a leaf and the path, build a proof.
    pub fn new(leaf: E, path: MerklePath) -> MerkleLeafProof<E> {
        MerkleLeafProof {
            leaf: MerkleLeaf(leaf),
            path,
        }
    }
}

/// A wrapper of the merkle membership proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum MerkleFrontier<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    /// Without proof.
    Empty {
        /// Height of the tree.
        height: u8,
    },
    /// With proof.
    Proof(MerkleLeafProof<E>),
}

impl<E> MerkleFrontier<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + CanonicalSerialize + CanonicalDeserialize,
{
    /// If the merkle frontier is empty or not.
    pub fn non_empty(&self) -> Option<&MerkleLeafProof<E>> {
        match self {
            MerkleFrontier::Proof(lap) => Some(lap),
            _ => None,
        }
    }
}

/// Data struct of a merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleTree<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    root: MerkleNode<E>,
    height: u8,
    capacity: u64,
    num_leaves: u64, // the index of the first unoccupied leaf
}

impl<E> MerkleTree<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    /// Create a new Merkle with a specific height
    /// * `height` - height of the tree (number of hops from the root to a
    ///   leaf).
    /// Returns `None` if the capacity of the tree overflows a u64
    pub fn new(height: u8) -> Option<Self> {
        let root = MerkleNode::EmptySubtree;
        let capacity = (3_u64).checked_pow(height as u32)?;
        Some(MerkleTree {
            root,
            height,
            capacity,
            num_leaves: 0,
        })
    }

    /// Recreates a pruned Merkle from the rightmost leaf and proof to the root.
    /// Returns `None` if the capacity of the tree overflows a u64
    pub fn restore_from_frontier(
        commitment: MerkleCommitment,
        proof: &MerkleFrontier<E>,
    ) -> Option<Self> {
        match proof {
            MerkleFrontier::Empty { height } => {
                if commitment.num_leaves == 0
                    && commitment.height == *height
                    && commitment.root_value == NodeValue::empty_node_value()
                {
                    Self::new(commitment.height)
                } else {
                    None
                }
            }
            MerkleFrontier::Proof(MerkleLeafProof { leaf, path }) => {
                if commitment.height as usize != path.nodes.len() || commitment.num_leaves == 0 {
                    None
                } else {
                    let capacity = (3_u64).checked_pow(commitment.height as u32)?;
                    let num_leaves = commitment.num_leaves;
                    let uid = num_leaves - 1;
                    let root = MerkleNode::rebuild_to_root(
                        capacity,
                        uid,
                        &path.nodes,
                        uid,
                        leaf.0.clone(),
                    )?;
                    if root.value() == commitment.root_value {
                        Some(MerkleTree {
                            root,
                            height: commitment.height,
                            capacity,
                            num_leaves,
                        })
                    } else {
                        None
                    }
                }
            }
        }
    }

    /// get the collected commitment
    pub fn commitment(&self) -> MerkleCommitment {
        MerkleCommitment {
            root_value: self.root.value(),
            height: self.height,
            num_leaves: self.num_leaves,
        }
    }
    /// get the frontier
    pub fn frontier(&self) -> MerkleFrontier<E> {
        if self.num_leaves > 0 {
            MerkleFrontier::Proof(self.get_leaf(self.num_leaves - 1).expect_ok().unwrap().1)
        } else {
            MerkleFrontier::Empty {
                height: self.height,
            }
        }
    }

    /// get the height
    pub fn height(&self) -> u8 {
        self.height
    }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    pub fn push(&mut self, elem: E) {
        let pos = self.num_leaves;
        let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
        self.root = root.insert_at_right(self.capacity, pos, elem);

        self.num_leaves += 1;
    }

    /// Returns the leaf value given a position
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, None if the leaf position has been
    ///   forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<(), MerkleLeafProof<E>> {
        if pos >= self.capacity {
            LookupResult::EmptyLeaf
        } else {
            self.root
                .get_leaf(self.capacity, pos)
                .map(|elem, nodes| ((), MerkleLeafProof::new(elem, MerklePath { nodes })))
        }
    }

    /// Verify an element is a leaf of a Merkle tree given the root of the tree
    /// an a path
    /// * `root_value` - value of the root of the tree
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - element from which the leaf value is computed and list of
    ///   node siblings/positions from the leaf to the root
    /// * `returns` - Ok(()) if the verification succeeds, Err(computed_root)
    ///   otherwise
    pub fn check_proof(
        root_value: NodeValue,
        pos: u64,
        proof: &MerkleLeafProof<E>,
    ) -> Result<(), Option<NodeValue>> {
        let mut current_val = MerkleNode::new_leaf(pos, proof.leaf.0.clone()).value();
        for mt_node in proof.path.nodes.iter() {
            let pos = mt_node.pos;
            let sibling1_value = mt_node.sibling1;
            let sibling2_value = mt_node.sibling2;

            let (l, m, r) = match pos {
                NodePos::Left => (current_val, sibling1_value, sibling2_value),
                NodePos::Middle => (sibling1_value, current_val, sibling2_value),
                NodePos::Right => (sibling1_value, sibling2_value, current_val),
            };

            current_val = MerkleNode::<E>::new_branch(
                Box::new(MerkleNode::ForgottenSubtree { value: l }),
                Box::new(MerkleNode::ForgottenSubtree { value: m }),
                Box::new(MerkleNode::ForgottenSubtree { value: r }),
            )
            .ok_or(None)?
            .value()
        }

        if root_value == current_val {
            Ok(())
        } else {
            Err(Some(current_val))
        }
    }

    /// Trim the leaf at position `i` from memory, if present.
    /// Will not trim if position `i` is the last inserted leaf position.
    /// Return is identical to result if `get_leaf(pos)` were called before this
    /// call.
    pub fn forget(&mut self, pos: u64) -> LookupResult<(), MerkleLeafProof<E>> {
        if pos == self.num_leaves - 1 {
            self.get_leaf(pos)
        } else {
            let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
            let (root, pf) = root.internal_forget(self.capacity, pos);
            self.root = root;
            pf.map(|elem, nodes| ((), MerkleLeafProof::new(elem, MerklePath { nodes })))
        }
    }

    /// "Re-insert" a leaf into the tree using its proof.
    /// Returns Ok(()) if insertion is successful, or Err((ix,val)) if the
    /// proof disagrees with the correct node value `val` at position `ix`
    /// in the proof.
    pub fn remember(
        &mut self,
        pos: u64,
        proof: &MerkleLeafProof<E>,
    ) -> Result<(), Option<(usize, NodeValue)>> {
        let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
        let path = {
            let mut path = vec![];
            let mut val = MerkleNode::new_leaf(pos, proof.leaf.0.clone()).value();
            for mt_node in proof.path.nodes.iter() {
                path.push((val, mt_node.clone()));
                let pos = mt_node.pos;
                let sibling1_value = mt_node.sibling1;
                let sibling2_value = mt_node.sibling2;

                let (l, m, r) = match pos {
                    NodePos::Left => (val, sibling1_value, sibling2_value),
                    NodePos::Middle => (sibling1_value, val, sibling2_value),
                    NodePos::Right => (sibling1_value, sibling2_value, val),
                };

                val = MerkleNode::<E>::new_branch(
                    Box::new(MerkleNode::ForgottenSubtree { value: l }),
                    Box::new(MerkleNode::ForgottenSubtree { value: m }),
                    Box::new(MerkleNode::ForgottenSubtree { value: r }),
                )
                .ok_or(None)?
                .value()
            }
            path
        };
        let (root, res) = root.internal_remember(0, proof.leaf.0.clone(), &path);
        self.root = root;
        res
    }
}

pub struct FilledMTBuilder<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    peaks: Vec<(MerkleNode<E>, MerkleNode<E>)>,
    filled_root: Option<MerkleNode<E>>,
    height: u8,
    capacity: u64,
    num_leaves: u64,
}

impl<E> FilledMTBuilder<E>
where
    E: Clone + Debug + PartialEq + Eq + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new(height: u8) -> Option<Self> {
        let capacity = (3_u64).checked_pow(height as u32)?;
        let peak_positions = height as usize;
        let mut peaks = Vec::with_capacity(peak_positions);
        peaks.resize(
            peak_positions,
            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
        );

        Some(FilledMTBuilder {
            peaks,
            filled_root: None,
            height,
            capacity,
            num_leaves: 0,
        })
    }

    // consumes an existing tree, claiming ownership of the frontier peaks, and will
    // build the new tree from there after batch updates
    pub fn from_existing(tree: MerkleTree<E>) -> Option<Self> {
        let height = tree.height;
        let peak_positions = height as usize;
        let capacity = tree.capacity;
        let num_leaves = tree.num_leaves;
        let mut peaks = Vec::with_capacity(peak_positions);
        peaks.resize(
            peak_positions,
            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
        );
        if num_leaves == 0 {
            Some(FilledMTBuilder {
                peaks,
                filled_root: None,
                height,
                capacity,
                num_leaves,
            })
        } else if num_leaves == capacity {
            Some(FilledMTBuilder {
                peaks,
                filled_root: Some(tree.root),
                height,
                capacity,
                num_leaves,
            })
        } else if let MerkleNode::Branch { children, .. } = tree.root {
            if Self::take_frontiers(children, &mut peaks, num_leaves, capacity) {
                Some(FilledMTBuilder {
                    peaks,
                    filled_root: None,
                    height,
                    capacity,
                    num_leaves,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    // starts with a commitment and frontier, extends tree forward for batch updates
    pub fn from_frontier(
        commitment: &MerkleCommitment,
        frontier: &MerkleFrontier<E>,
    ) -> Option<Self> {
        match frontier {
            MerkleFrontier::Empty { height } => {
                if commitment.num_leaves == 0
                    && commitment.height == *height
                    && commitment.root_value == NodeValue::empty_node_value()
                {
                    return Self::new(commitment.height);
                }
            }
            MerkleFrontier::Proof(MerkleLeafProof { leaf, path }) => {
                let num_leaves = commitment.num_leaves;
                if num_leaves == 0 {
                    debug_assert!(num_leaves != 0);
                    return None;
                }
                let height = commitment.height;
                let capacity = (3_u64).checked_pow(height as u32)?;
                let uid = num_leaves - 1;
                let root =
                    MerkleNode::rebuild_to_root(capacity, uid, &path.nodes, uid, leaf.0.clone())?;
                if root.value() == commitment.root_value {
                    if let MerkleNode::Branch { children, .. } = root {
                        let peak_positions = height as usize;
                        let mut peaks = Vec::with_capacity(peak_positions);
                        peaks.resize(
                            peak_positions,
                            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                        );
                        if Self::take_frontiers(children, &mut peaks, num_leaves, capacity) {
                            return Some(FilledMTBuilder {
                                peaks,
                                filled_root: None,
                                height,
                                capacity,
                                num_leaves,
                            });
                        }
                    }
                }
            }
        };
        None
    }

    fn take_frontiers(
        children: [Box<MerkleNode<E>>; 3],
        level_array: &mut [(MerkleNode<E>, MerkleNode<E>)],
        contained_leaves: u64,
        level_capacity: u64,
    ) -> bool {
        if contained_leaves == 0 || level_array.is_empty() {
            false
        } else {
            let (siblings, lower_levels) = level_array.split_last_mut().unwrap();
            let node_capacity = level_capacity / 3;
            let [child0, child1, child2] = children;
            let (remainder, branch_node) = match contained_leaves / node_capacity {
                0 => (contained_leaves, *child0),
                1 => {
                    siblings.0 = *child0;
                    (contained_leaves - node_capacity, *child1)
                }
                2 => {
                    siblings.0 = *child0;
                    siblings.1 = *child1;
                    (contained_leaves - (2 * node_capacity), *child2)
                }
                _ => unreachable!(),
            };

            if remainder > 0 {
                match branch_node {
                    MerkleNode::Branch { children, .. } => {
                        Self::take_frontiers(children, lower_levels, remainder, node_capacity)
                    }
                    _ => unreachable!(),
                }
            } else {
                true
            }
        }
    }

    // internal because this should only be used when forgetting all children is
    // implicitly okay
    fn prune_node(node_in: MerkleNode<E>) -> MerkleNode<E> {
        match node_in {
            MerkleNode::Leaf { value, .. } => MerkleNode::ForgottenSubtree { value },
            MerkleNode::Branch { value, .. } => MerkleNode::ForgottenSubtree { value },
            node => node, // empty and forgotten are unchanged
        }
    }

    // creates the nodes upward to whatever peak is now filled above the newly added
    // leaf. While still below the peak, creates a new filled branch for each
    // level, consuming the previously created left and middle (0, 1) siblings
    // into the new branch. When the peak is reached, inserts the newly-filled
    // `node` at `level_index`
    fn roll_up(
        peaks_from_level: &mut [(MerkleNode<E>, MerkleNode<E>)],
        filled_root: &mut Option<MerkleNode<E>>,
        node: MerkleNode<E>,
        level_index: u64,
    ) {
        if peaks_from_level.is_empty() {
            if filled_root.is_none() {
                *filled_root = Some(node);
            }
            return;
        }
        match level_index % 3 {
            0 => peaks_from_level[0].0 = node,
            1 => peaks_from_level[0].1 = node,
            2 => {
                let (level_peaks, higher_peaks) = peaks_from_level.split_first_mut().unwrap();
                let level_peaks = mem::replace(
                    level_peaks,
                    (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                );
                Self::roll_up(
                    higher_peaks,
                    filled_root,
                    MerkleNode::new_branch(
                        Box::new(level_peaks.0),
                        Box::new(level_peaks.1),
                        Box::new(node),
                    )
                    .unwrap(),
                    level_index / 3,
                );
            }
            _ => unreachable!(),
        }
    }

    // creates the non-filled branch nodes from the array of filled peaks, up to the
    // root
    fn build_up(
        level_array: &mut [(MerkleNode<E>, MerkleNode<E>)],
        contained_leaves: u64,
        level_capacity: u64,
        prune: bool,
    ) -> MerkleNode<E> {
        if contained_leaves == 0 {
            MerkleNode::EmptySubtree
        } else {
            if level_array.is_empty() {
                return MerkleNode::EmptySubtree;
            }
            let (siblings, lower_levels) = level_array.split_last_mut().unwrap();
            let siblings = mem::replace(
                siblings,
                (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
            );
            let node_capacity = level_capacity / 3;
            let new_contained_leaves = contained_leaves % node_capacity;
            let new_node = Self::build_up(lower_levels, new_contained_leaves, node_capacity, prune);
            let has_empty_child = matches!(new_node, MerkleNode::EmptySubtree);
            let (l, m, r) = match contained_leaves / node_capacity {
                0 => (new_node, MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                1 => {
                    if prune && !has_empty_child {
                        (
                            Self::prune_node(siblings.0),
                            new_node,
                            MerkleNode::EmptySubtree,
                        )
                    } else {
                        (siblings.0, new_node, MerkleNode::EmptySubtree)
                    }
                }
                2 => {
                    if prune {
                        if has_empty_child {
                            (Self::prune_node(siblings.0), siblings.1, new_node)
                        } else {
                            (
                                Self::prune_node(siblings.0),
                                Self::prune_node(siblings.1),
                                new_node,
                            )
                        }
                    } else {
                        (siblings.0, siblings.1, new_node)
                    }
                }
                _ => unreachable!(),
            };
            MerkleNode::new_branch(Box::new(l), Box::new(m), Box::new(r))
                .unwrap_or(MerkleNode::EmptySubtree)
        }
    }

    pub fn push(&mut self, elem: E) {
        if self.num_leaves == self.capacity {
            return;
        }

        let leaf_node = MerkleNode::new_leaf(self.num_leaves, elem);
        Self::roll_up(
            &mut self.peaks,
            &mut self.filled_root,
            leaf_node,
            self.num_leaves,
        );
        self.num_leaves += 1;
    }

    pub fn build(mut self) -> MerkleTree<E> {
        let root = if let Some(filled_root) = self.filled_root {
            filled_root
        } else {
            Self::build_up(&mut self.peaks, self.num_leaves, self.capacity, false)
        };
        MerkleTree {
            root,
            height: self.height,
            capacity: self.capacity,
            num_leaves: self.num_leaves,
        }
    }

    pub fn build_pruned(mut self) -> MerkleTree<E> {
        let root = if let Some(filled_root) = self.filled_root {
            filled_root
        } else {
            Self::build_up(&mut self.peaks, self.num_leaves, self.capacity, true)
        };
        MerkleTree {
            root,
            height: self.height,
            capacity: self.capacity,
            num_leaves: self.num_leaves,
        }
    }

    pub fn into_frontier_and_commitment(self) -> (MerkleFrontier<E>, MerkleCommitment) {
        // TODO: more efficient implementation
        let mt = self.build();
        (mt.frontier(), mt.commitment())
    }
}

impl<
        E: Clone + CanonicalSerialize + Debug + PartialEq + Eq + Hash + Default + CanonicalDeserialize,
    > From<FilledMTBuilder<E>> for MerkleTree<E>
{
    fn from(builder: FilledMTBuilder<E>) -> Self {
        builder.build()
    }
}

#[cfg(test)]
mod mt_tests {

    use crate::merkle_tree::*;
    use quickcheck::{Gen, QuickCheck};

    #[derive(Clone, Debug)]
    enum ArrayOp {
        Push(u64),      // Append a value
        Swap(u16),      // "move" an index to the other array
        Challenge(u16), // check that all arrays are consistent at that index
    }

    impl quickcheck::Arbitrary for ArrayOp {
        fn arbitrary(g: &mut Gen) -> Self {
            use ArrayOp::*;
            let choices = [
                Push(<_>::arbitrary(g)),
                Swap(<_>::arbitrary(g)),
                Challenge(<_>::arbitrary(g)),
            ];
            g.choose(&choices).unwrap().clone()
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            use ArrayOp::*;
            match self {
                Push(x) => Box::new(x.shrink().map(Push)),
                Swap(ix) => Box::new(core::iter::once(Challenge(*ix)).chain(ix.shrink().map(Swap))),
                Challenge(ix) => Box::new(ix.shrink().map(Challenge)),
            }
        }
    }

    #[test]
    fn quickcheck_mt_test_against_array() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(mt_test_against_array_helper as fn(_, Vec<_>) -> ());
    }

    #[test]
    fn mt_test_against_array_regressions() {
        use ArrayOp::*;

        mt_test_against_array_helper(0, vec![Push(18446744073709551614), Challenge(0)]);
    }

    fn mt_test_against_array_helper(height: u8, ops: Vec<ArrayOp>) {
        let height = height / 13 + 1; // cap it to ~20
        let mut full = MerkleTree::<u64>::new(height).unwrap();
        let mut full_vec = vec![];
        let mut sparse_l = MerkleTree::<u64>::new(height).unwrap();
        let mut sparse_l_vec = vec![];
        let mut sparse_r = MerkleTree::<u64>::new(height).unwrap();
        let mut sparse_r_vec = vec![];
        let mut pruned = MerkleTree::<u64>::new(height).unwrap();
        let mut pruned_vec = vec![];

        for op in ops {
            assert_eq!(full.root.value(), sparse_l.root.value());
            assert_eq!(full.root.value(), sparse_r.root.value());
            assert_eq!(full.num_leaves(), sparse_l.num_leaves());
            assert_eq!(full.num_leaves(), sparse_r.num_leaves());

            match op {
                ArrayOp::Push(val_v) => {
                    if full.num_leaves == full.capacity {
                        continue;
                    }
                    // let val_v = F::from(val);
                    full.push(val_v);
                    full_vec.push(Some(val_v));
                    sparse_l.push(val_v);
                    sparse_l_vec.push(Some(val_v));
                    sparse_r.push(val_v);
                    sparse_r_vec.push(Some(val_v));
                    pruned.push(val_v);
                    pruned_vec.push(Some(val_v));
                    let ix = sparse_r.num_leaves() - 1;

                    let forgotten_r = sparse_r.forget(ix);
                    let forgotten_f = pruned.forget(ix);
                    let (_, proof_r) = forgotten_r.clone().expect_ok().unwrap();
                    let (_, proof_f) = forgotten_f.clone().expect_ok().unwrap();
                    if ix > 0 {
                        let _ = sparse_r.forget(ix - 1).expect_ok().unwrap();
                        let _ = pruned.forget(ix - 1).expect_ok().unwrap();
                    }
                    sparse_r_vec[ix as usize] = None;
                    pruned_vec[ix as usize] = None;
                    assert_eq!(proof_r.leaf.0, val_v);
                    assert_eq!(proof_f.leaf.0, val_v);

                    MerkleTree::check_proof(full.root.value(), ix, &proof_r).unwrap();
                    MerkleTree::check_proof(full.root.value(), ix, &proof_f).unwrap();

                    assert_eq!(sparse_r.get_leaf(ix), forgotten_r);
                    assert_eq!(pruned.get_leaf(ix), forgotten_f);
                    if ix > 0 {
                        assert!(matches!(
                            sparse_r.get_leaf(ix - 1),
                            LookupResult::NotInMemory
                        ));
                        assert!(matches!(pruned.get_leaf(ix - 1), LookupResult::NotInMemory));
                    }

                    assert_eq!(full.get_leaf(ix), sparse_l.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix), sparse_r.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix), pruned.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix).expect_ok().unwrap().1.leaf.0, val_v);

                    // from frontier commitment
                    let commitment = pruned.commitment();
                    let frontier = pruned.frontier();

                    let built_fr =
                        MerkleTree::restore_from_frontier(commitment, &frontier).unwrap();
                    assert_eq!(pruned.get_leaf(ix), built_fr.get_leaf(ix));
                    assert_eq!(pruned.root.value(), built_fr.root.value());
                }

                ArrayOp::Swap(ix) => {
                    if full.num_leaves() <= 1 {
                        continue;
                    }
                    // constrained to not include the rightmost leaf, because that won't be
                    // forgotten.
                    let ix = (ix as u64) % (full.num_leaves() - 1);
                    if let Some(val) = sparse_l_vec.get(ix as usize).unwrap() {
                        assert!(matches!(sparse_r.get_leaf(ix), LookupResult::NotInMemory));
                        let (_, proof) = sparse_l.forget(ix).expect_ok().unwrap();
                        assert_eq!(proof.leaf.0, *val);
                        sparse_r.remember(ix, &proof).unwrap();
                        assert_eq!(((), proof), sparse_r.get_leaf(ix).expect_ok().unwrap());
                        assert!(matches!(sparse_l.get_leaf(ix), LookupResult::NotInMemory));
                        sparse_r_vec[ix as usize] = Some(*val);
                        sparse_l_vec[ix as usize] = None;
                    } else {
                        let val = sparse_r_vec.get(ix as usize).unwrap().unwrap();
                        assert!(matches!(sparse_l.get_leaf(ix), LookupResult::NotInMemory));
                        let (_, proof) = sparse_r.forget(ix).expect_ok().unwrap();
                        assert_eq!(proof.leaf.0, val);
                        sparse_l.remember(ix, &proof).unwrap();
                        assert_eq!(((), proof), sparse_l.get_leaf(ix).expect_ok().unwrap());
                        assert!(matches!(sparse_r.get_leaf(ix), LookupResult::NotInMemory));
                        sparse_l_vec[ix as usize] = Some(val);
                        sparse_r_vec[ix as usize] = None;
                    }
                }

                ArrayOp::Challenge(ix) => {
                    let ix = ix as u64;
                    assert_eq!(
                        <Option<Option<_>>>::from(full.get_leaf(ix)),
                        <Option<Option<_>>>::from(sparse_l.get_leaf(ix)).or_else(|| <Option<
                            Option<_>,
                        >>::from(
                            sparse_r.get_leaf(ix)
                        ))
                    );

                    let res = <Option<Option<_>>>::from(full.get_leaf(ix)).unwrap();
                    assert_eq!(
                        res.clone().map(|(_, x)| x.leaf.0),
                        full_vec.get(ix as usize).map(|x| x.unwrap())
                    );
                    assert_eq!(
                        res.clone().map(|(_, x)| x.leaf.0),
                        sparse_l_vec.get(ix as usize).map(|x| x
                            .or_else(|| *sparse_r_vec.get(ix as usize).unwrap())
                            .unwrap())
                    );

                    if let Some((_, proof)) = res {
                        let v_bad = proof.leaf.0 + 1;
                        MerkleTree::check_proof(full.root.value(), ix, &proof).unwrap();
                        MerkleTree::check_proof(
                            full.root.value(),
                            ix,
                            &MerkleLeafProof::new(v_bad, proof.path.clone()),
                        )
                        .unwrap_err();
                    }

                    // check against full tree restored from builder
                    let mut full_builder = FilledMTBuilder::<u64>::new(height).unwrap();
                    for leaf in full_vec.iter() {
                        full_builder.push(leaf.unwrap());
                    }

                    let built_fl = full_builder.build();
                    assert_eq!(full.root.value(), built_fl.root.value());
                    assert_eq!(full.get_leaf(ix), built_fl.get_leaf(ix));
                    if ix > 0 {
                        // edge case: leftmost
                        assert_eq!(full.get_leaf(0), built_fl.get_leaf(0));
                    }
                    if ix > 2 {
                        // edge case: first right leaf
                        assert_eq!(full.get_leaf(2), built_fl.get_leaf(2));
                    }
                    if ix > 3 {
                        // edge case: second set, first leaf
                        assert_eq!(full.get_leaf(3), built_fl.get_leaf(3));
                    }
                }
            }
        }
    }

    #[test]
    fn mt_gen() {
        mt_gen_helper();
    }
    fn mt_gen_helper() {
        const HEIGHT: u8 = 5;
        let mt = MerkleTree::<u64>::new(HEIGHT).unwrap();
        assert_eq!(mt.height, HEIGHT);
        assert_eq!(mt.root.value(), NodeValue::empty_node_value());
        assert_eq!(mt.num_leaves, 0);
    }

    fn check_proof(
        mt_state: &MerkleTree<u64>,
        pos: u64,
        elem: u64,
        root_value: Option<NodeValue>,
        expected_res: bool,
    ) {
        let proof = mt_state.get_leaf(pos).expect_ok().unwrap().1;
        let rt = root_value.unwrap_or_else(|| mt_state.root.value());
        let new_proof = MerkleLeafProof::new(elem, proof.path);
        assert_eq!(
            MerkleTree::check_proof(rt, pos, &new_proof).is_ok(),
            expected_res
        );
    }

    #[test]
    fn mt_get_leaf_value() {
        mt_get_leaf_value_helper();
    }

    fn mt_get_leaf_value_helper() {
        const HEIGHT: u8 = 3;
        let mut mt = MerkleTree::<u64>::new(HEIGHT).unwrap();

        let elem1 = 2u64;
        mt.push(elem1);

        let elem2 = 4u64;
        mt.push(elem2);

        let expected_leaf_value1 = mt.get_leaf(0).expect_ok().unwrap().1.leaf.0;
        assert_eq!(expected_leaf_value1, elem1);

        let expected_leaf_value2 = mt.get_leaf(1).expect_ok().unwrap().1.leaf.0;
        assert_eq!(expected_leaf_value2, elem2);

        let invalid_leaf_value = mt.get_leaf(2);
        assert!(matches!(invalid_leaf_value, LookupResult::EmptyLeaf));
    }

    #[test]
    fn mt_get_num_leaves() {
        mt_get_num_leaves_helper();
    }

    fn mt_get_num_leaves_helper() {
        const HEIGHT: u8 = 3;
        let mut mt = MerkleTree::<u64>::new(HEIGHT).unwrap();
        assert_eq!(mt.num_leaves(), 0);

        mt.push(2u64);
        assert_eq!(mt.num_leaves(), 1);

        mt.push(4u64);
        assert_eq!(mt.num_leaves(), 2);
    }

    #[test]
    fn mt_prove_and_verify() {
        mt_prove_and_verify_helper();
    }

    fn mt_prove_and_verify_helper() {
        let mut mt_state = MerkleTree::<u64>::new(3).unwrap();
        let elem0 = 4u64;
        mt_state.push(elem0);

        let elem1 = 7u64;
        mt_state.push(elem1);

        let elem2 = 20u64;
        mt_state.push(elem2);

        let elem3 = 16u64;
        mt_state.push(elem3);

        check_proof(&mt_state, 0, elem0, None, true);
        check_proof(&mt_state, 1, elem1, None, true);
        check_proof(&mt_state, 2, elem2, None, true);
        check_proof(&mt_state, 3, elem3, None, true);

        check_proof(&mt_state, 0, elem3, None, false);
        check_proof(&mt_state, 3, elem0, None, false);

        let wrong_root_value = NodeValue([1u8; NODE_VALUE_LEN]);
        check_proof(&mt_state, 0, elem0, Some(wrong_root_value), false);
    }

    #[test]
    fn test_sparse_proof_update() {
        test_sparse_proof_update_helper();
    }
    fn test_sparse_proof_update_helper() {
        let mut mt = MerkleTree::<u64>::new(3).unwrap();
        mt.push(50u64);
        mt.push(100u64);
        let mut mt_sparse = mt.clone();
        mt_sparse.forget(1);
        mt.push(500u64);
        mt_sparse.push(500u64);
        mt_sparse.forget(2);
        // `proof` is relative to the tree with [50,100,500]
        let proof = mt_sparse.get_leaf(0).expect_ok().unwrap().1;
        assert_eq!(proof.leaf.0, 50u64);
        MerkleTree::check_proof(mt.root.value(), 0, &proof).unwrap()
    }

    #[test]
    fn test_mt_restore_from_frontier() {
        test_mt_restore_from_frontier_helper(39, 59);

        test_mt_restore_from_frontier_helper(1, 1);

        test_mt_restore_from_frontier_empty();
    }
    fn test_mt_restore_from_frontier_helper(height: u8, count: u64) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let count = count % capacity;
        let mut full_tree = MerkleTree::<u64>::new(height).unwrap();
        let mut pruned_tree = MerkleTree::<u64>::new(height).unwrap();
        let mut rng = ark_std::test_rng();
        for idx in 0..count {
            let val: u64 = rng.gen();
            full_tree.push(val);
            pruned_tree.push(val);
            if idx > 0 {
                pruned_tree.forget(idx - 1);
            }
        }

        let full_comm = full_tree.commitment();
        let full_proof = full_tree.frontier();
        let pruned_comm = pruned_tree.commitment();
        let pruned_proof = pruned_tree.frontier();
        let restored_full =
            MerkleTree::<u64>::restore_from_frontier(full_comm, &full_proof).unwrap();
        let restored_pruned =
            MerkleTree::<u64>::restore_from_frontier(pruned_comm, &pruned_proof).unwrap();
        assert_eq!(full_tree.root.value(), restored_full.root.value());
        assert_eq!(pruned_tree.root.value(), restored_pruned.root.value());
    }
    fn test_mt_restore_from_frontier_empty() {
        let mut pruned_tree_h3 = MerkleTree::<u64>::new(3).unwrap();
        let mut pruned_tree_h4 = MerkleTree::<u64>::new(4).unwrap();
        let empty_commitment_h3 = pruned_tree_h3.commitment();
        let empty_commitment_h4 = pruned_tree_h4.commitment();
        let empty_frontier_h3 = pruned_tree_h3.frontier();
        let empty_frontier_h4 = pruned_tree_h4.frontier();
        let mut rng = ark_std::test_rng();
        for idx in 0..7 {
            let val = rng.gen();
            pruned_tree_h3.push(val);
            pruned_tree_h4.push(val);
            if idx > 0 {
                pruned_tree_h3.forget(idx - 1);
                pruned_tree_h4.forget(idx - 1);
            }
        }
        let commitment_h3 = pruned_tree_h3.commitment();
        let commitment_h4 = pruned_tree_h4.commitment();
        let frontier_h3 = pruned_tree_h3.frontier();
        let frontier_h4 = pruned_tree_h4.frontier();

        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h3, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h4, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h3, &frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h3, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h4, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h4, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h3, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h3, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h4, &frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h4, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h3, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<u64>::restore_from_frontier(commitment_h4, &frontier_h3),
            None
        );

        let empty_restore_3 =
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h3, &empty_frontier_h3)
                .unwrap();
        assert_eq!(empty_restore_3.num_leaves(), 0);
        let empty_restore_4 =
            MerkleTree::<u64>::restore_from_frontier(empty_commitment_h4, &empty_frontier_h4)
                .unwrap();
        assert_eq!(empty_restore_4.num_leaves(), 0);
    }

    #[test]
    fn test_mt_restore_from_leafs() {
        test_mt_restore_from_leafs_helper(39, 59);

        test_mt_restore_from_leafs_helper(0, 1);
    }
    fn test_mt_restore_from_leafs_helper(height: u8, count: u64) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let count = count % capacity;
        let mut full_tree = MerkleTree::<u64>::new(height).unwrap();
        let mut full_array = Vec::new();
        let mut rng = ark_std::test_rng();
        for _ in 0..count {
            let val = rng.gen();
            full_tree.push(val);
            full_array.push(val);
        }
        let idx = full_array.len() as u64 - 1;
        let mut builder = FilledMTBuilder::new(height).unwrap();
        for leaf in &full_array {
            builder.push(*leaf);
        }
        let built_full = builder.build();
        assert_eq!(full_tree.get_leaf(idx), built_full.get_leaf(idx));
        assert_eq!(full_tree.root.value(), built_full.root.value());
    }

    #[test]
    fn test_mt_batch_insertion() {
        test_mt_batch_insertion_helper(52, 59, 25);
    }
    fn test_mt_batch_insertion_helper(height: u8, initial_count: u64, batch_count: u64) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let initial_count = initial_count % capacity;
        let mut full_tree = MerkleTree::<u64>::new(height).unwrap();
        let mut rng = ark_std::test_rng();
        for _ in 0..initial_count {
            let val = rng.gen();
            full_tree.push(val);
        }

        let frontier = full_tree.frontier();
        let commitment = full_tree.commitment();

        let mut sparse_tree = MerkleTree::restore_from_frontier(commitment, &frontier).unwrap();
        let full_to_take = full_tree.clone();
        let sparse_to_take = sparse_tree.clone();

        let mut builder_from_full = FilledMTBuilder::from_existing(full_to_take).unwrap();
        let mut builder_from_sparse = FilledMTBuilder::from_existing(sparse_to_take).unwrap();
        let mut builder_from_frontier =
            FilledMTBuilder::from_frontier(&commitment, &frontier).unwrap();

        for ix in initial_count..initial_count + batch_count {
            let val = rng.gen();
            full_tree.push(val);
            sparse_tree.push(val);
            if ix > 0 {
                sparse_tree.forget(ix - 1);
            }
            builder_from_full.push(val);
            builder_from_sparse.push(val);
            builder_from_frontier.push(val);
        }
        let built_full = builder_from_full.build();
        let built_sparse = builder_from_sparse.build_pruned();
        let (frontier_out, commitment_out) = builder_from_frontier.into_frontier_and_commitment();
        let num_leaves = initial_count + batch_count;
        let idx = num_leaves - 1;

        assert_eq!(num_leaves, full_tree.num_leaves());
        assert_eq!(num_leaves, sparse_tree.num_leaves());
        assert_eq!(num_leaves, built_full.num_leaves());
        assert_eq!(num_leaves, built_sparse.num_leaves());
        assert_eq!(num_leaves, commitment_out.num_leaves);

        let full_leaf_proof = full_tree.get_leaf(idx);
        assert_eq!(full_leaf_proof, sparse_tree.get_leaf(idx));
        assert_eq!(full_leaf_proof, built_full.get_leaf(idx));
        assert_eq!(full_leaf_proof, built_sparse.get_leaf(idx));

        let root_value = full_tree.root.value();
        assert_eq!(root_value, built_full.root.value());
        assert_eq!(root_value, sparse_tree.root.value());
        assert_eq!(root_value, built_sparse.root.value());

        let full_tree_frontier = full_tree.frontier();
        let sparse_tree_frontier = sparse_tree.frontier();
        let built_full_frontier = built_full.frontier();
        let built_sparse_frontier = built_sparse.frontier();

        assert_eq!(full_tree_frontier, sparse_tree_frontier);
        assert_eq!(full_tree_frontier, built_full_frontier);
        assert_eq!(full_tree_frontier, built_sparse_frontier);
        assert_eq!(full_tree_frontier, frontier_out);

        let full_tree_commitment = full_tree.commitment();
        let sparse_tree_commitment = sparse_tree.commitment();
        let built_full_commitment = built_full.commitment();
        let built_sparse_commitment = built_sparse.commitment();

        assert_eq!(full_tree_commitment, sparse_tree_commitment);
        assert_eq!(full_tree_commitment, built_full_commitment);
        assert_eq!(full_tree_commitment, built_sparse_commitment);
        assert_eq!(full_tree_commitment, commitment_out);
    }
}
