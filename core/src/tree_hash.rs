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

use crate::util::canonical;
// use arbitrary_wrappers::*;
use ark_serialize::*;
use core::fmt::Debug;
use generic_array::{arr::AddLength, ArrayLength, GenericArray};
use typenum::U1;

/// A hash function usable for sparse merkle tree implementations.
///
/// Inherits several other traits for `#[derive]` ergonomics
pub trait KVTreeHash: Copy + Clone + PartialEq + Eq + Debug {
    /// The output of the hash function
    type Digest: core::hash::Hash
        + Debug
        + Eq
        + PartialEq
        + Copy
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// A data type for keys
    /// A data type for values
    type Key: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    type Value: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;

    /// The number of children each branch has minus one. This is due to the proof paths having sibling
    /// path lengths of n-1 and the generic implementation relying on type systems
    type BranchArityMinus1: AddLength<Self::Digest, U1>
        + ArrayLength<Self::Digest>
        + Debug
        + PartialEq;
    /// How many base-BranchArityMinus1 place values are in a `Digest`
    type MaxDepth: ArrayLength<u8> + Debug + PartialEq;

    /// A unique digest for empty subtrees
    fn empty_digest() -> Self::Digest;

    /// Convert a digest to a traversal
    fn traversal_of_digest(d: Self::Digest) -> GenericArray<u8, Self::MaxDepth>;

    /// Convert a traversal back to a digest. Primarily relevant for
    /// testing. Should return None if and only if a traversal is not
    /// representable by a Digest.
    fn digest_of_traversal(t: &GenericArray<u8, Self::MaxDepth>) -> Option<Self::Digest>;

    /// Hash a leaf's contents
    fn hash_leaf(key: Self::Key, value: Self::Value) -> Self::Digest;

    /// Hash a key's contents
    fn hash_key(key: Self::Key) -> Self::Digest;

    /// Hash a branch's children: the number of siblings in a branch is one greater than the
    /// AddLength<Self::BranchArityMinus1,U1>
    #[allow(clippy::type_complexity)]
    fn hash_branch(
        children: &GenericArray<
            Self::Digest,
            <Self::BranchArityMinus1 as AddLength<Self::Digest, U1>>::Output,
        >,
    ) -> Self::Digest;
}

pub mod treehash_tests {
    use super::*;
    use std::collections::HashSet;
    use typenum::Unsigned;

    pub fn treehash_basic_checks<TH: KVTreeHash>() {
        assert!(<TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_usize() > 0);
        assert_eq!(
            <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_usize(),
            <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_u8() as usize
        );
        assert!(TH::MaxDepth::to_usize() > 0);
        assert_eq!(TH::MaxDepth::to_usize(), TH::MaxDepth::to_u16() as usize);
        assert_eq!(TH::empty_digest(), TH::empty_digest());

        assert_ne!(
            TH::empty_digest(),
            TH::hash_branch(
                &GenericArray::from_exact_iter(vec![
                    TH::empty_digest();
                    <TH::BranchArityMinus1 as AddLength<
                        TH::Digest,
                        U1,
                    >>::Output::to_usize()
                ])
                .unwrap()
            )
        );
    }

    pub fn treehash_check_traversal_of_digest<TH: KVTreeHash>(d: TH::Digest) {
        let t = TH::traversal_of_digest(d);
        let d1 = TH::digest_of_traversal(&t).expect("digest generated a wrong traversal");
        let t1 = TH::traversal_of_digest(d);
        assert_eq!(d, d1, "digest -> traversal -> digest should be identity");
        assert_eq!(t, t1, "traversal -> digest -> traversal should be identity");

        for (i, x) in t.iter().enumerate() {
            assert!(
                ((*x) as usize)
                    < <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_usize(),
                "traversal has invalid step {} at position {}",
                x,
                i
            );
        }

        // Since we're assuming the traversal is a base-N representation of
        // the digest, we'd expect:
        //  - Changing any traversal step to be too large should yield an
        //    invalid traversal
        //  - reducing a traversal position should always yield another
        //    valid traversal

        // make traversal steps too large
        {
            let mut t2 = t.clone();
            for i in 0..t2.len() {
                let v = t2[i];

                t2[i] = <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_u8();
                assert_eq!(None, TH::digest_of_traversal(&t2));

                if <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_u8() <= 128 {
                    t2[i] =
                        v + <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_u8();
                    assert_eq!(None, TH::digest_of_traversal(&t2));
                }

                t2[i] = v;
            }
        }

        // make traversal steps smaller
        {
            let mut t2 = t;
            for i in 0..t2.len() {
                let v = t2[i];
                t2[i] = 0;

                TH::digest_of_traversal(&t2).unwrap();

                if v > 0 {
                    t2[i] = v - 1;
                    TH::digest_of_traversal(&t2).unwrap();
                }

                t2[i] = v;
            }
        }
    }

    pub fn treehash_check_digest_of_traversal<TH: KVTreeHash>(t: GenericArray<u8, TH::MaxDepth>) {
        let (t_reduced, t_extra_reduced) = {
            let mut ret = t.clone();
            for i in 0..ret.len() {
                ret[i] %= <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output::to_u8();
            }

            // set the most significant place to 0
            //
            // only needed if the largest Digest is below pow(AddLength<TH::BranchArityMinus1,U1>,
            // MaxDepth)
            let mut extra = ret.clone();
            let ix = extra.len() - 1;
            extra[ix] = 0;
            (ret, extra)
        };

        let d_reduced = TH::digest_of_traversal(&t_reduced).unwrap();
        let d_extra_reduced = TH::digest_of_traversal(&t_extra_reduced).unwrap();

        if t_reduced != t_extra_reduced {
            assert_ne!(d_reduced, d_extra_reduced);
        } else {
            assert_eq!(d_reduced, d_extra_reduced);
        }

        match TH::digest_of_traversal(&t) {
            Some(d) => {
                assert_eq!((t, d), (t_reduced, d_reduced));
            }
            None => {
                assert_eq!(TH::traversal_of_digest(d_reduced), t_reduced);
            }
        }
    }

    pub fn treehash_check_leaf_key_domain_separation<TH: KVTreeHash>(
        key: TH::Key,
        value: TH::Value,
    ) {
        assert_ne!(TH::hash_leaf(key, value), TH::hash_key(key));
    }

    pub fn treehash_collision_sanity_checks1<TH: KVTreeHash>(
        k0: TH::Key,
        v0: TH::Value,
        k1: TH::Key,
        v1: TH::Value,
    ) {
        if (k0, v0) == (k1, v1) {
            assert_eq!(TH::hash_leaf(k0, v0), TH::hash_leaf(k1, v1));
        } else {
            assert_ne!(TH::hash_leaf(k0, v0), TH::hash_leaf(k1, v1));
        }

        if k0 == k1 {
            assert_eq!(TH::hash_key(k0), TH::hash_key(k1));
            assert_eq!(TH::hash_leaf(k0, v0), TH::hash_leaf(k1, v0));
            assert_eq!(TH::hash_leaf(k0, v1), TH::hash_leaf(k1, v1));
        } else {
            assert_ne!(TH::hash_key(k0), TH::hash_key(k1));

            assert_ne!(TH::hash_leaf(k0, v1), TH::hash_leaf(k1, v1));
            assert_ne!(TH::hash_leaf(k0, v0), TH::hash_leaf(k1, v0));
        }
    }

    pub fn treehash_collision_sanity_checks2<TH: KVTreeHash>(
        key: TH::Key,
        val: TH::Value,
        digests: GenericArray<
            TH::Digest,
            <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output,
        >,
    ) {
        let mut all_results = HashSet::new();
        all_results.insert(TH::empty_digest());

        assert!(all_results.insert(TH::hash_key(key)));
        assert!(all_results.insert(TH::hash_leaf(key, val)));
        assert!(all_results.insert(TH::hash_branch(&digests)));

        for d in digests.into_iter().collect::<HashSet<_>>().into_iter() {
            if d != TH::empty_digest() {
                // this might probabilistically fail, but it should be
                // incredibly unlikely unless quickcheck gets really smart
                assert!(all_results.insert(d));
            }
        }
    }

    pub fn treehash_collision_sanity_checks3<TH: KVTreeHash>(
        digests0: GenericArray<
            TH::Digest,
            <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output,
        >,
        digests1: GenericArray<
            TH::Digest,
            <TH::BranchArityMinus1 as AddLength<TH::Digest, U1>>::Output,
        >,
    ) {
        if digests0 == digests1 {
            assert_eq!(TH::hash_branch(&digests0), TH::hash_branch(&digests1));
        } else {
            assert_ne!(TH::hash_branch(&digests0), TH::hash_branch(&digests1));
        }
    }
}

pub mod committable_hash {
    use super::*;
    use commit::{Commitment, Committable};
    use core::marker::PhantomData;
    use typenum::Unsigned;

    pub trait CommitableHashTag: Copy + Clone + Debug + PartialEq + Eq {
        fn commitment_diversifier() -> &'static str;
    }

    #[derive(Clone, Debug, PartialEq, Eq, Copy)]
    pub struct CommitableHash<K, V, T>
    where
        K: Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        V: Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        T: CommitableHashTag,
    {
        _data: PhantomData<(K, V, T)>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CommitableHashNode<K, V, T>
    where
        K: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        V: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        T: CommitableHashTag,
    {
        Empty,
        KeyDigest {
            key: K,
            _t: PhantomData<T>,
        },
        Leaf {
            key: K,
            val: V,
            _t: PhantomData<T>,
        },
        Branch {
            l: Commitment<CommitableHashNode<K, V, T>>,
            r: Commitment<CommitableHashNode<K, V, T>>,
            _t: PhantomData<T>,
        },
    }

    impl<K, V, T> commit::Committable for CommitableHashNode<K, V, T>
    where
        K: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        V: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        T: CommitableHashTag,
    {
        fn commit(&self) -> commit::Commitment<Self> {
            use commit::RawCommitmentBuilder;
            use CommitableHashNode::*;
            match self {
                Empty => {
                    RawCommitmentBuilder::new(&format!("{} Empty", T::commitment_diversifier()))
                        .finalize()
                }
                KeyDigest { key, _t } => {
                    RawCommitmentBuilder::new(&format!("{} Key", T::commitment_diversifier()))
                        .var_size_bytes(&canonical::serialize(key).unwrap())
                        .finalize()
                }
                Leaf { key, val, _t } => {
                    RawCommitmentBuilder::new(&format!("{} Leaf", T::commitment_diversifier()))
                        .var_size_bytes(&canonical::serialize(key).unwrap())
                        .var_size_bytes(&canonical::serialize(val).unwrap())
                        .finalize()
                }

                Branch { l, r, _t } => {
                    RawCommitmentBuilder::new(&format!("{} Branch", T::commitment_diversifier()))
                        .field("l", *l)
                        .field("r", *r)
                        .finalize()
                }
            }
        }
    }

    impl<K, V, T> KVTreeHash for CommitableHash<K, V, T>
    where
        K: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        V: Debug + Copy + Clone + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize,
        T: CommitableHashTag,
    {
        type Digest = Commitment<CommitableHashNode<K, V, T>>;
        type Key = K;
        type Value = V;

        type BranchArityMinus1 = typenum::U1;
        type MaxDepth = typenum::U256;

        fn empty_digest() -> Self::Digest {
            CommitableHashNode::Empty.commit()
        }

        fn traversal_of_digest(d: Self::Digest) -> GenericArray<u8, Self::MaxDepth> {
            let bits = d.into_bits();
            debug_assert_eq!(bits.len(), Self::MaxDepth::to_usize());
            let mut ret = GenericArray::from_iter(std::iter::repeat(0u8));
            for (i, b) in bits.into_iter().enumerate() {
                ret[i] = if b { 1 } else { 0 };
            }
            ret
        }

        fn digest_of_traversal(t: &GenericArray<u8, Self::MaxDepth>) -> Option<Self::Digest> {
            let mut ret = [0u8; 32];
            for (i, bit) in t.into_iter().enumerate() {
                if *bit > 1 {
                    return None;
                }
                if *bit == 1 {
                    ret[i / 8] |= 1 << (i % 8);
                }
            }

            Some(crate::util::canonical::deserialize(&ret).unwrap())
        }

        fn hash_leaf(key: Self::Key, val: Self::Value) -> Self::Digest {
            CommitableHashNode::Leaf {
                key,
                val,
                _t: Default::default(),
            }
            .commit()
        }

        fn hash_key(key: Self::Key) -> Self::Digest {
            CommitableHashNode::KeyDigest {
                key,
                _t: Default::default(),
            }
            .commit()
        }

        fn hash_branch(children: &GenericArray<Self::Digest, typenum::U2>) -> Self::Digest {
            CommitableHashNode::Branch {
                l: children[0],
                r: children[1],
                _t: Default::default(),
            }
            .commit()
        }
    }
}

#[cfg(test)]
pub mod kv_treehash_tests {
    use super::committable_hash::*;
    use super::*;
    use quickcheck_macros::quickcheck;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TestEntry([u8; 32]);

    impl quickcheck::Arbitrary for TestEntry {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut ret = [0u8; 32];
            for item in &mut ret {
                *item = <_>::arbitrary(g);
            }
            Self(ret)
        }
    }

    impl CanonicalSerialize for TestEntry {
        fn serialized_size(&self) -> usize {
            32 * (0u8.serialized_size())
        }
        fn serialize<W: ark_serialize::Write>(
            &self,
            mut w: W,
        ) -> Result<(), ark_serialize::SerializationError> {
            for x in self.0 {
                x.serialize(&mut w)?;
            }
            Ok(())
        }
    }

    impl CanonicalDeserialize for TestEntry {
        fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
        where
            R: ark_serialize::Read,
        {
            let mut ret = [0u8; 32];
            for x in &mut ret {
                *x = u8::deserialize(&mut r)?;
            }
            Ok(Self(ret))
        }
    }

    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    struct TestEntryTag();

    impl CommitableHashTag for TestEntryTag {
        fn commitment_diversifier() -> &'static str {
            "CAP TestEntry"
        }
    }

    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    struct TestEntryTag2();

    impl CommitableHashTag for TestEntryTag2 {
        fn commitment_diversifier() -> &'static str {
            "CaP TestEntry"
        }
    }

    type TheTreeHash = CommitableHash<TestEntry, TestEntry, TestEntryTag>;
    type TheTreeHash2 = CommitableHash<TestEntry, TestEntry, TestEntryTag2>;

    #[test]
    fn treehash_basic_checks() {
        assert_ne!(
            crate::util::canonical::serialize(&<TheTreeHash as KVTreeHash>::empty_digest())
                .unwrap(),
            crate::util::canonical::serialize(&<TheTreeHash2 as KVTreeHash>::empty_digest())
                .unwrap()
        );
        assert_ne!(
            <TheTreeHash as KVTreeHash>::empty_digest().into_bits(),
            <TheTreeHash2 as KVTreeHash>::empty_digest().into_bits(),
        );
        treehash_tests::treehash_basic_checks::<TheTreeHash>()
    }

    #[quickcheck]
    fn treehash_check_traversal_of_digest(d: TestEntry) {
        let digest = crate::util::canonical::deserialize(&d.0).unwrap();
        treehash_tests::treehash_check_traversal_of_digest::<TheTreeHash>(digest);
    }

    #[quickcheck]
    fn treehash_check_digest_of_traversal(t: Vec<u8>) {
        let t: GenericArray<u8, typenum::U256> =
            GenericArray::from_iter(t.into_iter().chain(std::iter::repeat(0u8)));
        treehash_tests::treehash_check_digest_of_traversal::<TheTreeHash>(t);
    }

    #[quickcheck]
    fn treehash_check_leaf_key_domain_separation(k: TestEntry, v: TestEntry) {
        assert_ne!(
            <TheTreeHash as KVTreeHash>::hash_key(k).into_bits(),
            <TheTreeHash2 as KVTreeHash>::hash_key(k).into_bits()
        );
        assert_ne!(
            <TheTreeHash as KVTreeHash>::hash_leaf(k, v).into_bits(),
            <TheTreeHash2 as KVTreeHash>::hash_leaf(k, v).into_bits()
        );

        assert_ne!(
            crate::util::canonical::serialize(&<TheTreeHash as KVTreeHash>::hash_key(k)).unwrap(),
            crate::util::canonical::serialize(&<TheTreeHash2 as KVTreeHash>::hash_key(k)).unwrap()
        );
        assert_ne!(
            crate::util::canonical::serialize(&<TheTreeHash as KVTreeHash>::hash_leaf(k, v))
                .unwrap(),
            crate::util::canonical::serialize(&<TheTreeHash2 as KVTreeHash>::hash_leaf(k, v))
                .unwrap()
        );
        treehash_tests::treehash_check_leaf_key_domain_separation::<TheTreeHash>(k, v);
    }

    #[quickcheck]
    fn treehash_collision_sanity_checks1(
        k0: TestEntry,
        v0: TestEntry,
        k1: TestEntry,
        v1: TestEntry,
    ) {
        treehash_tests::treehash_collision_sanity_checks1::<TheTreeHash>(k0, v0, k1, v1);
    }

    #[quickcheck]
    fn treehash_collision_sanity_checks2(
        key: <TheTreeHash as KVTreeHash>::Key,
        val: <TheTreeHash as KVTreeHash>::Value,
        digests: Vec<TestEntry>,
    ) {
        let digests: GenericArray<
            <TheTreeHash as KVTreeHash>::Digest,
            <<TheTreeHash as KVTreeHash>::BranchArityMinus1 as AddLength<
                <TheTreeHash as KVTreeHash>::Digest,
                U1,
            >>::Output,
        > = GenericArray::from_iter(
            digests
                .into_iter()
                .map(|x| crate::util::canonical::deserialize(&x.0).unwrap())
                .chain(std::iter::repeat(
                    <TheTreeHash as KVTreeHash>::empty_digest(),
                )),
        );

        let digests2: GenericArray<
            <TheTreeHash2 as KVTreeHash>::Digest,
            <<TheTreeHash2 as KVTreeHash>::BranchArityMinus1 as AddLength<
                <TheTreeHash2 as KVTreeHash>::Digest,
                U1,
            >>::Output,
        > = GenericArray::from_iter(digests.iter().map(|x| {
            crate::util::canonical::deserialize(&crate::util::canonical::serialize(x).unwrap())
                .unwrap()
        }));

        assert_ne!(
            crate::util::canonical::serialize(&<TheTreeHash as KVTreeHash>::hash_branch(&digests))
                .unwrap(),
            crate::util::canonical::serialize(&<TheTreeHash2 as KVTreeHash>::hash_branch(
                &digests2
            ))
            .unwrap()
        );

        treehash_tests::treehash_collision_sanity_checks2::<TheTreeHash>(key, val, digests);
    }

    #[quickcheck]
    fn treehash_collision_sanity_checks3(digests0: Vec<TestEntry>, digests1: Vec<TestEntry>) {
        let digests0: GenericArray<
            <TheTreeHash as KVTreeHash>::Digest,
            <<TheTreeHash as KVTreeHash>::BranchArityMinus1 as AddLength<
                <TheTreeHash as KVTreeHash>::Digest,
                U1,
            >>::Output,
        > = GenericArray::from_iter(
            digests0
                .into_iter()
                .map(|x| crate::util::canonical::deserialize(&x.0).unwrap())
                .chain(std::iter::repeat(
                    <TheTreeHash as KVTreeHash>::empty_digest(),
                )),
        );
        let digests1: GenericArray<
            <TheTreeHash as KVTreeHash>::Digest,
            <<TheTreeHash as KVTreeHash>::BranchArityMinus1 as AddLength<
                <TheTreeHash as KVTreeHash>::Digest,
                U1,
            >>::Output,
        > = GenericArray::from_iter(
            digests1
                .into_iter()
                .map(|x| crate::util::canonical::deserialize(&x.0).unwrap())
                .chain(std::iter::repeat(
                    <TheTreeHash as KVTreeHash>::empty_digest(),
                )),
        );
        treehash_tests::treehash_collision_sanity_checks3::<TheTreeHash>(digests0, digests1);
    }
}
