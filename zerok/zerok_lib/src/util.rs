#![deny(warnings)]
use bitvec::vec::BitVec;
use std::convert::TryFrom;

pub fn byte_array_to_bits<N: generic_array::ArrayLength<u8>>(
    arr: generic_array::GenericArray<u8, N>,
) -> BitVec<bitvec::order::Lsb0, u8> {
    BitVec::try_from(arr.into_iter().collect::<Vec<_>>()).unwrap()
}

pub mod canonical {
    use ark_serialize::*;
    pub use jf_utils::deserialize_canonical_bytes;
    pub use jf_utils::CanonicalBytes;

    pub fn serialize<T: CanonicalSerialize>(x: &T) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        x.serialize(&mut bytes)?;
        Ok(bytes)
    }

    pub fn deserialize<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, SerializationError> {
        T::deserialize(bytes)
    }
}

pub mod arbitrary_wrappers {
    use arbitrary::{Arbitrary, Unstructured};
    use jf_txn::keys::{UserAddress, UserKeyPair};
    use jf_txn::structs::{FreezeFlag, Nullifier, ReceiverMemo, RecordOpening};
    use jf_txn::KeyPair;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    pub struct ArbitraryNullifier(Nullifier);

    impl From<ArbitraryNullifier> for Nullifier {
        fn from(n: ArbitraryNullifier) -> Self {
            n.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryNullifier {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut rng = ChaChaRng::from_seed(u.arbitrary()?);
            Ok(Self(Nullifier::random_for_test(&mut rng)))
        }
    }

    pub struct ArbitraryRecordOpening(RecordOpening);

    impl From<ArbitraryRecordOpening> for RecordOpening {
        fn from(ro: ArbitraryRecordOpening) -> Self {
            ro.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryRecordOpening {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut rng = ChaChaRng::from_seed(u.arbitrary()?);
            Ok(Self(
                RecordOpening::dummy(
                    &mut rng,
                    *u.choose(&[FreezeFlag::Frozen, FreezeFlag::Unfrozen])?,
                )
                .0,
            ))
        }
    }

    pub struct ArbitraryReceiverMemo(ReceiverMemo);

    impl From<ArbitraryReceiverMemo> for ReceiverMemo {
        fn from(m: ArbitraryReceiverMemo) -> Self {
            m.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryReceiverMemo {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut rng = ChaChaRng::from_seed(u.arbitrary()?);
            Ok(Self(
                ReceiverMemo::from_ro(
                    &mut rng,
                    &u.arbitrary::<ArbitraryRecordOpening>()?.into(),
                    &[],
                )
                .unwrap(),
            ))
        }
    }

    pub struct ArbitraryUserKeyPair(UserKeyPair);

    impl From<ArbitraryUserKeyPair> for UserKeyPair {
        fn from(k: ArbitraryUserKeyPair) -> Self {
            k.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryUserKeyPair {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut rng = ChaChaRng::from_seed(u.arbitrary()?);
            Ok(Self(UserKeyPair::generate(&mut rng)))
        }
    }

    pub struct ArbitraryUserAddress(UserAddress);

    impl From<ArbitraryUserAddress> for UserAddress {
        fn from(a: ArbitraryUserAddress) -> Self {
            a.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryUserAddress {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self(
                UserKeyPair::from(u.arbitrary::<ArbitraryUserKeyPair>()?).address(),
            ))
        }
    }

    pub struct ArbitraryKeyPair(KeyPair);

    impl From<ArbitraryKeyPair> for KeyPair {
        fn from(k: ArbitraryKeyPair) -> Self {
            k.0
        }
    }

    impl<'a> Arbitrary<'a> for ArbitraryKeyPair {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut rng = ChaChaRng::from_seed(u.arbitrary()?);
            Ok(Self(KeyPair::generate(&mut rng)))
        }
    }
}
