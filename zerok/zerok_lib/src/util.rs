#![deny(warnings)]
use bitvec::vec::BitVec;
use std::convert::TryFrom;

pub fn byte_array_to_bits<const N: usize>(arr: [u8; N]) -> BitVec<bitvec::order::Lsb0, u8> {
    BitVec::try_from(arr.to_vec()).unwrap()
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

pub mod commit {
    use super::byte_array_to_bits;
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
    };
    use bitvec::vec::BitVec;
    use core::marker::PhantomData;
    use generic_array::{ArrayLength, GenericArray};
    use sha3::digest::Digest;
    use sha3::Sha3_256;
    use std::convert::TryInto;

    type Array = [u8; 32];

    const INVALID_UTF8: [u8; 2] = [0xC0u8, 0x7Fu8];

    #[cfg(test)]
    mod tests {
        use super::INVALID_UTF8;
        use quickcheck::quickcheck;

        #[quickcheck]
        fn invalid_utf8_is_invalid(pref: Vec<u8>, suff: Vec<u8>) {
            let s = pref
                .into_iter()
                .chain(INVALID_UTF8.iter().cloned())
                .chain(suff.into_iter())
                .collect::<Vec<_>>();
            assert!(std::str::from_utf8(&s).is_err());
        }

        #[quickcheck]
        fn invalid_utf8_is_invalid_strs_only(pref: String, suff: String) {
            let s = pref
                .as_bytes()
                .iter()
                .chain(INVALID_UTF8.iter())
                .chain(suff.as_bytes().iter())
                .cloned()
                .collect::<Vec<_>>();
            assert!(std::str::from_utf8(&s).is_err());
        }
    }

    pub trait Committable {
        fn commit(&self) -> Commitment<Self>;
    }

    pub struct Commitment<T: ?Sized + Committable>(Array, PhantomData<T>);

    impl<T: ?Sized + Committable> AsRef<[u8]> for Commitment<T> {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    // we need custom impls because `T` doesn't actually need to satisfy
    // these traits
    impl<T: ?Sized + Committable> core::fmt::Debug for Commitment<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            f.write_str("Commitment<")?;
            f.write_str(std::any::type_name::<T>())?;
            f.write_str(">(")?;
            f.write_str(&hex::encode(&self.0))?;
            f.write_str(")")
        }
    }

    impl<T: ?Sized + Committable> Clone for Commitment<T> {
        fn clone(&self) -> Self {
            Self(self.0, self.1)
        }
    }
    impl<T: ?Sized + Committable> Copy for Commitment<T> {}
    impl<T: ?Sized + Committable> PartialEq for Commitment<T> {
        fn eq(&self, rhs: &Self) -> bool {
            self.0 == rhs.0
        }
    }
    impl<T: ?Sized + Committable> Eq for Commitment<T> {}
    impl<T: ?Sized + Committable> core::hash::Hash for Commitment<T> {
        fn hash<H>(&self, h: &mut H)
        where
            H: std::hash::Hasher,
        {
            self.0.hash(h)
        }
    }

    impl<T: ?Sized + Committable> Commitment<T> {
        pub fn into_bits(self) -> BitVec<bitvec::order::Lsb0, u8> {
            byte_array_to_bits(self.0)
        }
    }

    impl<T: ?Sized + Committable> CanonicalSerialize for Commitment<T> {
        fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
            w.write_all(&self.0).map_err(SerializationError::from)
        }

        fn serialized_size(&self) -> usize {
            self.0.len()
        }
    }

    impl<T: ?Sized + Committable> CanonicalDeserialize for Commitment<T> {
        fn deserialize<R: Read>(mut r: R) -> Result<Self, SerializationError> {
            let mut buf = [0u8; 32];
            r.read_exact(&mut buf)?;
            Ok(Commitment(buf, Default::default()))
        }
    }

    impl<T: ?Sized + Committable> From<Commitment<T>> for [u8; 32] {
        fn from(v: Commitment<T>) -> Self {
            v.0
        }
    }

    pub struct RawCommitmentBuilder<T: Committable> {
        hasher: Sha3_256,
        _marker: PhantomData<T>,
    }

    impl<T: Committable> RawCommitmentBuilder<T> {
        pub fn new(tag: &str) -> Self {
            Self {
                hasher: Default::default(),
                _marker: Default::default(),
            }
            .constant_str(tag)
        }

        pub fn constant_str(mut self, s: &str) -> Self {
            self.hasher.update(s.as_bytes());
            self.fixed_size_bytes(&INVALID_UTF8)
        }

        pub fn fixed_size_bytes<const N: usize>(mut self, f: &[u8; N]) -> Self {
            self.hasher.update(f);
            self
        }

        #[allow(dead_code)]
        pub fn generic_byte_array<N: ArrayLength<u8>>(mut self, f: &GenericArray<u8, N>) -> Self {
            self.hasher.update(f);
            self
        }

        pub fn u64(self, val: u64) -> Self {
            self.fixed_size_bytes(&val.to_le_bytes())
        }

        pub fn var_size_bytes(self, f: &[u8]) -> Self {
            let mut ret = self.u64(f.len() as u64);
            ret.hasher.update(f);
            ret
        }

        #[allow(dead_code)]
        pub fn fixed_size_field<const N: usize>(self, name: &str, val: &[u8; N]) -> Self {
            self.constant_str(name).fixed_size_bytes(val)
        }

        pub fn var_size_field(self, name: &str, val: &[u8]) -> Self {
            self.constant_str(name).var_size_bytes(val)
        }

        pub fn field<S: Committable>(self, name: &str, val: Commitment<S>) -> Self {
            self.constant_str(name).fixed_size_bytes(&val.0)
        }

        pub fn u64_field(self, name: &str, val: u64) -> Self {
            self.constant_str(name).u64(val)
        }

        pub fn array_field<S: Committable>(self, name: &str, val: &[Commitment<S>]) -> Self {
            let mut ret = self.constant_str(name).u64(val.len() as u64);
            for v in val.iter() {
                ret = ret.fixed_size_bytes(&v.0);
            }
            ret
        }

        pub fn finalize(self) -> Commitment<T> {
            let ret = self.hasher.finalize();
            Commitment(ret.try_into().unwrap(), Default::default())
        }
    }
}
