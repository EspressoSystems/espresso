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
