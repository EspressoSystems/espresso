#![deny(warnings)]

pub mod canonical {
    use ark_serialize::*;
    pub use jf_utils::deserialize_canonical_bytes;
    pub use jf_utils::CanonicalBytes;

    pub fn serialize<T: CanonicalSerialize>(x: &T) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        x.serialize(&mut bytes)?;
        Ok(bytes)
    }

    pub fn serialize_unchecked<T: CanonicalSerialize>(
        x: &T,
    ) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        x.serialize_unchecked(&mut bytes)?;
        Ok(bytes)
    }

    pub fn deserialize<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, SerializationError> {
        T::deserialize(bytes)
    }

    pub fn deserialize_unchecked<T: CanonicalDeserialize>(
        bytes: &[u8],
    ) -> Result<T, SerializationError> {
        T::deserialize_unchecked(bytes)
    }
}
