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
    use serde::{Deserialize, Serialize};

    /// A helper for converting CanonicalSerde bytes to standard Serde bytes. use this struct as
    /// intermediate target instead of directly deriving serde::Serialize/Deserialize to avoid
    /// implementation of Visitors.
    #[derive(Serialize, Deserialize)]
    pub struct CanonicalBytes(pub Vec<u8>);

    impl<T: ark_serialize::CanonicalSerialize> From<T> for CanonicalBytes {
        fn from(obj: T) -> CanonicalBytes {
            let mut bytes = Vec::new();
            obj.serialize(&mut bytes)
                .expect("fail to serialize to canonical bytes");
            CanonicalBytes(bytes)
        }
    }

    #[macro_export]
    macro_rules! deserialize_canonical_bytes {
        ($t:ident) => {
            impl From<CanonicalBytes> for $t {
                fn from(bytes: CanonicalBytes) -> Self {
                    ark_serialize::CanonicalDeserialize::deserialize(bytes.0.as_slice())
                        .expect("fail to deserialize canonical bytes")
                }
            }
        };
        ($t:ident < $gen:tt : $tr:tt >) => {
            impl<$gen: $tr> From<CanonicalBytes> for $t<$gen> {
                fn from(bytes: CanonicalBytes) -> Self {
                    ark_serialize::CanonicalDeserialize::deserialize(bytes.0.as_slice())
                        .expect("fail to deserialize canonical bytes")
                }
            }
        };
        ($t:ident < $lt:lifetime, $gen:tt : $tr:tt >) => {
            impl<$lt, $gen: $tr> From<CanonicalBytes> for $t<$lt, $gen> {
                fn from(bytes: CanonicalBytes) -> Self {
                    ark_serialize::CanonicalDeserialize::deserialize(bytes.0.as_slice())
                        .expect("fail to deserialize canonical bytes")
                }
            }
        };
    }

    pub fn serialize<T: CanonicalSerialize>(x: &T) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        x.serialize(&mut bytes)?;
        Ok(bytes)
    }

    pub fn deserialize<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, SerializationError> {
        T::deserialize(bytes)
    }
}
