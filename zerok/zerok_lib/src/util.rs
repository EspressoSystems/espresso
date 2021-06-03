#![deny(warnings)]
use bitvec::vec::BitVec;
use std::convert::TryFrom;

pub fn byte_array_to_bits<N: generic_array::ArrayLength<u8>>(
    arr: generic_array::GenericArray<u8, N>,
) -> BitVec<bitvec::order::Lsb0, u8> {
    BitVec::try_from(arr.into_iter().collect::<Vec<_>>()).unwrap()
}
