// Tests for zerok-macros, since tests for proc-macros must be in a different crate from where the
// macros are defined.
#[cfg(test)]
mod tests {
    use crate::ser_test;
    use ark_serialize::*;
    use serde::{Deserialize, Serialize};

    #[ser_test(types(u64, "Vec<u64>"), types(u32, bool))]
    #[derive(
        Debug, Default, PartialEq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
    )]
    struct Generic<
        T1: CanonicalSerialize + CanonicalDeserialize,
        T2: CanonicalSerialize + CanonicalDeserialize,
    > {
        t1: T1,
        t2: T2,
    }
}
