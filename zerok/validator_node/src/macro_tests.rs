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
