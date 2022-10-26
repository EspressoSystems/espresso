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

use crate::{
    state::{ArcSer, ChainVariables},
    universal_params::MERKLE_HEIGHT,
    util::canonical,
};
use arbitrary::{Arbitrary, Unstructured};
use arbitrary_wrappers::ArbitraryRecordOpening;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use async_std::sync::Arc;
use commit::{Commitment, Committable, RawCommitmentBuilder};
use espresso_macros::ser_test;
use jf_cap::{
    structs::{RecordCommitment, RecordOpening},
    MerkleTree,
};
use serde::{Deserialize, Serialize};

/// Genesis transaction
///
/// A genesis transaction is used to initialize the Espresso ledger, setting per-chain variables and
/// populating the ledger with some initial records. It is valid in exactly one situation: when it
/// is the only transaction in the genesis block, block number 0. In this case, it has the effect of
/// setting the chain variables to `chain` and seeding the record set with commitments to
/// `faucet_records`.
#[ser_test(arbitrary)]
#[derive(
    Clone,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Hash,
    PartialEq,
    Eq,
)]
pub struct GenesisNote {
    pub chain: ChainVariables,
    pub faucet_records: ArcSer<Vec<RecordOpening>>,
}

impl Committable for GenesisNote {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("GenesisNote")
            .field("chain", self.chain.commit())
            .var_size_bytes(&canonical::serialize(&self.faucet_records).unwrap())
            .finalize()
    }
}

impl<'a> Arbitrary<'a> for GenesisNote {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            chain: u.arbitrary()?,
            faucet_records: ArcSer::new(
                u.arbitrary_iter::<ArbitraryRecordOpening>()?
                    .map(|ro| Ok(ro?.into()))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

impl GenesisNote {
    pub fn new(chain: ChainVariables, faucet_records: Arc<Vec<RecordOpening>>) -> Self {
        Self {
            chain,
            faucet_records: faucet_records.into(),
        }
    }

    pub fn output_len(&self) -> usize {
        self.faucet_records.len()
    }

    pub fn output_commitments(&self) -> Vec<RecordCommitment> {
        self.faucet_records
            .iter()
            .map(RecordCommitment::from)
            .collect()
    }

    pub fn output_openings(&self) -> Vec<RecordOpening> {
        (**self.faucet_records).clone()
    }

    pub fn record_merkle_tree(&self) -> MerkleTree {
        let mut records = MerkleTree::new(MERKLE_HEIGHT).unwrap();
        for comm in self.output_commitments() {
            records.push(comm.to_field_element());
        }
        records
    }
}
