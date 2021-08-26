// fuzz target for randomized testing of walletlib
// run with `cargo fuzz run --release -s none multixfr_wallet`

#![no_main]
use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use zerok_lib::test_helpers::*;

#[derive(Debug)]
struct MultiXfrParams {
    // List of blocks containing (def,key1,key2,amount) transfer specs
    txs: Vec<Vec<(u8, u8, u8, u64)>>,
    nkeys: u8,
    ndefs: u8,
    // (def,key,amount)
    init_rec: (u8, u8, u64),
    init_recs: Vec<(u8, u8, u64)>,
}

impl<'a> Arbitrary<'a> for MultiXfrParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let max_amt = 1000u64;
        let txns_per_block = std::cmp::max(u.arbitrary_len::<(u8, u8, u8, u64)>()?, 2);
        let num_blocks = std::cmp::max(u.arbitrary_len::<Vec<(u8, u8, u8, u64)>>()?, 2);
        let num_txns = txns_per_block * num_blocks;
        // fewer users than txns so we get multiple txns with same key
        let nkeys: u8 = u.int_in_range(2..=num_txns / 2 + 2)? as u8;
        // fewer defs than txns so we get multiple txns with same def
        let ndefs: u8 = u.int_in_range(1..=num_txns / 2 + 1)? as u8;

        let blocks: Vec<Vec<(u8, u8, u8, u64)>> = (0..num_blocks)
            .map(|_| {
                let num_txns = u.int_in_range(1..=txns_per_block)?;
                (0..num_txns)
                    .map(|_| {
                        Ok((
                            // range is inclusive because def 0 is the native asset, and other asset
                            // defs are 1-indexed
                            u.int_in_range(0..=ndefs)?,
                            u.int_in_range(0..=nkeys - 1)?,
                            u.int_in_range(0..=nkeys - 1)?,
                            // Transaction amounts are smaller than record amounts because we don't
                            // want to burn a whole record in one transaction.
                            u.int_in_range(1..=max_amt / 2)?,
                        ))
                    })
                    .collect()
            })
            .collect::<Result<Vec<Vec<(u8, u8, u8, u64)>>>>()?;

        let init_rec = (
            u.int_in_range(0..=ndefs)?,
            u.int_in_range(0..=nkeys - 1)?,
            u.int_in_range(1..=max_amt)?,
        );
        // enough records to give everyone 1 of each type, on average
        let num_recs = nkeys * ndefs;
        let init_recs = (0..num_recs)
            .map(|_| {
                Ok((
                    u.int_in_range(0..=ndefs)?,
                    u.int_in_range(0..=nkeys - 1)?,
                    u.int_in_range(1..=max_amt)?,
                ))
            })
            .collect::<Result<Vec<(u8, u8, u64)>>>()?;

        Ok(MultiXfrParams {
            txs: blocks,
            nkeys,
            ndefs,
            init_rec,
            init_recs,
        })
    }
}

fuzz_target!(|params: MultiXfrParams| {
    let MultiXfrParams {
        txs,
        nkeys,
        ndefs,
        init_rec,
        init_recs,
    } = params;
    test_multixfr_wallet(txs, nkeys, ndefs, init_rec, init_recs)
});
