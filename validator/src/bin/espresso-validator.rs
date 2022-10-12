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

#![deny(warnings)]

use clap::Parser;
use espresso_validator::{validator::*, *};
use futures::future::pending;
use jf_cap::keys::UserPubKey;

#[derive(Parser)]
#[command(
    name = "Espresso validator",
    about = "Runs a validator to participate in the consensus."
)]
struct Options {
    #[command(flatten)]
    validator_opt: ValidatorOpt,

    /// Public key which should own a faucet record in the genesis block.
    ///
    /// For each given public key, the ledger will be initialized with a record of 2^32 native
    /// tokens, owned by the public key.
    ///
    /// This option may be passed multiple times to initialize the ledger with multiple native
    /// token records.
    #[arg(long, env = "ESPRESSO_FAUCET_PUB_KEYS", value_delimiter = ',')]
    pub faucet_pub_key: Vec<UserPubKey>,
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let options = Options::parse();
    let genesis = genesis(options.validator_opt.chain_id, options.faucet_pub_key);
    let hotshot = init(genesis, options.validator_opt).await?;
    run_consensus(hotshot, pending::<()>()).await;
    Ok(())
}
