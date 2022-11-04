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
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    let node_opt = NodeOpt::parse();
    let genesis = genesis(&node_opt);
    let hotshot = init(ChaChaRng::from_entropy(), genesis, node_opt).await?;
    run_consensus(hotshot, pending::<()>()).await;
    Ok(())
}
