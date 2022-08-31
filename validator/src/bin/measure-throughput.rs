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

use async_std::task::sleep;
use clap::Parser;
use human_bytes::human_bytes;
use net::client::response_body;
use std::fmt::{self, Display, Formatter};
use std::ops::Sub;
use std::time::{Duration, Instant};
use surf::Url;
use tracing::{error, info};
use validator_node::node::LedgerSummary;

/// Measure system throughput over time by polling a query service.
#[derive(Parser)]
struct Options {
    /// The frequency at which to poll current throughput.
    #[clap(short, long, default_value = "60s", parse(try_from_str = espresso_validator::parse_duration))]
    frequency: Duration,

    /// The total duration over which to measure throughput.
    ///
    /// If not provided, runs until killed.
    #[clap(short, long, parse(try_from_str = espresso_validator::parse_duration))]
    total: Option<Duration>,

    /// The query service to poll for ledger state.
    #[clap(short = 'q', long, env = "ESPRESSO_ESQS_URL")]
    esqs_url: Url,
}

#[derive(Clone, Debug)]
struct Measurement {
    duration: Duration,
    transactions: usize,
    bytes: usize,
    blocks: usize,
}

impl Display for Measurement {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = self.duration.as_secs() as f32;
        write!(
            f,
            "{:.2} tx/s, {}/s, {:.2} tx/block, {}/tx",
            self.transactions as f32 / s,
            human_bytes(self.bytes as f32 / s),
            self.transactions as f32 / self.blocks as f32,
            human_bytes(self.bytes as f32 / self.transactions as f32),
        )
    }
}

#[derive(Clone, Debug)]
struct Snapshot {
    t: Instant,
    state: LedgerSummary,
}

impl Snapshot {
    async fn new(esqs_url: &Url) -> Result<Self, surf::Error> {
        let mut res = surf::get(esqs_url.join("/getinfo").unwrap()).send().await?;
        let state = response_body(&mut res).await?;
        Ok(Self {
            t: Instant::now(),
            state,
        })
    }
}

impl Sub for &Snapshot {
    type Output = Measurement;

    fn sub(self, other: &Snapshot) -> Measurement {
        Measurement {
            duration: self.t - other.t,
            transactions: self.state.num_txns - other.state.num_txns,
            bytes: self.state.total_size - other.state.total_size,
            blocks: self.state.num_blocks - other.state.num_blocks,
        }
    }
}

#[async_std::main]
async fn main() -> surf::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let opt = Options::from_args();
    let frequency = opt.frequency;
    let total = opt.total.map(Duration::from);

    let initial = Snapshot::new(&opt.esqs_url).await?;
    let mut previous = initial.clone();

    loop {
        if let Some(total) = total {
            if Instant::now() - initial.t > total {
                break;
            }
        }

        sleep(frequency).await;
        match Snapshot::new(&opt.esqs_url).await {
            Ok(new) => {
                info!("Current {} | Total {}", &new - &previous, &new - &initial);
                previous = new;
            }
            Err(err) => {
                error!("Failed to fetch ledger state: {}", err);
            }
        }
    }

    Ok(())
}
