#![deny(warnings)]
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

pub mod committee;
pub mod full_persistence;
pub mod genesis;
pub mod kv_merkle_tree;
pub mod ledger;
pub mod lw_persistence;
pub mod merkle_tree;
pub mod reward;
pub mod set_merkle_tree;
mod stake_table;
pub mod state;
pub mod testing;
pub mod tree_hash;
pub mod universal_params;

mod util;

extern crate espresso_macros;

pub type PubKey = hotshot::types::ed25519::Ed25519Pub;
pub type PrivKey = hotshot::types::ed25519::Ed25519Priv;
