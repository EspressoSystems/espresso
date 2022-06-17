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

extern crate zerok_client;
use zerok_client::cli_client::{cli_test, CliClient};

fn create_keystore(t: &mut CliClient, keystore: usize) -> Result<&mut CliClient, String> {
    let key_path = t.keystore_key_path(keystore)?;
    let key_path = key_path.as_os_str().to_str().ok_or_else(|| {
        format!(
            "failed to convert key path {:?} for keystore {} to string",
            key_path, keystore
        )
    })?;
    t.open(keystore)?
        .output("Your mnemonic phrase will be:")?
        .output("^(?P<mnemonic>[a-zA-Z ]+)")?
        .output("1\\) Accept phrase and create keystore")?
        .output("2\\) Generate a new phrase")?
        .output("3\\) Manually enter a mnemonic")?
        .command(keystore, "1")?
        .output("Create password:")?
        .command(keystore, "test_password")?
        .output("Retype password:")?
        // Try typing the incorrect password, to check the error handling
        .command(keystore, "wrong_password")?
        .output("Passwords do not match.")?
        .output("Create password:")?
        .command(keystore, "test_password")?
        .output("Retype password:")?
        .command(keystore, "test_password")?
        .output("Type 'help' for a list of commands.")?
        .command(keystore, format!("load_key sending {}", key_path))?
        .output(format!("(?P<default_addr{}>ADDR~.*)", keystore))?
        .output(format!("(?P<default_pubkey{}>USERPUBKEY~.*)", keystore))
}

fn wait_for_native_balance(
    t: &mut CliClient,
    keystore: usize,
    account: &str,
) -> Result<usize, String> {
    loop {
        t.command(keystore, "balance 0")?
            .output(format!("${} (?P<balance>\\d+)", account))?;
        let balance = t.var("balance").unwrap().parse().unwrap();
        if balance > 0 {
            break Ok(balance);
        }
    }
}

fn wait_for_starting_balance(t: &mut CliClient) -> Result<usize, String> {
    wait_for_native_balance(t, 0, "default_addr0")
}

fn cli_basic_info(t: &mut CliClient) -> Result<(), String> {
    t
        // `info`
        .command(0, "info")?
        .output("Addresses:")?
        .output("(?P<addr1>ADDR~.*)")?
        .output("Sending keys:")?
        .output("(?P<pubkey1>USERPUBKEY~.*)")?
        // `address`
        .command(0, "address")?
        .output("$addr1")?
        // `assets`
        .command(0, "assets")?
        .output("0. (?P<native>ASSET_CODE~.*) \\(native\\)")?;

    // add keys and check that they are reported
    t.command(0, "gen_key view")?
        .output("(?P<audkey>AUDPUBKEY~.*)")?
        .command(0, "gen_key freeze")?
        .output("(?P<freezekey>FREEZEPUBKEY~.*)")?
        .command(0, "gen_key send")?
        .output("(?P<addr2>ADDR~.*)")?
        .command(0, "info")?
        .output("Addresses:")?
        .output("$addr1")?
        .output("$addr2")?
        .command(0, "keys")?
        .output("Sending keys:")?
        .output("$pubkey1")?
        .output("USERPUBKEY~.*")?
        .output("Viewing keys:")?
        .output("$audkey")?
        .output("Freezing keys:")?
        .output("$freezekey")?;

    // native asset info, specified two ways
    for command in &["asset 0", "asset $native"] {
        t.command(0, command)?
            .output("Native $native")?
            .output("Not viewable")?
            .output("Not freezeable")?
            .output("Not mintable")?;
    }

    Ok(())
}

fn cli_transfer_native(t: &mut CliClient) -> Result<(), String> {
    let balance = wait_for_starting_balance(t)?;
    t
        // Get the balance of both keystores.
        .command(0, "balance 0")?
        .output(format!("Total {}", balance))?
        .command(1, "balance 0")?
        .output("Total 0")?
        // Transfer some native coins from the primary keystore to the secondary.
        .command(0, "transfer 0 $default_pubkey1 500 1")?
        .output("(?P<txn>TXN~.*)")?
        // Wait for the transaction to complete in both keystores (just because one keystore has
        // received and processed the completed transaction doesn't mean the other has).
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        .command(0, "balance 0")?
        .output(format!("Total {}", balance - 501))?
        .command(1, "balance 0")?
        .output("Total 500")?
        // Transfer part of the money back
        .command(1, "transfer 0 $default_pubkey0 200 2")?
        .output("(?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        .command(1, "balance 0")?
        .output("Total 298")?
        .command(0, "balance 0")?
        .output(format!("Total {}", balance - 301))?;
    Ok(())
}

fn cli_mint_and_transfer(t: &mut CliClient) -> Result<(), String> {
    wait_for_starting_balance(t)?;
    t
        // Define a new asset and mint some for the receiver.
        .command(0, "create_asset asset1")?
        .output("(?P<asset1>ASSET_CODE~.*)")?
        .command(0, "asset 1")?
        .output("asset1 $asset1")?
        .output("Not viewable")?
        .output("Not freezeable")?
        .output("Minter: me")?
        .command(0, "mint 1 $default_pubkey1 100 1")?
        .output("(?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        // Check on the receiving end that
        //  (1) we have learned about the new asset after receiving it
        //  (2) we have a balance of it
        .command(1, "asset 1")?
        .output("Asset $asset1")? // Receiver doesn't know the description "asset1"
        .output("Not viewable")?
        .output("Not freezeable")?
        .output("Minter: unknown")? // Receiver doesn't know who minted the asset for them
        .command(1, "balance 1")?
        .output("$default_addr1 100")?
        // Do it again, this time specifiying view and freeze keys
        .command(0, "gen_key viewing")?
        .output("(?P<audkey0>AUDPUBKEY~.*)")?
        .command(1, "gen_key freezing")?
        .output("(?P<freezekey1>FREEZEPUBKEY~.*)")?
        .command(
            0,
            "create_asset asset2 viewing_key=$audkey0 freezing_key=$freezekey1",
        )?
        .output("(?P<asset2>ASSET_CODE~.*)")?
        // Once there is more than 1 custom asset, we have to refer to it by code, not index,
        // because the order of custom assets is non-deterministic. I should probably fix that.
        .command(0, "asset $asset2")?
        .output("asset2 $asset2")?
        .output("Viewer: me")?
        .output("Freezer: $freezekey1")?
        .output("Minter: me")?
        .command(0, "mint $asset2 $default_pubkey1 200 1")?
        .output("(?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        // Check on the receiving end
        .command(1, "asset $asset2")?
        .output("Asset $asset2")?
        .output("Viewer: $audkey0")?
        .output("Freezer: me")?
        .output("Minter: unknown")?
        .command(1, "balance $asset2")?
        .output("Total 200")?;
    Ok(())
}

fn cli_login(t: &mut CliClient) -> Result<(), String> {
    t.close(0)?
        .open(0)?
        .output("Forgot your password\\? Want to change it\\? \\[y/n\\]")?
        .command(0, "n")?
        .output("Enter password:")?
        // Enter the wrong password to check error handling
        .command(0, "wrong_password")?
        .output("Sorry, that's incorrect")?
        .output("Forgot your password\\? Want to change it\\? \\[y/n\\]")?
        .command(0, "n")?
        .output("Enter password:")?
        .command(0, "test_password")?
        .output("Type 'help' for a list of commands.")?;

    // Check that the keystore is functional.
    cli_basic_info(t)
}

#[test]
fn cli_integration_tests() {
    cli_test(|t| {
        create_keystore(t, 0)?;
        create_keystore(t, 1)?;

        cli_basic_info(t)?;
        cli_transfer_native(t)?;
        cli_mint_and_transfer(t)?;
        cli_login(t)?;

        Ok(())
    });
}

#[test]
fn recover_from_mnemonic() {
    cli_test(|t| {
        let key_path = t.keystore_key_path(0)?;
        let key_path = key_path.as_os_str().to_str().ok_or_else(|| {
            format!(
                "failed to convert key path {:?} for keystore {} to string",
                key_path, 0
            )
        })?;
        t.open(0)?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>(?:[a-z]+ ){11}(?:[a-z]+))$")?
            .output("1\\) Accept phrase and create keystore")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            // Ask for a new mnemonic just so we hit every code path
            .command(0, "2")?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>(?:[a-z]+ ){11}(?:[a-z]+))$")?
            .output("1\\) Accept phrase and create keystore")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            .command(0, "1")?
            .output("Create password")?
            .command(0, "password")?
            .output("Retype password")?
            .command(0, "password")?
            .output("Type 'help' for a list of commands.")?
            .command(0, format!("load_key sending {}", key_path))?
            .output("(?P<default_addr0>ADDR~.*)")?
            .output("(?P<default_pubkey0>USERPUBKEY~.*)")?;
        wait_for_starting_balance(t)?;
        t
            // Create a determinstic key
            .command(0, "gen_key sending")?
            .output("(?P<pubkey>USERPUBKEY~.*)")?
            .output("(?P<addr>ADDR~.*)")?
            // Give the key some assets
            .command(0, "transfer 0 $pubkey 100 1 wait=true")?
            .command(0, "balance 0")?
            .output("$addr 100")?
            // Create a new keystore with the same mnemonic and check that we get the balance.
            .open(1)?
            .output("3\\) Manually enter a mnemonic")?
            .command(1, "3")?
            .output("Enter mnemonic phrase")?
            .command(1, "$mnemonic")?
            .output("Create password")?
            .command(1, "password")?
            .output("Retype password")?
            .command(1, "password")?
            .output("Type 'help' for a list of commands.")?
            .command(1, "gen_key spend scan_from=0")?;
        let balance = wait_for_native_balance(t, 0, "addr")?;
        if balance != 100 {
            return Err(format!("incorrect balance (expected 100, got {})", balance));
        }

        Ok(())
    })
}
