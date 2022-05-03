extern crate zerok_client;
use zerok_client::cli_client::{cli_test, CliClient};

fn create_wallet(t: &mut CliClient, wallet: usize) -> Result<&mut CliClient, String> {
    let key_path = t.wallet_key_path(wallet)?;
    let key_path = key_path.as_os_str().to_str().ok_or_else(|| {
        format!(
            "failed to convert key path {:?} for wallet {} to string",
            key_path, wallet
        )
    })?;
    t.open(wallet)?
        .output("Your mnemonic phrase will be:")?
        .output("^(?P<mnemonic>[a-zA-Z ]+)")?
        .output("1\\) Accept phrase and create wallet")?
        .output("2\\) Generate a new phrase")?
        .output("3\\) Manually enter a mnemonic")?
        .command(wallet, "1")?
        .output("Create password:")?
        .command(wallet, "test_password")?
        .output("Retype password:")?
        // Try typing the incorrect password, to check the error handling
        .command(wallet, "wrong_password")?
        .output("Passwords do not match.")?
        .output("Create password:")?
        .command(wallet, "test_password")?
        .output("Retype password:")?
        .command(wallet, "test_password")?
        .output("connecting...")?
        .command(wallet, format!("load_key sending {}", key_path))?
        .output(format!("(?P<default_addr{}>ADDR~.*)", wallet))
}

fn wait_for_native_balance(
    t: &mut CliClient,
    wallet: usize,
    account: &str,
) -> Result<usize, String> {
    loop {
        t.command(wallet, "balance 0")?
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
        // Get the balance of both wallets.
        .command(0, "balance 0")?
        .output(format!("Total {}", balance))?
        .command(1, "balance 0")?
        .output("Total 0")?
        // Transfer some native coins from the primary wallet to the secondary.
        .command(0, "transfer 0 $default_addr1 500 1")?
        .output("(?P<txn>TXN~.*)")?
        // Wait for the transaction to complete in both wallets (just because one wallet has
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
        .command(1, "transfer 0 $default_addr0 200 2")?
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
        .command(0, "mint 1 $default_addr0 $default_addr1 100 1")?
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
        // Do it again, this time specifiying audit and freeze keys
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
        .command(0, "mint $asset2 $default_addr0 $default_addr1 200 1")?
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
        .output("connecting...")?;

    // Check that the wallet is functional.
    cli_basic_info(t)
}

#[test]
fn cli_integration_tests() {
    cli_test(|t| {
        create_wallet(t, 0)?;
        create_wallet(t, 1)?;

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
        let key_path = t.wallet_key_path(0)?;
        let key_path = key_path.as_os_str().to_str().ok_or_else(|| {
            format!(
                "failed to convert key path {:?} for wallet {} to string",
                key_path, 0
            )
        })?;
        t.open(0)?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>(?:[a-z]+ ){11}(?:[a-z]+))$")?
            .output("1\\) Accept phrase and create wallet")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            // Ask for a new mnemonic just so we hit every code path
            .command(0, "2")?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>(?:[a-z]+ ){11}(?:[a-z]+))$")?
            .output("1\\) Accept phrase and create wallet")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            .command(0, "1")?
            .output("Create password")?
            .command(0, "password")?
            .output("Retype password")?
            .command(0, "password")?
            .output("connecting...")?
            .command(0, format!("load_key sending {}", key_path))?
            .output("(?P<default_addr0>ADDR~.*)")?;
        wait_for_starting_balance(t)?;
        t
            // Create a determinstic key
            .command(0, "gen_key sending")?
            .output("(?P<addr>ADDR~.*)")?
            // Give the key some assets
            .command(0, "transfer 0 $addr 100 1 wait=true")?
            .command(0, "balance 0")?
            .output("$addr 100")?
            // Create a new wallet with the same mnemonic and check that we get the balance.
            .open(1)?
            .output("3\\) Manually enter a mnemonic")?
            .command(1, "3")?
            .output("Enter mnemonic phrase")?
            .command(1, "$mnemonic")?
            .output("Create password")?
            .command(1, "password")?
            .output("Retype password")?
            .command(1, "password")?
            .output("connecting...")?
            .command(1, "gen_key spend scan_from=0")?;
        let balance = wait_for_native_balance(t, 0, "addr")?;
        if balance != 100 {
            return Err(format!("incorrect balance (expected 100, got {})", balance));
        }

        Ok(())
    })
}
