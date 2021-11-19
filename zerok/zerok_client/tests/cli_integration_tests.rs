extern crate zerok_client;
use zerok_client::cli_client::{cli_test, CliClient};

fn create_wallet(t: &mut CliClient, wallet: usize) -> Result<&mut CliClient, String> {
    t.open(wallet)?
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
        .output("connecting...")
}

fn wait_for_starting_balance(t: &mut CliClient) -> Result<usize, String> {
    loop {
        t.command(0, "balance 0")?.output("(?P<balance>\\d+)")?;
        let balance = t.var("balance").unwrap().parse().unwrap();
        if balance > 0 {
            break Ok(balance);
        }
    }
}

fn cli_basic_info(t: &mut CliClient) -> Result<(), String> {
    t
        // `info`
        .command(0, "info")?
        .output("Address: (?P<addr>ADDR~.*)")?
        .output("Public key: (?P<pubkey>USERPUBKEY~.*)")?
        .output("Audit key: (?P<audkey>AUDPUBKEY~.*)")?
        .output("Freeze key: (?P<freezekey>FREEZEPUBKEY~.*)")?
        // `address`
        .command(0, "address")?
        .output("$addr")?
        // `assets`
        .command(0, "assets")?
        .output("0. (?P<native>ASSETCODE~.*) \\(native\\)")?;

    // native asset info, specified two ways
    for command in &["asset 0", "asset $native"] {
        t.command(0, command)?
            .output("Native $native")?
            .output("Not auditable")?
            .output("Not freezeable")?
            .output("Not mintable")?;
    }

    Ok(())
}

fn cli_transfer_native(t: &mut CliClient) -> Result<(), String> {
    let balance = wait_for_starting_balance(t)?;
    t
        // Get the address and balance of both wallets.
        .command(0, "address")?
        .output("(?P<addr0>ADDR~.*)")?
        .command(0, "balance 0")?
        .output(format!("{}", balance))?
        .command(1, "address")?
        .output("(?P<addr1>ADDR~.*)")?
        .command(1, "balance 0")?
        .output("0")?
        // Transfer some native coins from the primary wallet to the secondary.
        .command(0, "transfer 0 $addr1 500 1")?
        .output("Transaction (?P<txn>TXN~.*)")?
        // Wait for the transaction to complete in both wallets (just because one wallet has
        // received and processed the completed transaction doesn't mean the other has).
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        .command(0, "balance 0")?
        .output(format!("{}", balance - 501))?
        .command(1, "balance 0")?
        .output("500")?
        // Transfer part of the money back
        .command(1, "transfer 0 $addr0 200 2")?
        .output("Transaction (?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        .command(1, "balance 0")?
        .output("298")?
        .command(0, "balance 0")?
        .output(format!("{}", balance - 301))?;
    Ok(())
}

fn cli_mint_and_transfer(t: &mut CliClient) -> Result<(), String> {
    wait_for_starting_balance(t)?;
    t
        // Get the address of the receiving wallet.
        .command(1, "address")?
        .output("(?P<addr1>ADDR~.*)")?
        // Define a new asset and mint some for the receiver.
        .command(0, "issue asset1")?
        .output("(?P<asset1>ASSETCODE~.*)")?
        .command(0, "asset 1")?
        .output("asset1 $asset1")?
        .output("Not auditable")?
        .output("Not freezeable")?
        .output("Minter: me")?
        .command(0, "mint 1 $addr1 100 1")?
        .output("Transaction (?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        // Check on the receiving end that
        //  (1) we have learned about the new asset after receiving it
        //  (2) we have a balance of it
        .command(1, "asset 1")?
        .output("Asset $asset1")? // Receiver doesn't know the description "asset1"
        .output("Not auditable")?
        .output("Not freezeable")?
        .output("Minter: unknown")? // Receiver doesn't know who minted the asset for them
        .command(1, "balance 1")?
        .output("100")?
        // Do it again, this time specifiying audit and freeze keys
        .command(0, "info")?
        .output("Audit key: (?P<audkey0>AUDPUBKEY~.*)")?
        .command(1, "info")?
        .output("Freeze key: (?P<freezekey1>FREEZEPUBKEY~.*)")?
        .command(0, "issue asset2 auditor=$audkey0 freezer=$freezekey1")?
        .output("(?P<asset2>ASSETCODE~.*)")?
        // Once there is more than 1 custom asset, we have to refer to it by code, not index,
        // because the order of custom assets is non-deterministic. I should probably fix that.
        .command(0, "asset $asset2")?
        .output("asset2 $asset2")?
        .output("Auditor: me")?
        .output("Freezer: $freezekey1")?
        .output("Minter: me")?
        .command(0, "mint $asset2 $addr1 200 1")?
        .output("Transaction (?P<txn>TXN~.*)")?
        .command(0, "wait $txn")?
        .output("accepted")?
        .command(1, "wait $txn")?
        .output("accepted")?
        // Check on the receiving end
        .command(1, "asset $asset2")?
        .output("Asset $asset2")?
        .output("Auditor: $audkey0")?
        .output("Freezer: me")?
        .output("Minter: unknown")?
        .command(1, "balance $asset2")?
        .output("200")?;
    Ok(())
}

fn cli_login(t: &mut CliClient) -> Result<(), String> {
    t.close(0)?
        .open(0)?
        .output("Enter password:")?
        // Enter the wrong password to check error handling
        .command(0, "wrong_password")?
        .output("Sorry, that's incorrect")?
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
