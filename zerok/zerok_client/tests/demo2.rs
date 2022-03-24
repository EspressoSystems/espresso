extern crate zerok_client;
use zerok_client::cli_client::cli_test;

#[test]
fn demo2() {
    cli_test(|t| {
        let key_path0 = t.wallet_key_path(0)?;
        let key_path0 = key_path0.as_os_str().to_str().ok_or_else(|| {
            format!(
                "failed to convert key path {:?} for wallet {} to string",
                key_path0, 0
            )
        })?;
        let key_path1 = t.wallet_key_path(1)?;
        let key_path1 = key_path1.as_os_str().to_str().ok_or_else(|| {
            format!(
                "failed to convert key path {:?} for wallet {} to string",
                key_path1, 1
            )
        })?;
        //Get the wallet addresses and check balances of the native assets
        let balance = 1u64 << 32;
        t.open(0)?
            .output("Welcome to the Espresso wallet, version 0.2.0")?
            .output("\\(c\\) 2021 Espresso Systems, Inc.")?
            .output("Your wallet will be identified by a secret mnemonic phrase. This phrase will allow you to recover your wallet if you lose access to it. Anyone who has access to this phrase will be able to view and spend your assets. Store this phrase in a safe, private place.")?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>[a-zA-Z ]+)")?
            .output("1\\) Accept phrase and create wallet")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            .command(0, "1")?
            .output("Create password:")?
            .command(0, "test_password0")?
            .output("Retype password:")?
            .command(0, "test_password0")?
            .output("connecting...")?
            .command(0, format!("load_key send {}", key_path0))?
            .output("Note: assets belonging to this key will become available")?
            .output("after a scan of the ledger. This may take a long time. If")?
            .output("you have the owner memo for a record you want to use")?
            .output("immediately, use import_memo.")?
            .output("(?P<addr0>ADDR~.*)")?
            .open(1)?
            .output("Welcome to the Espresso wallet, version 0.2.0")?
            .output("\\(c\\) 2021 Espresso Systems, Inc.")?
            .output("Your wallet will be identified by a secret mnemonic phrase. This phrase will allow you to recover your wallet if you lose access to it. Anyone who has access to this phrase will be able to view and spend your assets. Store this phrase in a safe, private place.")?
            .output("Your mnemonic phrase will be:")?
            .output("^(?P<mnemonic>[a-zA-Z ]+)$")?
            .output("1\\) Accept phrase and create wallet")?
            .output("2\\) Generate a new phrase")?
            .output("3\\) Manually enter a mnemonic")?
            .command(1, "1")?
            .output("Create password:")?
            .command(1, "test_password1")?
            .output("Retype password:")?
            .command(1, "test_password1")?
            .output("connecting...")?
            .command(1, format!("load_key send {}", key_path1))?
            .output("Note: assets belonging to this key will become available")?
            .output("after a scan of the ledger. This may take a long time. If")?
            .output("you have the owner memo for a record you want to use")?
            .output("immediately, use import_memo.")?
            .output("(?P<addr1>ADDR~.*)")?
            //get balances
            .command(0, "balance 0")?
            .output(format!("${} (?P<balance>\\d+)", "addr0"))?
            .command(1, "balance 0")?
            .output(format!("${} (?P<balance>\\d+)", "addr1"))?
            // Transfer some of the primary wallet's native tokens to the secondary
            .command(0, "transfer 0 $addr1 500 1")?
            .output("(?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("$addr0 {}", balance - 501))?
            .command(1, "balance 0")?
            .output("$addr1 500")?
            // Close and restart the wallets, showing that they retain their balances.
            .close(0)?
            .close(1)?
            .open(0)?
            .output("Enter mnemonic phrase")?
            .command(0, "$mnemonic0")?
            .output("connecting...")?
            .open(1)?
            .output("Enter mnemonic phrase")?
            .command(1, "$mnemonic1")?
            .output("connecting...")?
            .command(0, "balance 0")?
            .output(format!("$addr0 {}", balance - 501))?
            .command(1, "balance 0")?
            .output("$addr1 500")?
            // TODO Query the validator network APIs
            //  * show that all validators have the same state commitment (/getsnapshot)
            //  * show the public information about the committed block (/getblock, /gettransaction,
            //    /getunspentrecord)
            //
            // Close a validator (not 0, that's the server for the wallets) and show that we can
            // still complete transactions.
            .close_validator(1)?
            .command(0, "transfer 0 $addr1 200 2 wait=true")?
            .output("(?P<txn>TXN~.*)")?
            /*.command(0, "wait $txn")?
            .output("accepted")?*/
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("$addr0 {}", balance - 703))?
            .command(1, "balance 0")?
            .output("$addr1 700")?
            // Restart the validator and continue making transactions.
            .open_validator(1)?
            .command(0, "transfer 0 $addr1 200 2")?
            .output("(?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("$addr0 {}", balance - 905))?
            .command(1, "balance 0")?
            .output("$addr1 900")?
            // TODO Query the state commitments again, showing that
            //  1. All the validator's still agree on the state
            //  2. The restarted valiator has caught up and now agrees on the latest state
            //
            // To show that non-native assets work just as well, define, mint and transfer one.
            // Define a new asset and mint some for the receiver.
            .command(0, "issue MyAsset")?
            .output("(?P<asset>ASSET_CODE~.*)")?
            .command(0, "asset 1")?
            .output("MyAsset $asset")?
            .output("Not auditable")?
            .output("Not freezeable")?
            .output("Minter: me")?
            // Mint some for myself
            .command(0, "mint 1 $addr0 $addr0 100 1 wait=true")?
            // Transfer some to the secondary
            .command(0, "transfer 1 $addr0 $addr1 50 1")?
            .output("(?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            // Check on the receiving end that
            //  (1) we have learned about the new asset after receiving it
            //  (2) we have a balance of it
            .command(1, "asset 1")?
            .output("Asset $asset")? // Receiver doesn't know the description "MyAsset"
            .output("Not auditable")?
            .output("Not freezeable")?
            .output("Minter: unknown")? // Receiver doesn't know who minted the asset for them
            .command(1, "balance 1")?
            .output("$addr1 50")?;

        Ok(())
    })
}
