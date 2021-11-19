extern crate zerok_client;
use zerok_client::cli_client::cli_test;

#[test]
#[ignore]
fn demo2() {
    cli_test(|t| {
        t
            // Log in to the primary wallet
            .open(0)?
            .output("Create password:")?
            .command(0, "test_password1")?
            .output("Retype password:")?
            .command(0, "test_password1")?
            .output("connecting...")?
            // Log in to the secondary wallet
            .open(1)?
            .output("Create password:")?
            .command(1, "test_password2")?
            .output("Retype password:")?
            .command(1, "test_password2")?
            .output("connecting...")?
            // Get the wallet addresses and check balances of the native assets
            .command(0, "address")?
            .output("(?P<addr0>ADDR~.*)")?
            .command(0, "balance 0")?
            .output(format!("{}", 1u64 << 32))?
            .command(1, "address")?
            .output("(?P<addr1>ADDR~.*)")?
            .command(1, "balance 0")?
            .output("0")?
            // Transfer some of the primary wallet's native tokens to the secondary
            .command(0, "transfer 0 $addr1 500 1")?
            .output("Transaction (?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("{}", (1u64 << 32) - 501))?
            .command(1, "balance 0")?
            .output("500")?
            // Close and restart the wallets, showing that they retain their balances.
            .close(0)?
            .close(1)?
            .open(0)?
            .output("Enter password:")?
            .command(0, "test_password1")?
            .output("Connecting...")?
            .open(1)?
            .output("Enter password:")?
            .command(1, "test_password2")?
            .output("Connecting...")?
            .command(0, "balance 0")?
            .output(format!("{}", (1u64 << 32) - 501))?
            .command(1, "balance 0")?
            .output("500")?
            // TODO Query the validator network APIs
            //  * show that all validators have the same state commitment (/getsnapshot)
            //  * show the public information about the committed block (/getblock, /gettransaction,
            //    /getunspentrecord)
            //
            // Close a validator (not 0, that's the server for the wallets) and show that we can
            // still complete transactions.
            .close_validator(1)?
            .command(0, "transfer 0 $addr1 200 2")?
            .output("Transaction (?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("{}", (1u64 << 32) - 703))?
            .command(1, "balance 0")?
            .output("700")?
            // Restart the validator and continue making transactions.
            .open_validator(1)?
            .command(0, "transfer 0 $addr1 200 2")?
            .output("Transaction (?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            .command(0, "balance 0")?
            .output(format!("{}", (1u64 << 32) - 905))?
            .command(1, "balance 0")?
            .output("900")?
            // TODO Query the state commitments again, showing that
            //  1. All the validator's still agree on the state
            //  2. The restarted valiator has caught up and now agrees on the latest state
            //
            // To show that non-native assets work just as well, define, mint and transfer one.
            // Define a new asset and mint some for the receiver.
            .command(0, "issue MyAsset")?
            .output("(?P<asset>ASSETCODE~.*)")?
            .command(0, "asset 1")?
            .output("MyAsset $asset")?
            .output("Not auditable")?
            .output("Not freezeable")?
            .output("Minter: me")?
            // Mint some for myself
            .command(0, "mint 1 $addr0 100 1 wait=true")?
            // Transfer some to the secondary
            .command(0, "transfer 1 $addr0 50 1")?
            .output("(?P<txn>TXN~.*)")?
            .command(0, "wait $txn")?
            .output("accepted")?
            .command(1, "wait $txn")?
            .output("accepted")?
            // Check on the receiving end that
            //  (1) we have learned about the new asset after receiving it
            //  (2) we have a balance of it
            .command(1, "asset 1")?
            .output("Asset $asset1")? // Receiver doesn't know the description "MyAsset"
            .output("Not auditable")?
            .output("Not freezeable")?
            .output("Minter: unknown")? // Receiver doesn't know who minted the asset for them
            .command(1, "balance 1")?
            .output("50")?;

        Ok(())
    })
}
