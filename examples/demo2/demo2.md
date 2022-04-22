# Setup

You can use the `demo_script` interpreter to control many validator and keystore processes at once, from a single terminal. This makes interacting with the demo a lot smoother. To start it,
```
cargo run --release --bin demo_script
```

# Create keystores

You can route commands to individual keystores using the keystore's numeric ID. Type the following (excluding # lines, which show the expected output) to create a new password-protected keystore:
```
keystore 0: open
# Enter password:
keystore 0: test_password0
# Retype password:
keystore 0: test_password0
```
Repeat the process using keystore ID 1, so we will have to keystores to transfer assets between.

# Check initial state
At any time, you can type `list` to list the active processes in the demo. Right now, typing `list` should show a number of validators and the two keystores we just created.

The demo is set up so that the primary keystore, keystore 0, has an initial balance of 2^32 native tokens, and all other keystores have no balance:
```
keystore 0: assets
# Lists available assets, notice the native asset type has index 0
keystore 0: balance 0
# 4294967296
keystore 1: balance 0
# 0
```

You can query the network API served by any validator using `validator ID: query URL`. Try it now to get some basic information about the state of the ledger:
```
validator 0: query getinfo
validator 0: query getstatecomm/latest
```
You can use getstatecomm with each of the validators to check that the validators agree about the initial state of the ledger.

# Make a transfer
Get the receiver address with
```
keystore 1: address
```
And then start a transfer with
```
keystore 0: transfer 0 <ADDRESS> 500 1
```
The arguments to `transfer` are asset index, destination address, amount, fee amount. Note that you can also use an asset code in place of the asset index.

The `transfer` command should print a transaction ID. You can wait for this transaction to complete (and for both keystores to process its completion) using
```
keystore 0: wait <TXN1>
# accepted
keystore 1: wait <TXN1>
# accepted
```

And check that the assets were actually transferred:
```
keystore 0: balance 0
# 4294966795
keystore 1: balance 0
# 500
```

Use the `getstatecomm` API endpoint to check that all of the validators have moved to a new state commitment, and they all still agree on what that is. You can use `getstatecomm/:index` to view previous state commitments, to ensure they are different from the current one. For example,
```
validator 0: query getstatecomm/latest
validator 0: query getstatecomm/0
```

We can also use the API to view the public information about the transaction we just completed:
```
validator 0: query getblock/latest
```

# Simulate a validator getting disconnected
```
validator 1: close
```
Uh oh! Validator #1 has been disconnected from the system. Can the rest of the validators still form consensus and continue to make progress? Let's see...
```
keystore 0: transfer 0 <ADDRESS> 200 2
keystore 0: wait <TXN2>
keystore 1: wait <TXN2>

keystore 0: balance 0
# 4294966593
keystore 1: balance 0
# 700
```

Use the network API once again to check that the remaining validators have agreed on a new state commitment.

# Catch-up a validator
```
validator 1: open
```
Validator #1 is back online. Can it catch up to the other validators and start successfully participating in consensus again?
```
keystore 0: transfer 0 <ADDRESS> 200 2
keystore 0: wait <TXN3>
keystore 1: wait <TXN3>

keystore 0: balance 0
# 4294966391
keystore 1: balance 0
# 900
```

Check that all of the validators, including #1, agree on the new state commitment. Query validator 1 to make sure it has the latest information about the state of the ledger:
```
validator 1: query getinfo
# should contain a block count of 3, including the block that was committed while it was
# down and the 1 that has been committed since it came back up
validator 1: query getblock/index/1
# should have block details for the block that was committed while it was down
```

