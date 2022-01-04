use super::*;
use chrono::Duration;

#[derive(Clone, Debug)]
pub struct TxnHistoryWithTimeTolerantEq<L: Ledger>(pub TransactionHistoryEntry<L>);

impl<L: Ledger> PartialEq<Self> for TxnHistoryWithTimeTolerantEq<L> {
    fn eq(&self, other: &Self) -> bool {
        let time_tolerance = Duration::minutes(5);
        let times_eq = if self.0.time < other.0.time {
            other.0.time - self.0.time < time_tolerance
        } else {
            self.0.time - other.0.time < time_tolerance
        };
        times_eq
            && self.0.asset == other.0.asset
            && self.0.kind == other.0.kind
            && self.0.receivers == other.0.receivers
            && self.0.receipt == other.0.receipt
    }
}

#[cfg(test)]
#[generic_tests::define(attrs(test, async_std::test))]
mod tests {
    use super::*;

    /*
     * Test idea: simulate two wallets transferring funds back and forth. After initial
     * setup, the wallets only receive publicly visible information (e.g. block commitment
     * events and receiver memos posted on bulletin boards). Check that both wallets are
     * able to maintain accurate balance statements and enough state to construct new transfers.
     *
     * - Alice magically starts with some coins, Bob starts empty.
     * - Alice transfers some coins to Bob using exact change.
     * - Alice and Bob check their balances, then Bob transfers some coins back to Alice, in an
     *   amount that requires a fee change record.
     *
     * Limitations:
     * - Parts of the system are mocked (e.g. consensus is replaced by one omniscient validator,
     *   info event streams, query services, and bulletin boards is provided directly to the
     *   wallets by the test)
     */
    #[allow(unused_assignments)]
    async fn test_two_wallets<'a, T: SystemUnderTest<'a>>(native: bool) {
        let mut t = T::default();
        let mut now = Instant::now();

        // One more input and one more output than we will ever need, to test dummy records.
        let num_inputs = 3;
        let num_outputs = 4;

        // Give Alice an initial grant of 5 native coins. If using non-native transfers, give Bob an
        // initial grant with which to pay his transaction fee, since he will not be receiving any
        // native coins from Alice.
        let alice_grant = 5;
        let bob_grant = if native { 0 } else { 1 };
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                vec![alice_grant, bob_grant],
                &mut now,
            )
            .await;
        let alice_address = wallets[0].1.clone();
        let bob_address = wallets[1].1.clone();

        // Verify initial wallet state.
        assert_ne!(alice_address, bob_address);
        assert_eq!(
            wallets[0]
                .0
                .balance(&alice_address, &AssetCode::native())
                .await,
            alice_grant
        );
        assert_eq!(
            wallets[1]
                .0
                .balance(&bob_address, &AssetCode::native())
                .await,
            bob_grant
        );

        let coin = if native {
            AssetDefinition::native()
        } else {
            let coin = wallets[0]
                .0
                .define_asset("Alice's asset".as_bytes(), Default::default())
                .await
                .unwrap();
            // Alice gives herself an initial grant of 5 coins.
            wallets[0]
                .0
                .mint(&alice_address, 1, &coin.code, 5, alice_address.clone())
                .await
                .unwrap();
            t.sync(&ledger, &wallets).await;
            println!("Asset minted: {}s", now.elapsed().as_secs_f32());
            now = Instant::now();

            assert_eq!(wallets[0].0.balance(&alice_address, &coin.code).await, 5);
            assert_eq!(wallets[1].0.balance(&bob_address, &coin.code).await, 0);

            coin
        };

        let alice_initial_native_balance = wallets[0]
            .0
            .balance(&alice_address, &AssetCode::native())
            .await;
        let bob_initial_native_balance = wallets[1]
            .0
            .balance(&bob_address, &AssetCode::native())
            .await;

        // Construct a transaction to transfer some coins from Alice to Bob.
        wallets[0]
            .0
            .transfer(&alice_address, &coin.code, &[(bob_address.clone(), 3)], 1)
            .await
            .unwrap();
        t.sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that both wallets reflect the new balances (less any fees). This cannot be a
        // closure because rust infers the wrong lifetime for the references (it tries to use 'a,
        // which is longer than we want to borrow `wallets` for).
        async fn check_balance<'b, L: 'static + Ledger>(
            wallet: &(
                Wallet<'b, impl WalletBackend<'b, L> + Sync + 'b, L>,
                UserAddress,
            ),
            expected_coin_balance: u64,
            starting_native_balance: u64,
            fees_paid: u64,
            coin: &AssetDefinition,
            native: bool,
        ) {
            if native {
                assert_eq!(
                    wallet.0.balance(&wallet.1, &coin.code).await,
                    expected_coin_balance - fees_paid
                );
            } else {
                assert_eq!(
                    wallet.0.balance(&wallet.1, &coin.code).await,
                    expected_coin_balance
                );
                assert_eq!(
                    wallet.0.balance(&wallet.1, &AssetCode::native()).await,
                    starting_native_balance - fees_paid
                );
            }
        }
        check_balance(
            &wallets[0],
            2,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 3, bob_initial_native_balance, 0, &coin, native).await;

        // Check that Bob's wallet has sufficient information to access received funds by
        // transferring some back to Alice.
        //
        // This transaction should also result in a non-zero fee change record being
        // transferred back to Bob, since Bob's only sufficient record has an amount of 3 coins, but
        // the sum of the outputs and fee of this transaction is only 2.
        wallets[1]
            .0
            .transfer(&bob_address, &coin.code, &[(alice_address, 1)], 1)
            .await
            .unwrap();
        t.sync(&ledger, &wallets).await;
        println!("Transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        check_balance(
            &wallets[0],
            3,
            alice_initial_native_balance,
            1,
            &coin,
            native,
        )
        .await;
        check_balance(&wallets[1], 2, bob_initial_native_balance, 1, &coin, native).await;
    }

    #[async_std::test]
    async fn test_two_wallets_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        test_two_wallets::<T>(true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_two_wallets_non_native<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        test_two_wallets::<T>(false).await;
        Ok(())
    }

    // Test transactions that fail to complete.
    //
    // If `native`, the transaction is a native asset transfer.
    // If `!native && !mint && !freeze`, the transaction is a non-native asset transfer.
    // If `!native && mint`, the transaction is a non-native asset mint.
    // If `!native && freeze`, the transaction is a non-native asset freeze.
    //
    // If `timeout`, the failed transaction times out with no explicit rejection event. Otherwise,
    // the failed transaction fails to verify and a Reject event is emitted.
    //
    // (native, mint), (native, freeze), and (mint, freeze) are pairs of mutually exclusive flags.
    async fn test_wallet_rejected<'a, T: SystemUnderTest<'a>>(
        native: bool,
        mint: bool,
        freeze: bool,
        timeout: bool,
    ) {
        let mut t = T::default();

        assert!(!(native && mint));
        assert!(!(native && freeze));
        assert!(!(mint && freeze));

        let mut now = Instant::now();

        // Native transfers have extra fee/change inputs/outputs.
        let num_inputs = if native { 1 } else { 2 };
        let num_outputs = if native { 2 } else { 3 };

        // The sender wallet (wallets[0]) gets an initial grant of 2 for a transaction fee and a
        // payment (or, for non-native transfers, a transaction fee and a mint fee). wallets[1] will
        // act as the receiver, and wallets[2] will be a third party which generates
        // RECORD_HOLD_TIME transfers while a transfer from wallets[0] is pending, causing the
        // transfer to time out.
        let (ledger, mut wallets) = t
            .create_test_network(
                &[(num_inputs, num_outputs)],
                // If native, wallets[0] gets 1 coin to transfer and 1 for a transaction fee. Otherwise,
                // it gets
                //  * 1 transaction fee
                //  * 1 mint fee for its initial non-native record, if the test itself is not minting
                //    that record
                //  * 1 mint fee for wallets[2]'s initial non-native record in the timeout test.
                vec![
                    if native {
                        2
                    } else {
                        1 + !mint as u64 + timeout as u64
                    },
                    0,
                    2 * RECORD_HOLD_TIME,
                ],
                &mut now,
            )
            .await;

        let asset = if native {
            AssetDefinition::native()
        } else {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let audit_key = AuditorKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(audit_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            wallets[0].0.add_audit_key(audit_key).await.unwrap();
            wallets[0].0.add_freeze_key(freeze_key).await.unwrap();
            let asset = wallets[0]
                .0
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            if !mint {
                // If we're freezing, the transaction is essentially taking balance away from
                // wallets[1], so wallets[1] gets 1 coin to start with. Otherwise, the transaction
                // is transferring balance from wallets[0] to wallets[1], so  wallets[0] gets 1
                // coin. We only need this if the test itself is not minting the asset later on.
                let dst = if freeze {
                    wallets[1].1.clone()
                } else {
                    wallets[0].1.clone()
                };
                let src = wallets[0].1.clone();
                wallets[0]
                    .0
                    .mint(&src, 1, &asset.code, 1, dst)
                    .await
                    .unwrap();
                t.sync(&ledger, &wallets).await;
            }

            if timeout {
                // If doing a timeout test, wallets[2] (the sender that will generate enough
                // transactions to cause wallets[0]'s transaction to timeout) gets RECORD_HOLD_TIME
                // coins.
                let src = wallets[0].1.clone();
                let dst = wallets[2].1.clone();
                wallets[0]
                    .0
                    .mint(&src, 1, &asset.code, RECORD_HOLD_TIME, dst)
                    .await
                    .unwrap();
                t.sync(&ledger, &wallets).await;
            }

            asset
        };

        // Start a transfer that will ultimately get rejected.
        println!(
            "generating a transfer which will fail: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        ledger.lock().await.hold_next_transaction();
        let receiver = wallets[1].1.clone();
        let sender = wallets[0].1.clone();
        if mint {
            wallets[0]
                .0
                .mint(&sender, 1, &asset.code, 1, receiver.clone())
                .await
                .unwrap();
        } else if freeze {
            wallets[0]
                .0
                .freeze(&sender, 1, &asset, 1, receiver.clone())
                .await
                .unwrap();
        } else {
            wallets[0]
                .0
                .transfer(&sender, &asset.code, &[(receiver.clone(), 1)], 1)
                .await
                .unwrap();
        }
        println!("transfer generated: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();

        // Check that the sender's balance is on hold (for the fee and the payment).
        assert_eq!(
            wallets[0]
                .0
                .balance(&wallets[0].1, &AssetCode::native())
                .await,
            0
        );
        if !freeze {
            assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 0);
        }

        // Now do something that causes the sender's transaction to not go through
        if timeout {
            // Generate RECORD_HOLD_TIME transactions to cause `txn` to time out.
            println!(
                "generating {} transfers to time out the original transfer: {}s",
                RECORD_HOLD_TIME,
                now.elapsed().as_secs_f32()
            );
            now = Instant::now();
            for _ in 0..RECORD_HOLD_TIME {
                // Check that the sender's balance is still on hold.
                assert_eq!(
                    wallets[0]
                        .0
                        .balance(&wallets[0].1, &AssetCode::native())
                        .await,
                    0
                );
                if !freeze {
                    assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 0);
                }

                let sender = wallets[2].1.clone();
                wallets[2]
                    .0
                    .transfer(&sender, &asset.code, &[(receiver.clone(), 1)], 1)
                    .await
                    .unwrap();
                t.sync(&ledger, &wallets).await;
            }
        } else {
            {
                let mut ledger = ledger.lock().await;

                // Change the validator state, so that the wallet's transaction (built against the
                // old validator state) will fail to validate.
                ledger.mangle();

                println!(
                    "validating invalid transaction: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
                ledger.release_held_transaction();
                ledger.flush().unwrap();

                // The sender gets back in sync with the validator after their transaction is
                // rejected.
                ledger.unmangle();
            }

            t.sync(&ledger, &wallets).await;
        }

        // Check that the sender got their balance back.
        if native {
            assert_eq!(
                wallets[0]
                    .0
                    .balance(&wallets[0].1, &AssetCode::native())
                    .await,
                2
            );
        } else {
            assert_eq!(
                wallets[0]
                    .0
                    .balance(&wallets[0].1, &AssetCode::native())
                    .await,
                1
            );
            if !(mint || freeze) {
                // in the mint and freeze cases, we never had a non-native balance to start with
                assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 1);
            }
        }
        assert_eq!(
            wallets[1].0.balance(&wallets[1].1, &asset.code).await,
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 1 } else { 0 })
        );

        // Now check that they can use the un-held record if their state gets back in sync with the
        // validator.
        println!(
            "transferring un-held record: {}s",
            now.elapsed().as_secs_f32()
        );
        if mint {
            wallets[0]
                .0
                .mint(&sender, 1, &asset.code, 1, receiver)
                .await
                .unwrap();
        } else if freeze {
            wallets[0]
                .0
                .freeze(&sender, 1, &asset, 1, receiver)
                .await
                .unwrap();
        } else {
            wallets[0]
                .0
                .transfer(&sender, &asset.code, &[(receiver, 1)], 1)
                .await
                .unwrap();
        }
        t.sync(&ledger, &wallets).await;
        assert_eq!(
            wallets[0]
                .0
                .balance(&wallets[0].1, &AssetCode::native())
                .await,
            0
        );
        assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 0);
        assert_eq!(
            wallets[1].0.balance(&wallets[1].1, &asset.code).await,
            (if timeout { RECORD_HOLD_TIME } else { 0 }) + (if freeze { 0 } else { 1 })
        );
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(true, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(true, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_xfr_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, true, false, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_mint_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, true, false, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_invalid<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, true, false).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_rejected_non_native_freeze_timeout<'a, T: SystemUnderTest<'a>>(
    ) -> std::io::Result<()> {
        test_wallet_rejected::<T>(false, false, true, true).await;
        Ok(())
    }

    #[async_std::test]
    async fn test_wallet_freeze<'a, T: SystemUnderTest<'a>>() -> std::io::Result<()> {
        let mut t = T::default();
        let mut now = Instant::now();

        // The sender wallet (wallets[0]) gets an initial grant of 1 for a transfer fee. wallets[1]
        // will act as the receiver, and wallets[2] will be a third party which issues and freezes
        // some of wallets[0]'s assets. It gets a grant of 3, for a mint fee, a freeze fee and an
        // unfreeze fee.
        //
        // Note that the transfer proving key size (3, 4) used here is chosen to be 1 larger than
        // necessary in both inputs and outputs, to test dummy records.
        let (ledger, mut wallets) = t
            .create_test_network(&[(3, 4)], vec![1, 0, 3], &mut now)
            .await;

        let asset = {
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let audit_key = AuditorKeyPair::generate(&mut rng);
            let freeze_key = FreezerKeyPair::generate(&mut rng);
            let policy = AssetPolicy::default()
                .set_auditor_pub_key(audit_key.pub_key())
                .set_freezer_pub_key(freeze_key.pub_key())
                .reveal_record_opening()
                .unwrap();
            wallets[2].0.add_audit_key(audit_key).await.unwrap();
            wallets[2].0.add_freeze_key(freeze_key).await.unwrap();
            let asset = wallets[2]
                .0
                .define_asset("test asset".as_bytes(), policy)
                .await
                .unwrap();

            // wallets[0] gets 1 coin to transfer to wallets[1].
            let src = wallets[2].1.clone();
            let dst = wallets[0].1.clone();
            wallets[2]
                .0
                .mint(&src, 1, &asset.code, 1, dst)
                .await
                .unwrap();
            t.sync(&ledger, &wallets).await;

            asset
        };
        assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 1);
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1, &asset.code)
                .await,
            0
        );

        // Now freeze wallets[0]'s record.
        println!(
            "generating a freeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let src = wallets[2].1.clone();
        let dst = wallets[0].1.clone();
        ledger.lock().await.hold_next_transaction();
        wallets[2]
            .0
            .freeze(&src, 1, &asset, 1, dst.clone())
            .await
            .unwrap();

        // Check that, like transfer inputs, freeze inputs are placed on hold and unusable while a
        // freeze that uses them is pending.
        match wallets[2].0.freeze(&src, 1, &asset, 1, dst).await {
            Err(WalletError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {}
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now go ahead with the original freeze.
        ledger.lock().await.release_held_transaction();
        t.sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 0);
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1, &asset.code)
                .await,
            1
        );

        // Check that trying to transfer fails due to frozen balance.
        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        now = Instant::now();
        let src = wallets[0].1.clone();
        let dst = wallets[1].1.clone();
        match wallets[0]
            .0
            .transfer(&src, &asset.code, &[(dst, 1)], 1)
            .await
        {
            Err(WalletError::TransactionError {
                source: TransactionError::InsufficientBalance { .. },
            }) => {
                println!(
                    "transfer correctly failed due to frozen balance: {}s",
                    now.elapsed().as_secs_f32()
                );
                now = Instant::now();
            }
            ret => panic!("expected InsufficientBalance, got {:?}", ret.map(|_| ())),
        }

        // Now unfreeze the asset and try again.
        println!(
            "generating an unfreeze transaction: {}s",
            now.elapsed().as_secs_f32()
        );
        now = Instant::now();
        let src = wallets[2].1.clone();
        let dst = wallets[0].1.clone();
        wallets[2]
            .0
            .unfreeze(&src, 1, &asset, 1, dst)
            .await
            .unwrap();
        t.sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 1);
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1, &asset.code)
                .await,
            0
        );

        println!("generating a transfer: {}s", now.elapsed().as_secs_f32());
        let src = wallets[0].1.clone();
        let dst = wallets[1].1.clone();
        let xfr_receipt = wallets[0]
            .0
            .transfer(&src, &asset.code, &[(dst, 1)], 1)
            .await
            .unwrap();
        t.sync(&ledger, &wallets).await;
        assert_eq!(wallets[0].0.balance(&wallets[0].1, &asset.code).await, 0);
        assert_eq!(
            wallets[0]
                .0
                .frozen_balance(&wallets[0].1, &asset.code)
                .await,
            0
        );
        assert_eq!(wallets[1].0.balance(&wallets[1].1, &asset.code).await, 1);

        // Check that the history properly accounts for freezes and unfreezes.
        let expected_history = vec![
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::mint(),
                sender: None,
                receivers: vec![(wallets[0].1.clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::freeze(),
                sender: None,
                receivers: vec![(wallets[0].1.clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::unfreeze(),
                sender: None,
                receivers: vec![(wallets[0].1.clone(), 1)],
                receipt: None,
            },
            TransactionHistoryEntry {
                time: Local::now(),
                asset: asset.code,
                kind: TransactionKind::<T::Ledger>::send(),
                sender: Some(wallets[0].1.clone()),
                receivers: vec![(wallets[1].1.clone(), 1)],
                receipt: Some(xfr_receipt),
            },
        ]
        .into_iter()
        .map(TxnHistoryWithTimeTolerantEq)
        .collect::<Vec<_>>();
        let actual_history = wallets[0]
            .0
            .transaction_history()
            .await
            .unwrap()
            .into_iter()
            .map(TxnHistoryWithTimeTolerantEq)
            .collect::<Vec<_>>();
        assert_eq!(actual_history, expected_history);

        Ok(())
    }

    #[instantiate_tests(<'static, aap_test::AAPTest>)]
    mod aap_wallet_tests {}

    #[instantiate_tests(<'static, cape_test::CapeTest>)]
    mod cape_wallet_tests {}
}
