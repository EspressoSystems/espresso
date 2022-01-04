#[cfg(test)]
#[generic_tests::define(attrs(test, async_std::test))]
mod tests {
    use super::super::*;

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

    #[instantiate_tests(<'static, aap_test::AAPTest>)]
    mod aap_wallet_tests {}

    #[instantiate_tests(<'static, cape_test::CapeTest>)]
    mod cape_wallet_tests {}
}
