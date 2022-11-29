// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

#[cfg(all(test, feature = "slow-tests"))]
mod test {
    use crate::testing::TempDir;
    use crate::testing::UnencryptedKeystoreLoader;
    use crate::testing::{minimal_test_network, retry};
    use espresso_client::{network::NetworkBackend, Keystore};
    use espresso_core::universal_params::UNIVERSAL_PARAM;
    use jf_cap::{keys::UserKeyPair, structs::AssetCode};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use tracing_test::traced_test;

    #[cfg(feature = "slow-tests")]
    #[async_std::test]
    #[traced_test]
    async fn test_rewards_balance() {
        let mut rng = ChaChaRng::from_seed([1; 32]);
        let faucet_key_pair = UserKeyPair::generate(&mut rng);
        let rewards_address_keypair = UserKeyPair::generate(&mut rng);
        let network = minimal_test_network(
            &mut rng,
            faucet_key_pair.pub_key(),
            Some(rewards_address_keypair.pub_key()),
        )
        .await;

        //create wallet
        let mut loader1 = UnencryptedKeystoreLoader {
            dir: TempDir::new("rewards_test").unwrap(),
        };
        let mut keystore1 = Keystore::new(
            NetworkBackend::new(
                &UNIVERSAL_PARAM,
                network.query_api.clone(),
                network.address_book_api.clone(),
                network.submit_api.clone(),
            )
            .await
            .unwrap(),
            &mut loader1,
        )
        .await
        .unwrap();

        keystore1
            .add_account(
                rewards_address_keypair.clone(),
                "rewards addr".into(),
                Default::default(),
            )
            .await
            .unwrap();
        keystore1
            .add_account(faucet_key_pair.clone(), "faucet".into(), Default::default())
            .await
            .unwrap();

        keystore1
            .await_sending_key_scan(&faucet_key_pair.address())
            .await
            .unwrap();

        //send txn so we get a non-empty block to collect reward for
        let receipt = keystore1
            .transfer(
                None,
                &AssetCode::native(),
                &[(faucet_key_pair.pub_key(), 100)],
                1,
            )
            .await
            .unwrap();
        keystore1.await_transaction(&receipt).await.unwrap();

        //wait until reward transaction has been processed
        retry(|| async {
            keystore1
                .balance_breakdown(&rewards_address_keypair.address(), &AssetCode::native())
                .await
                > 0.into()
        })
        .await;
    }
}
