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

use address_book::{
    error::AddressBookError,
    init_web_server,
    store::{address_book_temp_dir, FileStore, Store, TransientFileStore},
    InsertPubKey,
};
use async_std::task::spawn;
use jf_cap::keys::{UserKeyPair, UserPubKey};
use portpicker::pick_unused_port;
use rand_chacha::rand_core::SeedableRng;
use std::collections::HashSet;
use surf_disco::{Error, StatusCode};

const ROUND_TRIP_COUNT: u64 = 100;
const NOT_FOUND_COUNT: u64 = 100;

// Test
//    lookup(insert(x)) = x
// and
//    lookup(y) = Err, if y has not been previously inserted.
//
async fn round_trip<T: Store + 'static>(store: T) {
    let port = pick_unused_port().unwrap();
    let base_url: String = format!("127.0.0.1:{port}");
    let api_path = std::env::current_dir()
        .unwrap()
        .join("api")
        .join("api.toml");

    let app = init_web_server(api_path.to_str().unwrap().to_string(), store).expect("Huh");

    // Note: we don't want to take base_url from the settings because we want to pick a free port
    // for testing.
    let handle = spawn(app.serve(base_url.clone()));
    // Don't add `http://` to `base_url` until `handle` is created, to avoid the `spawn` failure
    // due to `Can't assign requested address`.
    let base_url = format!("http://{base_url}").parse().unwrap();
    let client = surf_disco::Client::<AddressBookError>::new(base_url);
    assert!(client.connect(None).await);

    let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
    let mut rng2 = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
    let mut inserted = HashSet::new();

    // Insert and lookup a bunch of address/key pairs.
    for _ in 0..ROUND_TRIP_COUNT {
        let user_key = UserKeyPair::generate(&mut rng);
        let pub_key = user_key.pub_key();
        inserted.insert(pub_key.clone());
        let pub_key_bytes = bincode::serialize(&pub_key).unwrap();
        let sig = user_key.sign(&pub_key_bytes);
        let json_request = InsertPubKey { pub_key_bytes, sig };
        client
            .post::<()>("insert_pubkey")
            .body_json(&json_request)
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(
            client
                .post::<UserPubKey>("request_pubkey")
                .body_binary(&pub_key.address())
                .unwrap()
                .send()
                .await
                .unwrap(),
            pub_key
        );
        assert_eq!(
            client
                .get::<Vec<UserPubKey>>("request_peers")
                .send()
                .await
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            inserted
        );
    }
    // Lookup the addresses just inserted to demonstrate that all the keys
    // are still present after the lookups.
    for _ in 0..ROUND_TRIP_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        assert_eq!(
            client
                .post::<UserPubKey>("request_pubkey")
                .body_binary(&pub_key.address())
                .unwrap()
                .send()
                .await
                .unwrap(),
            pub_key
        );
    }

    // Lookup addresses we didn't insert.
    for _ in 0..NOT_FOUND_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        let err = client
            .post::<UserPubKey>("request_pubkey")
            .body_binary(&pub_key.address())
            .unwrap()
            .send()
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::NotFound);
    }
    assert!(handle.cancel().await.is_none());
}

#[async_std::test]
async fn test_address_book() {
    // Can change to using two separate tests once the webserver port is
    // configurable.
    let temp_dir = address_book_temp_dir();
    let file_store = FileStore::new(temp_dir.path().to_path_buf());
    round_trip(file_store).await;

    let transient_store = TransientFileStore::default();
    round_trip(transient_store).await
}
