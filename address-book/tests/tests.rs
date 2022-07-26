// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.

use address_book::{
    init_web_server,
    store::{address_book_temp_dir, FileStore, Store, TransientFileStore},
    InsertPubKey,
};
use async_std::task::spawn;
use jf_cap::keys::{UserKeyPair, UserPubKey};
use portpicker::pick_unused_port;
use rand_chacha::rand_core::SeedableRng;
use std::collections::HashSet;
use tide::StatusCode;
use tide_disco::{wait_for_server, SERVER_STARTUP_RETRIES, SERVER_STARTUP_SLEEP_MS};
use url::Url;

const ROUND_TRIP_COUNT: u64 = 100;
const NOT_FOUND_COUNT: u64 = 100;

// Test
//    lookup(insert(x)) = x
// and
//    lookup(y) = Err, if y has not been previously inserted.
//
async fn round_trip<T: Store + 'static>(store: T) {
    let port = pick_unused_port().unwrap();
    let base_url: String = format!("http://127.0.0.1:{port}");
    let api_path = std::env::current_dir()
        .unwrap()
        .join("api")
        .join("api.toml");

    let app = init_web_server(api_path.to_str().unwrap().to_string(), store).expect("Huh");

    // Note: we don't want to take base_url from the settings because we want to pick a free port
    // for testing.
    let handle = spawn(app.serve(base_url.clone()));
    wait_for_server(
        &Url::parse(&base_url).unwrap(),
        SERVER_STARTUP_RETRIES,
        SERVER_STARTUP_SLEEP_MS,
    )
    .await;

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
        let url = format!("{base_url}/insert_pubkey");
        let response = surf::post(url)
            .content_type(surf::http::mime::JSON)
            .body_json(&json_request)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::Ok);
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let url = format!("{base_url}/request_pubkey");
        let response = surf::post(url)
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes);
        let mut response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::Ok);
        let gotten_pub_key: UserPubKey = response.body_json().await.unwrap();
        assert_eq!(gotten_pub_key, pub_key);
        let mut response = surf::get(format!("{base_url}/request_peers"))
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        let gotten_pub_keys: Vec<UserPubKey> = serde_json::from_slice(&bytes).unwrap();
        let gotten_set: HashSet<UserPubKey> = gotten_pub_keys.into_iter().collect();
        assert_eq!(gotten_set, inserted);
    }
    // Lookup the addresses just inserted to demonstrate that all the keys
    // are still present after the lookups.
    for _ in 0..ROUND_TRIP_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let mut response = surf::post(format!("{base_url}/request_pubkey"))
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes)
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        let gotten_pub_key: UserPubKey = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(gotten_pub_key, pub_key);
    }

    // Lookup addresses we didn't insert.
    for _ in 0..NOT_FOUND_COUNT {
        let user_key = UserKeyPair::generate(&mut rng2);
        let pub_key = user_key.pub_key();
        let address_bytes = bincode::serialize(&pub_key.address()).unwrap();
        let mut response = surf::post(format!("{base_url}/request_pubkey"))
            .content_type(surf::http::mime::BYTE_STREAM)
            .body_bytes(&address_bytes)
            .await
            .unwrap();
        let bytes = response.body_bytes().await.unwrap();
        assert!(bincode::deserialize::<UserPubKey>(&bytes).is_err());
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
