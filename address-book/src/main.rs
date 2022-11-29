// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

// Copyright (c) 2022 Espresso Systems (espressosys.com)

use address_book::{
    error::AddressBookError, init_web_server, store::address_book_store_path, store::FileStore,
    AppKey, Args, APP_NAME,
};
use espresso_systems_common::brand::ORG_DIR_NAME;
use std::fs;
use std::path::PathBuf;
use tide_disco::{compose_settings, init_logging, DiscoKey};

#[async_std::main]
async fn main() -> Result<(), AddressBookError> {
    // Combine settings from multiple sources.
    let api_path = std::env::current_dir()
        .unwrap()
        .join("api")
        .join("api.toml");
    let settings = compose_settings::<Args>(
        ORG_DIR_NAME,
        APP_NAME,
        &[
            (DiscoKey::api_toml.as_ref(), api_path.to_str().unwrap()),
            (DiscoKey::base_url.as_ref(), "http://127.0.0.1:50078"),
            (
                AppKey::store_path.as_ref(),
                address_book_store_path().to_str().unwrap(),
            ),
        ],
    )?;

    // Colorful logs upon request.
    let want_color = settings.get_bool("ansi_color").unwrap_or(false);

    init_logging(want_color);

    let api_toml = settings.get_string(DiscoKey::api_toml.as_ref())?;
    let base_url = &settings.get_string(DiscoKey::base_url.as_ref())?;

    let store_path = &settings.get_string(AppKey::store_path.as_ref())?;
    fs::create_dir_all(&store_path)?;
    let store = FileStore::new(PathBuf::from(store_path));

    let app = init_web_server(api_toml, store)?;

    app.serve(base_url)
        .await
        .map_err(|err| AddressBookError::Config {
            msg: err.to_string(),
        })
        .unwrap();

    Ok(())
}
