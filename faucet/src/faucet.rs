// Copyright (c) 2022 Espresso Systems (espressosys.com)
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! # The Espresso Faucet
//!

use async_std::{
    sync::{Arc, Mutex},
    task::{spawn, JoinHandle},
};
use jf_cap::{
    keys::{UserKeyPair, UserPubKey},
    structs::AssetCode,
};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::path::PathBuf;
use structopt::StructOpt;
use surf::Url;
use tide::{
    http::headers::HeaderValue,
    security::{CorsMiddleware, Origin},
    StatusCode,
};
use zerok_lib::{
    keystore::{
        events::EventIndex,
        loader::{Loader, LoaderMetadata},
        network::NetworkBackend,
        EspressoKeystore, EspressoKeystoreError,
    },
    universal_params::UNIVERSAL_PARAM,
};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Espresso Faucet Server",
    about = "Grants a native asset seed to a provided UserPubKey"
)]
pub struct FaucetOptions {
    /// mnemonic for the faucet keystore
    #[structopt(long, env = "ESPRESSO_FAUCET_WALLET_MNEMONIC")]
    pub mnemonic: String,

    /// path to the faucet keystore
    #[structopt(long = "keystore-path", env = "ESPRESSO_FAUCET_WALLET_PATH")]
    pub faucet_keystore_path: PathBuf,

    /// password on the faucet account keyfile
    #[structopt(
        long = "keystore-password",
        env = "ESPRESSO_FAUCET_WALLET_PASSWORD",
        default_value = ""
    )]
    pub faucet_password: String,

    /// binding port for the faucet service
    #[structopt(long, env = "ESPRESSO_FAUCET_PORT", default_value = "50079")]
    pub faucet_port: String,

    /// size of transfer for faucet grant
    #[structopt(long, env = "ESPRESSO_FAUCET_GRANT_SIZE", default_value = "5000")]
    pub grant_size: u64,

    /// fee for faucet grant
    #[structopt(long, env = "ESPRESSO_FAUCET_FEE_SIZE", default_value = "100")]
    pub fee_size: u64,

    /// URL for the Espresso Query Service.
    #[structopt(
        long,
        env = "ESPRESSO_ESQS_URL",
        default_value = "http://localhost:50087"
    )]
    pub esqs_url: Url,
}

#[derive(Clone)]
struct FaucetState {
    keystore: Arc<Mutex<EspressoKeystore<'static, NetworkBackend<'static, LoaderMetadata>>>>,
    grant_size: u64,
    fee_size: u64,
}

#[derive(Debug, Snafu, Serialize, Deserialize)]
#[snafu(module(error))]
pub enum FaucetError {
    #[snafu(display("error in faucet transfer: {}", msg))]
    Transfer { msg: String },

    #[snafu(display("internal server error: {}", msg))]
    Internal { msg: String },
}

impl net::Error for FaucetError {
    fn catch_all(msg: String) -> Self {
        Self::Internal { msg }
    }
    fn status(&self) -> StatusCode {
        match self {
            Self::Transfer { .. } => StatusCode::BadRequest,
            Self::Internal { .. } => StatusCode::InternalServerError,
        }
    }
}

pub fn faucet_server_error<E: Into<FaucetError>>(err: E) -> tide::Error {
    net::server_error(err)
}

pub fn faucet_error(source: EspressoKeystoreError) -> tide::Error {
    faucet_server_error(FaucetError::Transfer {
        msg: source.to_string(),
    })
}

/// Return a JSON expression with status 200 indicating the server
/// is up and running. The JSON expression is simply,
///    {"status": "available"}
/// When the server is running but unable to process requests
/// normally, a response with status 503 and payload {"status":
/// "unavailable"} should be added.
async fn healthcheck(_req: tide::Request<FaucetState>) -> Result<tide::Response, tide::Error> {
    Ok(tide::Response::builder(200)
        .content_type(tide::http::mime::JSON)
        .body(tide::prelude::json!({"status": "available"}))
        .build())
}

async fn request_fee_assets(
    mut req: tide::Request<FaucetState>,
) -> Result<tide::Response, tide::Error> {
    let pub_key: UserPubKey = net::server::request_body(&mut req).await?;
    let mut keystore = req.state().keystore.lock().await;
    let faucet_addr = keystore.pub_keys().await[0].address();
    tracing::info!(
        "transferring {} tokens from {} to {}",
        req.state().grant_size,
        net::UserAddress(faucet_addr.clone()),
        net::UserAddress(pub_key.address())
    );
    let bal = keystore.balance(&AssetCode::native()).await;
    tracing::info!("Keystore balance before transfer: {}", bal);
    keystore
        .transfer(
            Some(&faucet_addr),
            &AssetCode::native(),
            &[(pub_key.address(), req.state().grant_size)],
            req.state().fee_size,
        )
        .await
        .map_err(|err| {
            tracing::error!("Failed to transfer {}", err);
            faucet_error(err)
        })?;
    net::server::response(&req, ())
}

/// `faucet_key_pair` - If provided, will be added to the faucet keystore.
pub async fn init_web_server(
    opt: &FaucetOptions,
    faucet_key_pair: Option<UserKeyPair>,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    let mut password = opt.faucet_password.clone();
    if password.is_empty() {
        password = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    }
    let mut loader = Loader::recovery(
        opt.mnemonic.clone().replace('-', " "),
        password,
        opt.faucet_keystore_path.clone(),
    );
    let backend = NetworkBackend::new(
        &*UNIVERSAL_PARAM,
        opt.esqs_url.clone(),
        opt.esqs_url.clone(),
        opt.esqs_url.clone(),
        &mut loader,
    )
    .unwrap();
    let mut keystore = EspressoKeystore::new(backend).await.unwrap();

    // If a faucet key pair is provided, add it to the keystore. Otherwise, if we're initializing
    // for the first time, we need to generate a key. The faucet should be set up so that the
    // first HD sending key is the faucet key.
    if let Some(key) = faucet_key_pair {
        keystore
            .add_user_key(key, "faucet".into(), EventIndex::default())
            .await
            .unwrap();
    } else if keystore.pub_keys().await.is_empty() {
        // We pass `EventIndex::default()` to start a scan of the ledger from the beginning, in
        // order to discove the faucet record.
        keystore
            .generate_user_key("faucet".into(), Some(EventIndex::default()))
            .await
            .unwrap();
    }

    let bal = keystore.balance(&AssetCode::native()).await;
    tracing::info!("Keystore balance before init: {}", bal);
    let state = FaucetState {
        keystore: Arc::new(Mutex::new(keystore)),
        grant_size: opt.grant_size,
        fee_size: opt.fee_size,
    };
    let mut app = tide::with_state(state);
    app.with(
        CorsMiddleware::new()
            .allow_methods("GET, POST".parse::<HeaderValue>().unwrap())
            .allow_headers("*".parse::<HeaderValue>().unwrap())
            .allow_origin(Origin::from("*")),
    );
    app.at("/healthcheck").get(healthcheck);
    app.at("/request_fee_assets").post(request_fee_assets);
    let address = format!("0.0.0.0:{}", opt.faucet_port);
    Ok(spawn(app.listen(address)))
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Initialize the faucet web server.
    init_web_server(&FaucetOptions::from_args(), None)
        .await?
        .await?;

    Ok(())
}
