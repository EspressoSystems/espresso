// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use async_std::sync::{Arc, RwLock};
use async_std::task;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::hash_map::{Entry, HashMap};
use std::time::Duration;
use tide::{Body, Error, Request, StatusCode};
use tide_websockets::async_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
//use tide_websockets::async_tungstenite::tungstenite::protocol::CloseFrame;
use tide_websockets::Message::Close;
use tide_websockets::{/*Message as WSMessage, */ WebSocket, WebSocketConnection};
use tracing::{event, Level};

#[derive(Clone)]
struct Connection {
    id: u64,
    wsc: WebSocketConnection,
}

#[derive(Clone)]
struct State {
    connections: Arc<RwLock<HashMap<u64, Connection>>>,
}

impl State {
    fn new() -> Self {
        Self {
            connections: Default::default(),
        }
    }

    async fn send_message(&self, id: u64, cmd: &str, message: &str) -> tide::Result<()> {
        let mut connections = self.connections.write().await;
        match connections.entry(id) {
            Entry::Vacant(_) => {
                event!(
                    Level::DEBUG,
                    "main.rs:send_message: Vacant {}, {}",
                    id,
                    message
                );
            }
            Entry::Occupied(mut id_connections) => {
                id_connections
                    .get_mut()
                    .wsc
                    .send_json(&json!({"client_id": id, "cmd": cmd, "msg": message }))
                    .await?
            }
        }
        Ok(())
    }

    async fn add_connection(&self, id: u64, wsc: WebSocketConnection) -> tide::Result<()> {
        event!(Level::DEBUG, "main.rs: Adding connection {}", id);
        let mut connections = self.connections.write().await;
        let connection = Connection { id, wsc };
        connections.insert(id, connection);
        Ok(())
    }
}

/*async fn get_transfer_html(_: Request<State>) -> Result<Body, tide::Error> {
    Ok(Body::from_file("./public/index.html").await?)
}

async fn get_index_html(req: Request<State>) -> Result<String, tide::Error> {
    let amount: u64 = req
        .param("amount")?
        .parse()
        .map_err(|err| Error::new(StatusCode::BadRequest, err))?;
    Ok(format!(
        "Recipient: {}, Amount: {}",
        req.param("recipient")?,
        amount
    ))
}
*/

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let mut app = tide::with_state(State::new());
    app.at("/public").serve_dir("./public/")?;
    app.at("/")
        .get(|_| async { Ok(Body::from_file("./public/index.html").await?) });
    app.at("/:id")
        .with(WebSocket::new(
            |req: Request<State>, mut wsc: WebSocketConnection| async move {
                let id = req.param("id")?;
                event!(Level::DEBUG, "main.rs: id: {}", &id);
                let nid: u64 = id.parse().expect("id should be an ordinal number.");
                let state = req.state().clone();
                state.add_connection(nid, wsc.clone()).await?;
                state.send_message(nid, "REPORT", "hi, there").await?;
                // TODO !corbett Hmm. Are there other results that are
                // getting dropped, like someone leaving?

                // while let Some(Ok(WSMessage::Text(message))) = wsc.next().await {
                loop {
                    let opt_message = wsc.next().await;
                    match opt_message {
                        Some(result_message) => match result_message {
                            Ok(message) => {
                                event!(Level::DEBUG, "main.rs:WebSocket message: {:?}", message);
                                if let Close(Some(cf)) = message {
                                    // See https://docs.rs/tungstenite/0.14.0/tungstenite/protocol/frame/coding/enum.CloseCode.html
                                    if cf.code == CloseCode::Away {
                                        event!(Level::DEBUG, "main.rs:cf Client went away.");
                                        break;
                                    } else {
                                        event!(Level::DEBUG, "main.rs:cf {:?}", &cf.code);
                                    }
                                }

                                // Demonstration
                                wsc.send_json(&json!({
                                    "cmd": "INIT",
                                    "client_id": id,
                                    "msg": "A great day for initialization!"
                                }))
                                .await?;
                                task::sleep(Duration::from_secs(2)).await;
                                wsc.send_json(&json!({
                                    "cmd": "RECV",
                                    "client_id": id,
                                    "msg": "Transaction received"
                                }))
                                .await?;
                                task::sleep(Duration::from_secs(2)).await;
                                wsc.send_json(&json!({
                                    "cmd": "RECV",
                                    "client_id": id,
                                    "msg": "Transaction accepted"
                                }))
                                .await?;
                            }
                            Err(err) => {
                                event!(Level::ERROR, "{:?}", err)
                            }
                        },
                        None => {
                            event!(Level::ERROR, "opt_messages is None.")
                        }
                    };
                }
                Ok(())
            },
        ))
        .get(|_| async { Ok(Body::from_file("./public/index.html").await?) });
    // TODO !corbett Reply with the form filled in.
    app.at("/transfer/:recipient/:amount")
        .get(|req: Request<_>| async move {
            let amount: u64 = req
                .param("amount")?
                .parse()
                .map_err(|err| Error::new(StatusCode::BadRequest, err))?;
            Ok(format!(
                "Recipient: {}, Amount: {}",
                req.param("recipient")?,
                amount
            ))
        });
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("127.0.0.1:{}", port);
    app.listen(addr).await?;
    Ok(())
}
