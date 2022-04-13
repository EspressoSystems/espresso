// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use async_std::sync::{Arc, RwLock};
use async_std::task;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::hash_map::{Entry, HashMap};
use std::time::Duration;
use tide::{Body, Request};
use tide_websockets::async_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tide_websockets::{Message::Close, WebSocket, WebSocketConnection};
use tracing::{event, Level};

#[derive(Clone)]
struct Connection {
    wsc: WebSocketConnection,
}

#[derive(Clone)]
struct State {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
}

impl State {
    fn new() -> Self {
        Self {
            connections: Default::default(),
        }
    }

    async fn add_connection(&self, id: &str, wsc: WebSocketConnection) -> tide::Result<()> {
        event!(Level::DEBUG, "main.rs: Adding connection {}", &id);
        let mut connections = self.connections.write().await;
        let connection = Connection { wsc };
        connections.insert(id.to_string(), connection);
        Ok(())
    }

    async fn remove_connection(&self, id: &str) -> tide::Result<()> {
        event!(Level::DEBUG, "main.rs: Removing connection {}", id);
        let mut connections = self.connections.write().await;
        connections.remove(id);
        Ok(())
    }

    async fn send_message(&self, id: &str, cmd: &str, message: &str) -> tide::Result<()> {
        let mut connections = self.connections.write().await;
        match connections.entry(id.to_string()) {
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
                    .send_json(&json!({"clientId": id, "cmd": cmd, "msg": message }))
                    .await?
            }
        }
        Ok(())
    }

    /// Currently a demonstration of messages with delays to suggest processing time.
    async fn report_transaction_status(&self, id: &str) -> tide::Result<()> {
        task::sleep(Duration::from_secs(2)).await;
        self.send_message(id, "FOO", "Here it is.").await?;
        self.send_message(id, "INIT", "Something something").await?;
        task::sleep(Duration::from_secs(2)).await;
        self.send_message(id, "RECV", "Transaction received")
            .await?;
        task::sleep(Duration::from_secs(2)).await;
        self.send_message(id, "RECV", "Transaction accepted")
            .await?;
        Ok(())
    }
}

async fn landing_page(_: Request<State>) -> Result<Body, tide::Error> {
    Ok(Body::from_file("./public/index.html").await?)
}

async fn handle_web_socket(req: Request<State>, mut wsc: WebSocketConnection) -> tide::Result<()> {
    event!(Level::DEBUG, "main.rs: id: {}", &req.param("id")?);
    let id = req.param("id").expect("Route must include :id parameter.");
    let state = req.state().clone();
    state.add_connection(id, wsc.clone()).await?;
    state
        .send_message(id, "RPT", "Server says, \"Hi!\"")
        .await?;
    loop {
        let opt_message = wsc.next().await;
        match opt_message {
            Some(result_message) => match result_message {
                Ok(message) => {
                    event!(Level::DEBUG, "main.rs:WebSocket message: {:?}", message);
                    if let Close(Some(cf)) = message {
                        // See https://docs.rs/tungstenite/0.14.0/tungstenite/protocol/frame/coding/enum.CloseCode.html
                        if cf.code == CloseCode::Away {
                            event!(Level::DEBUG, "main.rs:cf Client said goodbye.");
                            state.remove_connection(id).await?;
                            break;
                        } else {
                            event!(Level::DEBUG, "main.rs:cf {:?}", &cf.code);
                        }
                    }

                    // Demonstration
                    state.report_transaction_status(id).await?;
                }
                Err(err) => {
                    event!(Level::ERROR, "WebSocket stream: {:?}", err)
                }
            },
            None => {
                event!(Level::ERROR, "main.rs: Client left without saying goodbye.");
                state.remove_connection(id).await?;
                break;
            }
        };
    }
    Ok(())
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let mut app = tide::with_state(State::new());
    app.at("/public").serve_dir("./public/")?;
    app.at("/").get(landing_page);
    app.at("/:id")
        .with(WebSocket::new(handle_web_socket))
        .get(landing_page);
    // TODO !corbett Reply with the form filled in.
    app.at("/transfer/:id/:recipient/:amount")
        .with(WebSocket::new(handle_web_socket))
        // .get(index_page);
        .get(landing_page);
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("127.0.0.1:{}", port);
    app.listen(addr).await?;
    Ok(())
}
