// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use async_std::sync::{Arc, RwLock};
use async_std::task;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::hash_map::{Entry, HashMap};
use std::time::Duration;
use tide::{Body, Request};
use tide_websockets::{Message as WSMessage, WebSocket, WebSocketConnection};

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
                println!("main.rs:send_message: Vacant {}, {}", id, message);
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
        println!("main.rs: Adding connection {}", id);
        let mut connections = self.connections.write().await;
        let connection = Connection { id, wsc };
        connections.insert(id, connection);
        Ok(())
    }
}

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
                println!("main.rs: id: {}", id);
                let nid: u64 = id.parse().expect("id should be an ordinal number.");
                let state = req.state().clone();
                state.add_connection(nid, wsc.clone()).await?;
                state.send_message(nid, "REPORT", "hi, there").await?;
                // TODO !corbett Hmm. Are there other results that are
                // getting dropped, like someone leaving?
                while let Some(Ok(WSMessage::Text(message))) = wsc.next().await {
                    println!("main.rs:WebSocket message: {:?}", message);
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
                Ok(())
            },
        ))
        .get(|_| async { Ok(Body::from_file("./public/index.html").await?) });
    // TODO !corbett Reply with the form filled in.
    // app.at("/transfer/:recipient/:amount")

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("127.0.0.1:{}", port);
    app.listen(addr).await?;
    Ok(())
}
