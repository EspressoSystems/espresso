// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use async_std::prelude::*;
use tide_tracing::TraceMiddleware;
use tide_websockets::{Message, WebSocket};

#[derive(Clone, Debug)]
struct State {
    name: String,
}

async fn report_params(req: tide::Request<State>) -> tide::Result<String> {
    tide::log::debug!("Request {:?}", &req);
    let res = format!(
        "Sent {} jellybeans to {}. {}\n",
        req.param("amt")?,
        req.param("raddr")?,
        req.state().name
    );
    Ok(res)
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let state = State {
        name: "nom nom".to_string(),
    };

    // Initialize and start the HTTP server
    let mut app = tide::with_state(state);
    app.with(TraceMiddleware::new());
    app.at("/working_endpoint")
        .get(|_| async { Ok(tide::Response::new(tide::StatusCode::Ok)) });
    app.at("/client_error")
        .get(|_| async { Ok(tide::Response::new(tide::StatusCode::NotFound)) });
    app.at("/internal_error").get(|_| async {
        tide::Result::<tide::Response>::Err(tide::Error::from_str(
            tide::StatusCode::ServiceUnavailable,
            "This message will be displayed",
        ))
    });

    app.at("/transfer").serve_file("src/transfer.html")?;
    app.at("/transfer/").serve_file("src/transfer.html")?;
    app.at("/transfer/:raddr/:amt").get(report_params);
    app.at("*").get(|_| async { Ok("Whatever") });

    app.at("/as_middleware")
        .with(WebSocket::new(|_request, mut stream| async move {
            while let Some(Ok(Message::Text(input))) = stream.next().await {
                let output: String = input.chars().rev().collect();

                stream
                    .send_string(format!("{} | {}", &input, &output))
                    .await?;
            }

            Ok(())
        }))
        .get(|_| async move { Ok("this was not a websocket request") });

    app.at("/as_endpoint")
        .get(WebSocket::new(|_request, mut stream| async move {
            while let Some(Ok(Message::Text(input))) = stream.next().await {
                let output: String = input.chars().rev().collect();

                stream
                    .send_string(format!("{} | {}", &input, &output))
                    .await?;
            }

            Ok(())
        }));

    app.listen("127.0.0.1:8080").await?;

    Ok(())
}

/*
use async_std::net::TcpListener;
use async_std::task;
use async_tungstenite::tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
};
use std::time::Duration;
use tide_tracing::TraceMiddleware;

#[derive(Clone, Debug)]
struct State {
    name: String,
}

async fn report_params(req: tide::Request<State>) -> tide::Result<String> {
    tide::log::debug!("Request {:?}", &req);
    let res = format!(
        "Sent {} jellybeans to {}. {}\n",
        req.param("amt")?,
        req.param("raddr")?,
        req.state().name
    );
    Ok(res)
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let state = State {
        name: "nom nom".to_string(),
    };

    // Initialize and start the HTTP server
    let mut app = tide::with_state(state);

    app.with(TraceMiddleware::new());

    app.at("/working_endpoint")
        .get(|_| async { Ok(tide::Response::new(tide::StatusCode::Ok)) });
    app.at("/client_error")
        .get(|_| async { Ok(tide::Response::new(tide::StatusCode::NotFound)) });
    app.at("/internal_error").get(|_| async {
        tide::Result::<tide::Response>::Err(tide::Error::from_str(
            tide::StatusCode::ServiceUnavailable,
            "This message will be displayed",
        ))
    });

    app.at("/transfer").serve_file("src/transfer.html")?;
    app.at("/transfer/").serve_file("src/transfer.html")?;
    app.at("/transfer/:raddr/:amt").get(report_params);
    app.at("*").get(|_| async { Ok("Whatever") });
    app.listen("127.0.0.1:8080").await?;

    // From tungstenite server.rs
    // Initialize and start the Web Socket server
    //    let server = TcpListener::bind("127.0.0.1:3012").await.unwrap();
    //    let mut incoming = server.incoming();

    let try_socket = TcpListener::bind("127.0.0.1:3012").await;
    let incoming = try_socket.expect("Failed to bind");

    while let Ok((stream, addr)) = incoming.accept().await {
        let callback = |_req: &Request, response: Response| Ok(response);
        let mut websocket = accept_hdr(stream, callback).unwrap();
        websocket
            .write_message("Web Socket server says hello.".into())
            .unwrap();

        let mut counter: usize = 0;
        loop {
            if let Ok(msg) = websocket.read_message() {
                if msg.is_text() {
                    websocket
                        .write_message(format!("{}: {}", counter, msg).into())
                        .unwrap();
                    counter += 1;
                }
            }
            task::sleep(Duration::from_millis(10)).await;
        }
    }

    Ok(())
}
*/
