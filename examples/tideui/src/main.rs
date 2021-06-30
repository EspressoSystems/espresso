// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use async_std::task::block_on;
use std::{net::TcpListener, thread::spawn};
use tide;
use tide_tracing::TraceMiddleware;
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
};

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
    //    let mut app = tide::Server::new();
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
    spawn(move || block_on(app.listen("127.0.0.1:8080")));

    // From tungstenite server.rs
    // Initialize and start the Web Socket server
    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    for stream in server.incoming() {
        spawn(move || {
            let callback = |_req: &Request, response: Response| Ok(response);
            let mut websocket = accept_hdr(stream.unwrap(), callback).unwrap();
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
            }
        });
    }

    Ok(())
}
