// Copyright © 2021 Translucence Research, Inc. All rights reserved.
use async_std::task::block_on;
use std::{net::TcpListener, thread::spawn};
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
};

async fn report_params(req: tide::Request<()>) -> tide::Result<String> {
    tide::log::debug!("Request {:?}", &req);
    let res = format!(
        "Sent {} jellybeans to {}.\n",
        req.param("amt")?,
        req.param("raddr")?
    );
    Ok(res)
}

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    tide::log::start();

    // Initialize and start the HTTP server
    let mut app = tide::new();
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
                let msg = websocket.read_message().unwrap();
                if msg.is_text() {
                    websocket
                        .write_message(format!("{}: {}", counter, msg).into())
                        .unwrap();
                    counter += 1;
                }
            }
        });
    }

    Ok(())
}
