//
use tide::Request;

async fn echo(req: Request<()>) -> tide::Result<String> {
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
    let mut app = tide::new();
    app.at("/transfer").serve_file("src/transfer.html")?;
    app.at("/transfer/").serve_file("src/transfer.html")?;
    app.at("/transfer/:raddr/:amt").get(echo);
    app.at("*").get(|_| async { Ok("Whatever") });
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}
