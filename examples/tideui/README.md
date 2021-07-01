# Tide UI

_Example project showing how to read values from a web form with the Tide web application framework_

We're exploring Tide instead of Rocket because Tide uses Rust async, rather than Tokio, which will make Tide easier to integrate with our Hot Stuff implementation.

The application serves a form from a static file. When the user clicks the "Send" button, the values are received by the server and reported in the browser as plain text.

The application uses the WebSocket API for bidirectional communication between the web page and the application server. The "Web Socket Send" button sends a websocket message to the server and displays the server's response in the Status text area.

To recompile and rerun the server automatically after any of the sources change,
you can use catflap and watch as follows (you'll need to `cargo install` them, first).

```
catflap -- cargo watch -x "run tideui"
```


