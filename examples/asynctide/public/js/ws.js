let socket;
let client_id;

function isOpen() {
    return socket && socket.readyState === socket.OPEN
};

function ioConn() {
    let url = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}${window.location.pathname}`;
    console.log(`ws.js:ioConn url:${url}`);
    if (client_id) url += `?c=${client_id}`;
    if (!isOpen()) socket = new WebSocket(url);
}

function uilog(msg) {
    console.log(`ws.js:uilog:${msg}`);
    let ta = document.getElementById('events');
    if (ta.value.length) { ta.value += '\n'; }
    ta.value += msg;
    ta.scrollTop = ta.scrollHeight;
}

async function ioSend(msg) {
    if (!isOpen()) {
        ioConn();
        // TODO Why half a second? There must be a better condition.
        await new Promise(r => setTimeout(r, 500)); // wait half second to connect
    }
    uilog('ioSend ' + msg);
    socket.send(msg);
}

// TODO leftover
function handleRestartGame() {
    reset_by_me = true;
    ioSend(`RESET:${client_id}`);
}

function cleanUrl() {
    let raddr = document.getElementById("raddr").value;
    let amt = document.getElementById("amt").value;
    return `/transfer/${raddr}/${amt}`;
}

function redirectClean() {
    console.log('redirectClean');
    window.location = cleanUrl();
    return false;
}

function onLoad() {
    (function() {
        socket.onmessage = function(msg) {
            console.log(`ws.js:socket.onmessage:${msg.data}`);
            const data = JSON.parse(msg.data);
            uilog(`Got socket message: client_id:${data.client_id} msg:${data.msg}.`);
        };
        uilog('Web Socket enabled.');
    })();
}
function onSend(){
    uilog('Web Socket Send button pressed');
    socket.send('Web Socket Send button pressed:' + cleanUrl());
}

document.addEventListener("DOMContentLoaded", function() {
    console.log('ws.js:Adding event listener for DOMContentLoaded');

    ioConn();

    socket.addEventListener('message', message => {
        const data = JSON.parse(message.data);
        console.log(`ws.js: message event listener: client_id:${data.client_id} msg:${data.msg}`);

        switch (data.cmd) {
        case 'INIT':
            console.log(`ws.js:Server sent INIT for client ${data.client_id}`);
            client_id = data.client_id;
            break;
        case 'STATE':
            gameState = data.play_book;
            // redraw
            redrawPlayBook();
            if (!handleResultValidation() ) handlePlayerChange();
            transfer_state = cleanUrl();

            ioSend(`TRANSFER:${localPlayer}:${transfer_state}`);

            break;
        case 'RESET':
            console.log('ws.js:reset');
            if( ! reset_by_me ) alert( 'Other player just RESET the game' );

            gameState = data.play_book;
            // redraw
            redrawPlayBook();
            handlePlayerChange();
            gameActive = localPlayer === currentPlayer ? true : false;
            reset_by_me = false;
            break;
        case 'COMPLETE':
            console.log('ws.js:COMPLETE');
            alert( 'Oops... board complete!' );
            statusDisplay.innerHTML = COMPLETE_MSG;
            statusDisplay.classList.add("complete");
            document.querySelector('.game--restart').classList.add("hidden");
            gameActive = false;
            break;
        case 'LEAVE':
            console.log('ws.js:leave');
            alert('ws.js:Got LEAVE from other client');
            break;
        case 'TRANSFER':
            uilog('TRANSFER ' + data.xfr);
            break;
        default:
            console.log('ws.js: Received a message without a cmd field.');
        };
    });
});

window.addEventListener('beforeunload', function(event) {
    ioSend(`LEAVE:${client_id}`);
});

window.addEventListener("load", onLoad);
ioSend('play');
