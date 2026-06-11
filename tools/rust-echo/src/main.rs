// Thread-per-connection tungstenite echo — the library's documented
// server shape (tungstenite is sync; tokio-tungstenite adds the reactor).
use std::net::TcpListener;
use std::thread;
use tungstenite::accept;

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(9002);
    let server = TcpListener::bind(("0.0.0.0", port)).unwrap();
    println!("listening on {}", port);
    for stream in server.incoming() {
        thread::spawn(move || {
            let stream = stream.unwrap();
            stream.set_nodelay(true).ok();
            let mut ws = match accept(stream) { Ok(w) => w, Err(_) => return };
            loop {
                match ws.read() {
                    Ok(msg) if msg.is_text() || msg.is_binary() => {
                        if ws.send(msg).is_err() { break; }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
}
