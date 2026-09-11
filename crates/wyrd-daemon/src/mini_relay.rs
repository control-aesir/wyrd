//! Minimal in-process NIP-01 relay for live-mailbox integration tests.
//!
//! Implements the slice of the relay protocol the mailbox exercises:
//! `EVENT` publish (store, `OK`, broadcast to matching subscriptions),
//! `REQ` subscription (replay + `EOSE`), and `CLOSE`. Deliberately accepts
//! events without signature verification so tests can inject garbage
//! frames; `cfg(test)`-only, never a runtime dependency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::prelude::{Event, Filter};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Publisher/injector requests routed to the relay core task.
enum Command {
    /// A client `EVENT`: store, reply `OK` to the publisher, broadcast.
    Publish {
        event: Event,
        reply: mpsc::UnboundedSender<Message>,
    },
    /// Direct injection: store and broadcast, no client attached.
    Inject(Event),
    Req {
        conn: u64,
        sub_id: String,
        filter: Filter,
        tx: mpsc::UnboundedSender<Message>,
    },
    Close {
        conn: u64,
        sub_id: String,
    },
}

type Frames = mpsc::UnboundedSender<Message>;
type Subs = Arc<Mutex<HashMap<(u64, String), (Frames, Filter)>>>;
type Store = Arc<Mutex<Vec<Event>>>;

/// A tiny websocket relay bound to a random localhost port. Dropping it
/// tears down the listener and all sessions.
pub(crate) struct MiniRelay {
    url: String,
    commands: mpsc::UnboundedSender<Command>,
    /// Declared last so the runtime (and with it the accept and core
    /// tasks) drops last.
    _runtime: Runtime,
}

impl MiniRelay {
    /// Bind on a random localhost port and start serving.
    pub(crate) fn spawn() -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let listener = runtime.block_on(async {
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test relay")
        });
        let url = format!("ws://{}", listener.local_addr().expect("local addr"));

        let (commands, core) = mpsc::unbounded_channel::<Command>();
        let store: Store = Arc::new(Mutex::new(Vec::new()));
        let subs: Subs = Arc::new(Mutex::new(HashMap::new()));

        let listener = Arc::new(listener);
        runtime.spawn(accept_loop(listener, commands.clone()));
        runtime.spawn(core_loop(core, Arc::clone(&store), Arc::clone(&subs)));

        Self {
            url,
            commands,
            _runtime: runtime,
        }
    }

    /// The relay's websocket URL.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Store and broadcast an event without a publishing client; no
    /// signature checks, so tests can inject garbage frames.
    pub(crate) fn inject(&self, event: Event) {
        self.commands
            .send(Command::Inject(event))
            .expect("relay core alive");
    }
}

async fn accept_loop(
    listener: std::sync::Arc<TcpListener>,
    commands: mpsc::UnboundedSender<Command>,
) {
    let mut next_conn: u64 = 0;
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        next_conn += 1;
        let conn = next_conn;
        let commands = commands.clone();
        tokio::spawn(handle_connection(stream, commands, conn));
    }
}

async fn handle_connection(stream: TcpStream, commands: mpsc::UnboundedSender<Command>, conn: u64) {
    eprintln!("[mini-relay] conn {conn} open");
    let Ok(websocket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let (mut sink, mut source) = websocket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink.send(frame).await.is_err() {
                return;
            }
        }
    });

    while let Some(Ok(message)) = source.next().await {
        let Message::Text(text) = message else {
            // Answer protocol-level pings; ignore everything else.
            if let Message::Ping(payload) = message {
                let _ = tx.send(Message::Pong(payload));
            }
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(frame) = value.as_array() else {
            continue;
        };
        match frame.first().and_then(|tag| tag.as_str()) {
            Some("EVENT") if frame.len() == 2 => {
                let Ok(event) = serde_json::from_value::<Event>(frame[1].clone()) else {
                    let _ = tx.send(Message::text(json!(["NOTICE", "bad event"]).to_string()));
                    continue;
                };
                let _ = commands.send(Command::Publish {
                    event,
                    reply: tx.clone(),
                });
            }
            Some("REQ") if frame.len() == 3 => {
                let (Some(sub_id), Ok(filter)) = (
                    frame[1].as_str().map(str::to_owned),
                    serde_json::from_value::<Filter>(frame[2].clone()),
                ) else {
                    continue;
                };
                let _ = commands.send(Command::Req {
                    conn,
                    sub_id,
                    filter,
                    tx: tx.clone(),
                });
            }
            Some("CLOSE") if frame.len() == 2 => {
                if let Some(sub_id) = frame[1].as_str() {
                    let _ = commands.send(Command::Close {
                        conn,
                        sub_id: sub_id.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    writer.abort();
}

async fn core_loop(mut core: mpsc::UnboundedReceiver<Command>, store: Store, subs: Subs) {
    while let Some(command) = core.recv().await {
        match command {
            Command::Publish { event, reply } => {
                let id = event.id.to_hex();
                store.lock().expect("store lock").push(event.clone());
                let _ = reply.send(Message::text(json!(["OK", id, true, ""]).to_string()));
                broadcast(&subs, &event);
            }
            Command::Inject(event) => {
                store.lock().expect("store lock").push(event.clone());
                broadcast(&subs, &event);
            }
            Command::Req {
                conn,
                sub_id,
                filter,
                tx,
            } => {
                for event_json in matching_events(&store, &filter) {
                    let _ = tx.send(event_frame(&sub_id, &event_json));
                }
                let _ = tx.send(Message::text(json!(["EOSE", sub_id]).to_string()));
                subs.lock()
                    .expect("subs lock")
                    .insert((conn, sub_id), (tx, filter));
            }
            Command::Close { conn, sub_id } => {
                subs.lock().expect("subs lock").remove(&(conn, sub_id));
            }
        }
    }
}

fn matching_events(store: &Store, filter: &Filter) -> Vec<String> {
    store
        .lock()
        .expect("store lock")
        .iter()
        .filter(|event| filter.match_event(event, MatchEventOptions::default()))
        .map(|event| event.as_json())
        .collect()
}

fn event_frame(sub_id: &str, event_json: &str) -> Message {
    let event_value: serde_json::Value = serde_json::from_str(event_json).expect("event re-parses");
    Message::text(json!(["EVENT", sub_id, event_value]).to_string())
}

fn broadcast(subs: &Subs, event: &Event) {
    let subs = subs.lock().expect("subs lock");
    let event_value: serde_json::Value =
        serde_json::from_str(&event.as_json()).expect("event re-parses");
    for ((_, sub_id), (tx, filter)) in subs.iter() {
        if filter.match_event(event, MatchEventOptions::default()) {
            let _ = tx.send(Message::text(
                json!(["EVENT", sub_id, event_value]).to_string(),
            ));
        }
    }
}
