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
use tokio::task::JoinHandle;
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

/// Task handles for one serving episode. Aborting them kills the listener
/// loop, the core loop, and every open connection; the bound socket and
/// the event store live outside, so a later restart serves the same URL
/// with the same history — a faithful relay outage and reboot.
struct Serving {
    commands: mpsc::UnboundedSender<Command>,
    accept: JoinHandle<()>,
    core: JoinHandle<()>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

fn abort_serving(serving: Serving) {
    serving.accept.abort();
    serving.core.abort();
    if let Ok(mut connections) = serving.connections.lock() {
        for conn in connections.drain(..) {
            conn.abort();
        }
    }
}

/// A tiny websocket relay bound to a random localhost port. Dropping it
/// tears down the listener and all sessions; [`shutdown`](Self::shutdown)
/// stops serving while keeping the socket bound (and the history stored)
/// so [`restart`](Self::restart) resumes on the same URL.
pub(crate) struct MiniRelay {
    url: String,
    listener: Arc<TcpListener>,
    store: Store,
    subs: Subs,
    serving: Mutex<Option<Serving>>,
    /// Declared last so the runtime (and with it any serving tasks)
    /// drops last.
    runtime: Runtime,
}

impl Drop for MiniRelay {
    fn drop(&mut self) {
        // Best-effort: the runtime drop would abort these anyway, but an
        // explicit abort keeps a mid-flight shutdown deterministic.
        if let Ok(mut serving) = self.serving.lock() {
            if let Some(episode) = serving.take() {
                abort_serving(episode);
            }
        }
    }
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

        let store: Store = Arc::new(Mutex::new(Vec::new()));
        let subs: Subs = Arc::new(Mutex::new(HashMap::new()));

        let relay = Self {
            url,
            listener: Arc::new(listener),
            store,
            subs,
            serving: Mutex::new(None),
            runtime,
        };
        relay.restart();
        relay
    }

    /// Stop serving: abort the accept loop, the core loop, and every open
    /// connection. Connected clients observe a hard disconnect; the bound
    /// socket and the stored history survive for a later [`restart`](Self::restart).
    pub(crate) fn shutdown(&self) {
        if let Ok(mut serving) = self.serving.lock() {
            if let Some(episode) = serving.take() {
                abort_serving(episode);
            }
        }
    }

    /// Serve again on the same URL with the same history. Pre-outage
    /// subscriptions reference dead connections, so they are cleared —
    /// clients must re-REQ exactly as after a real relay reboot, and the
    /// replay they get exercises the consumer's dedupe.
    pub(crate) fn restart(&self) {
        self.shutdown();
        self.subs.lock().expect("subs lock").clear();
        let (commands, core) = mpsc::unbounded_channel::<Command>();
        let connections: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let accept = self.runtime.spawn(accept_loop(
            Arc::clone(&self.listener),
            commands.clone(),
            Arc::clone(&connections),
        ));
        let core = self.runtime.spawn(core_loop(
            core,
            Arc::clone(&self.store),
            Arc::clone(&self.subs),
        ));
        *self.serving.lock().expect("relay lock") = Some(Serving {
            commands,
            accept,
            core,
            connections,
        });
    }

    /// The relay's websocket URL.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Store and broadcast an event without a publishing client; no
    /// signature checks, so tests can inject garbage frames. Panics while
    /// the relay is shut down — tests only ever inject into a serving relay.
    pub(crate) fn inject(&self, event: Event) {
        self.serving
            .lock()
            .expect("relay lock")
            .as_ref()
            .expect("relay serving")
            .commands
            .send(Command::Inject(event))
            .expect("relay core alive");
    }
}

async fn accept_loop(
    listener: std::sync::Arc<TcpListener>,
    commands: mpsc::UnboundedSender<Command>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let mut next_conn: u64 = 0;
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        next_conn += 1;
        let conn = next_conn;
        let commands = commands.clone();
        let handle = tokio::spawn(handle_connection(stream, commands, conn));
        if let Ok(mut connections) = connections.lock() {
            connections.retain(|handle| !handle.is_finished());
            connections.push(handle);
        }
    }
}

async fn handle_connection(stream: TcpStream, commands: mpsc::UnboundedSender<Command>, conn: u64) {
    eprintln!("[mini-relay] conn {conn} open");
    let Ok(websocket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let (mut sink, mut source) = websocket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // One task drives the socket and the outbound queue together, so
    // aborting the connection task always closes the socket: a split-off
    // writer task would survive the abort and hold the connection
    // half-open, hiding the outage from the client.
    loop {
        tokio::select! {
            frame = rx.recv() => {
                let Some(frame) = frame else {
                    return;
                };
                if sink.send(frame).await.is_err() {
                    return;
                }
            }
            message = source.next() => {
                if !handle_message(message, &commands, &tx, conn) {
                    return;
                }
            }
        }
    }
}

/// Handle one inbound websocket frame. Returns false when the connection
/// is over and the task should exit (closing the socket).
fn handle_message(
    message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    commands: &mpsc::UnboundedSender<Command>,
    tx: &mpsc::UnboundedSender<Message>,
    conn: u64,
) -> bool {
    let Some(Ok(message)) = message else {
        return false;
    };
    let Message::Text(text) = message else {
        // Answer protocol-level pings; ignore everything else.
        if let Message::Ping(payload) = message {
            let _ = tx.send(Message::Pong(payload));
        }
        return true;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return true;
    };
    let Some(frame) = value.as_array() else {
        return true;
    };
    match frame.first().and_then(|tag| tag.as_str()) {
        Some("EVENT") if frame.len() == 2 => {
            let Ok(event) = serde_json::from_value::<Event>(frame[1].clone()) else {
                let _ = tx.send(Message::text(json!(["NOTICE", "bad event"]).to_string()));
                return true;
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
                return true;
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
    true
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

/// Frame one stored event for a subscription. String-interpolates the
/// already-serialized event instead of parsing and re-serializing it:
/// identical bytes on the wire, a third of the fake's CPU per replay.
fn event_frame(sub_id: &str, event_json: &str) -> Message {
    Message::text(format!(
        "[\"EVENT\",{},{}]",
        serde_json::to_string(sub_id).expect("sub id serializes"),
        event_json
    ))
}

fn broadcast(subs: &Subs, event: &Event) {
    let subs = subs.lock().expect("subs lock");
    let event_json = event.as_json();
    for ((_, sub_id), (tx, filter)) in subs.iter() {
        if filter.match_event(event, MatchEventOptions::default()) {
            let _ = tx.send(event_frame(sub_id, &event_json));
        }
    }
}
