//! Mount-free live reads against a scriptable view: the surface
//! proves itself without FUSE, a loop, or a real store.

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use wyrd_format::{ContentId, FetchStatus, MemoryObjectStore, ObjectKind};

use crate::quarantine::QuarantineQueue;
use crate::scrub::ScrubQueue;
use crate::view::{Attr, DirEntry, Head, Kind, MaterializationPolicy, Node, ViewLockError};
use crate::want::WantRegistry;

/// Residency is scripted per read call below; the policy stays
/// trivially local so every demand verdict comes from the fake.
struct AllLocal;

impl MaterializationPolicy for AllLocal {
    fn status(&self, _id: &ContentId) -> FetchStatus {
        FetchStatus::Available
    }
}

/// How one path reads. `RemoteOnly` flips to served when the test
/// sets its flag, simulating the fetch landing mid-wait.
enum Outcome {
    Served(Vec<u8>),
    RemoteOnly {
        fulfill: Arc<AtomicBool>,
        bytes: Vec<u8>,
    },
    Unavailable(Vec<u8>),
    Corrupt(Vec<u8>),
    Rejected(Vec<u8>),
    Lost(Vec<u8>),
}

impl Outcome {
    fn bytes(&self) -> &[u8] {
        match self {
            Outcome::Served(bytes)
            | Outcome::RemoteOnly { bytes, .. }
            | Outcome::Unavailable(bytes)
            | Outcome::Corrupt(bytes)
            | Outcome::Rejected(bytes)
            | Outcome::Lost(bytes) => bytes,
        }
    }
}

struct FakeView {
    files: Mutex<BTreeMap<String, Outcome>>,
    store: Arc<RwLock<MemoryObjectStore>>,
}

impl FakeView {
    fn file_id(path: &str) -> ContentId {
        let mut bytes = [0xF1; 32];
        let raw = path.as_bytes();
        let take = raw.len().min(31);
        bytes[1..1 + take].copy_from_slice(&raw[..take]);
        ContentId::from_bytes(bytes)
    }

    fn outcome(&self, path: &str) -> Option<std::sync::MutexGuard<'_, BTreeMap<String, Outcome>>> {
        let guard = self.files.lock().ok()?;
        guard.contains_key(path).then_some(guard)
    }
}

impl NamespaceView for FakeView {
    type Store = MemoryObjectStore;
    type Materialization = AllLocal;

    fn open(
        store: Self::Store,
        _materialization: Self::Materialization,
        _heads: Vec<Head>,
    ) -> Self {
        FakeView {
            files: Mutex::new(BTreeMap::new()),
            store: Arc::new(RwLock::new(store)),
        }
    }

    fn open_shared(
        store: Arc<RwLock<Self::Store>>,
        _materialization: Self::Materialization,
        _heads: Vec<Head>,
    ) -> Self {
        FakeView {
            files: Mutex::new(BTreeMap::new()),
            store,
        }
    }

    fn store_handle(&self) -> Arc<RwLock<Self::Store>> {
        Arc::clone(&self.store)
    }

    fn store_read(&self) -> Result<RwLockReadGuard<'_, Self::Store>, ViewLockError> {
        self.store.read().map_err(|_| ViewLockError)
    }

    fn store_write(&self) -> Result<RwLockWriteGuard<'_, Self::Store>, ViewLockError> {
        self.store.write().map_err(|_| ViewLockError)
    }

    fn set_heads(&mut self, _heads: Vec<Head>) {}

    fn set_materialization(&mut self, _materialization: Self::Materialization) {}

    fn status(&self, _id: &ContentId) -> FetchStatus {
        FetchStatus::Available
    }

    fn lookup(&self, path: &str) -> Result<Node, ViewError> {
        let guard = self.outcome(path).ok_or(ViewError::NotFound)?;
        let outcome = guard.get(path).ok_or(ViewError::NotFound)?;
        Ok(Node::File {
            size: outcome.bytes().len() as u64,
            executable: false,
            chunks: vec![Self::file_id(path)],
        })
    }

    fn stat(&self, path: &str) -> Result<Attr, ViewError> {
        let node = self.lookup(path)?;
        match node {
            Node::File { size, .. } => Ok(Attr {
                kind: Kind::File,
                size,
                executable: false,
            }),
            _ => Err(ViewError::NotAFile),
        }
    }

    fn readdir(&self, _node: &Node) -> Result<Vec<DirEntry>, ViewError> {
        Err(ViewError::NotADirectory)
    }

    fn open_file(&self, node: &Node) -> Result<OpenFile, ViewError> {
        let (size, chunks) = match node {
            Node::File { size, chunks, .. } => (*size, chunks.clone()),
            _ => return Err(ViewError::NotAFile),
        };
        // The chunk id encodes the path hash; recover the path by
        // scanning the table for the matching identity.
        let guard = self.files.lock().map_err(|_| {
            ViewError::Store(wyrd_format::StoreFailure::Transient, "fake lock".into())
        })?;
        let (path, outcome) = guard
            .iter()
            .find(|(path, _)| Self::file_id(path) == chunks[0])
            .ok_or(ViewError::NotFound)?;
        let content = Self::file_id(path);
        match outcome {
            Outcome::Served(_) => Ok(OpenFile::new(chunks, size)),
            Outcome::RemoteOnly { fulfill, .. } if fulfill.load(Ordering::SeqCst) => {
                Ok(OpenFile::new(chunks, size))
            }
            Outcome::RemoteOnly { .. } => Err(ViewError::NotMaterialized { content }),
            Outcome::Unavailable(_) => Err(ViewError::Unavailable { content }),
            Outcome::Corrupt(_) => Err(ViewError::Corrupt),
            Outcome::Rejected(_) => Err(ViewError::RejectedRepresentation {
                content,
                kind: ObjectKind::Chunk,
            }),
            Outcome::Lost(_) => Err(ViewError::LostRepresentation {
                content,
                kind: ObjectKind::Chunk,
            }),
        }
    }

    fn read(&self, file: &OpenFile, offset: u64, len: usize) -> Result<Vec<u8>, ViewError> {
        let guard = self.files.lock().map_err(|_| {
            ViewError::Store(wyrd_format::StoreFailure::Transient, "fake lock".into())
        })?;
        let (path, outcome) = guard
            .iter()
            .find(|(path, _)| Self::file_id(path) == file.chunks()[0])
            .ok_or(ViewError::NotFound)?;
        let bytes = match outcome {
            Outcome::Served(bytes) => bytes,
            Outcome::RemoteOnly { fulfill, bytes } if fulfill.load(Ordering::SeqCst) => bytes,
            Outcome::RemoteOnly { .. } => {
                return Err(ViewError::NotMaterialized {
                    content: Self::file_id(path),
                })
            }
            Outcome::Unavailable(_) => {
                return Err(ViewError::Unavailable {
                    content: Self::file_id(path),
                })
            }
            Outcome::Corrupt(_) => return Err(ViewError::Corrupt),
            Outcome::Rejected(_) => {
                return Err(ViewError::RejectedRepresentation {
                    content: Self::file_id(path),
                    kind: ObjectKind::Chunk,
                })
            }
            Outcome::Lost(_) => {
                return Err(ViewError::LostRepresentation {
                    content: Self::file_id(path),
                    kind: ObjectKind::Chunk,
                })
            }
        };
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }
}

fn reader_with_wants(timeout: Duration) -> (LiveReader, Arc<WantRegistry>) {
    let wants = Arc::new(WantRegistry::default());
    let reader = LiveReader::new(timeout).with_wants(Arc::clone(&wants));
    (reader, wants)
}

fn view_with(files: Vec<(&str, Outcome)>) -> FakeView {
    let view = FakeView::open(MemoryObjectStore::default(), AllLocal, Vec::new());
    let mut guard = view.files.lock().unwrap();
    for (path, outcome) in files {
        guard.insert(path.to_string(), outcome);
    }
    drop(guard);
    view
}

#[test]
fn read_served_file_returns_bytes_without_demand() {
    let view = view_with(vec![("/a", Outcome::Served(b"hello".to_vec()))]);
    let reader = LiveReader::new(Duration::from_secs(5));
    assert_eq!(reader.read_file(&view, "/a").unwrap(), b"hello");
}

#[test]
fn read_remote_only_blocks_until_fetch_lands() {
    let fulfill = Arc::new(AtomicBool::new(false));
    let view = view_with(vec![(
        "/a",
        Outcome::RemoteOnly {
            fulfill: Arc::clone(&fulfill),
            bytes: b"landed".to_vec(),
        },
    )]);
    let (reader, _wants) = reader_with_wants(Duration::from_secs(10));
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        fulfill.store(true, Ordering::SeqCst);
    });
    let bytes = reader.read_file(&view, "/a").unwrap();
    flipper.join().unwrap();
    assert_eq!(bytes, b"landed");
}

#[test]
fn read_remote_only_times_out_bounded_without_fetch() {
    let view = view_with(vec![(
        "/a",
        Outcome::RemoteOnly {
            fulfill: Arc::new(AtomicBool::new(false)),
            bytes: b"never".to_vec(),
        },
    )]);
    let (reader, _wants) = reader_with_wants(Duration::from_millis(120));
    match reader.read_file(&view, "/a") {
        Err(ReadError::Timeout { .. }) => {}
        other => panic!("expected bounded timeout, got {other:?}"),
    }
}

#[test]
fn read_terminal_unavailable_fails_fast_and_notes_reopen() {
    let view = view_with(vec![("/a", Outcome::Unavailable(b"gone".to_vec()))]);
    let (reader, wants) = reader_with_wants(Duration::from_secs(5));
    match reader.read_file(&view, "/a") {
        Err(ReadError::Terminal(ViewError::Unavailable { .. })) => {}
        other => panic!("expected fast terminal, got {other:?}"),
    }
    let content = FakeView::file_id("/a");
    assert!(wants.take_reopen_notes().contains(&content));
}

#[test]
fn read_terminal_corrupt_fails_fast_without_reopen_note() {
    let view = view_with(vec![("/a", Outcome::Corrupt(b"doomed".to_vec()))]);
    let (reader, wants) = reader_with_wants(Duration::from_secs(5));
    match reader.read_file(&view, "/a") {
        Err(ReadError::Terminal(ViewError::Corrupt)) => {}
        other => panic!("expected fast terminal corrupt, got {other:?}"),
    }
    // Corrupt notes nothing: its repair is quarantine's job, not
    // rewant's, so the generation sweep stays shut.
    assert!(wants.take_reopen_notes().is_empty());
}

#[test]
fn read_lost_names_scrub_and_heals_when_served() {
    let view = Arc::new(view_with(vec![("/a", Outcome::Lost(b"healed".to_vec()))]));
    let scrub = Arc::new(ScrubQueue::default());
    let (reader, _wants) = reader_with_wants(Duration::from_secs(10));
    let reader = reader.with_repair(Arc::new(QuarantineQueue::default()), Arc::clone(&scrub));
    let healer_view = Arc::clone(&view);
    let healer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        healer_view
            .files
            .lock()
            .unwrap()
            .insert("/a".to_string(), Outcome::Served(b"healed".to_vec()));
    });
    let bytes = reader.read_file(&*view, "/a").unwrap();
    healer.join().unwrap();
    assert_eq!(bytes, b"healed");
    assert!(!scrub.is_empty());
}

#[test]
fn read_unavailable_behind_recent_repair_waits_it_out() {
    let view = Arc::new(view_with(vec![(
        "/a",
        Outcome::Rejected(b"healed".to_vec()),
    )]));
    let reader = LiveReader::new(Duration::from_secs(10))
        .with_wants(Arc::new(WantRegistry::default()))
        .with_repair(
            Arc::new(QuarantineQueue::default()),
            Arc::new(ScrubQueue::default()),
        );
    // Seed the repair note with a real observation: the rejection
    // heals mid-wait, and the note outlives the call.
    let seeder_view = Arc::clone(&view);
    let seeder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        seeder_view
            .files
            .lock()
            .unwrap()
            .insert("/a".to_string(), Outcome::Served(b"healed".to_vec()));
    });
    assert_eq!(reader.read_file(&*view, "/a").unwrap(), b"healed");
    seeder.join().unwrap();
    // The verdict flips to terminal behind the stale projection,
    // then the repair lands: the waiter saw this repair moments ago,
    // so it must wait it out, not fail fast on the stale view. (The
    // no-note case fails fast instead — pinned by the terminal test
    // above.)
    view.files
        .lock()
        .unwrap()
        .insert("/a".to_string(), Outcome::Unavailable(b"healed".to_vec()));
    let healer_view = Arc::clone(&view);
    let healer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        healer_view
            .files
            .lock()
            .unwrap()
            .insert("/a".to_string(), Outcome::Served(b"healed".to_vec()));
    });
    let bytes = reader.read_file(&*view, "/a").unwrap();
    healer.join().unwrap();
    assert_eq!(bytes, b"healed");
}

#[test]
fn read_missing_path_maps_lookup_error() {
    let view = view_with(vec![]);
    let reader = LiveReader::new(Duration::from_secs(5));
    match reader.read_file(&view, "/missing") {
        Err(ReadError::View(ViewError::NotFound)) => {}
        other => panic!("expected NotFound passthrough, got {other:?}"),
    }
}

#[test]
fn read_rejected_names_quarantine_and_heals_when_served() {
    let view = Arc::new(view_with(vec![(
        "/a",
        Outcome::Rejected(b"healed".to_vec()),
    )]));
    let quarantine = Arc::new(QuarantineQueue::default());
    let (reader, _wants) = reader_with_wants(Duration::from_secs(10));
    let reader = reader.with_repair(Arc::clone(&quarantine), Arc::new(ScrubQueue::default()));
    // Repair lands mid-wait: the rejection becomes served bytes.
    let healer_view = Arc::clone(&view);
    let healer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        healer_view
            .files
            .lock()
            .unwrap()
            .insert("/a".to_string(), Outcome::Served(b"healed".to_vec()));
    });
    let bytes = reader.read_file(&*view, "/a").unwrap();
    healer.join().unwrap();
    assert_eq!(bytes, b"healed");
    assert!(!quarantine.is_empty());
}
