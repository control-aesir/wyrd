use super::tests_harness::*;
use super::*;
use wyrd_format::ContentId;
use wyrd_format::Entry;
use wyrd_format::FetchStatus;
use wyrd_format::MemoryObjectStore;
use wyrd_format::ObjectKind;

#[test]
fn zero_length_reads_serve_nothing() {
    let drive = small_drive();
    let view = view(drive);
    let file = view.open(&view.lookup("hello.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 0).unwrap(), b"");

    // Even where bytes are absent: no bytes served, nothing to verify.
    let mut store = MemoryObjectStore::default();
    let missing = ContentId::derive(ObjectKind::Chunk, b"withheld");
    let root = tree_of(
        &mut store,
        vec![Entry::file("gone.txt", 8, false, vec![missing]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::with(vec![(missing, FetchStatus::Unavailable(3))]),
        heads(vec![snapshot(root)]),
    );
    let gone = view.open(&view.lookup("gone.txt").unwrap()).unwrap();
    assert_eq!(view.read(&gone, 0, 0).unwrap(), b"");
    assert_eq!(
        view.read(&gone, 0, 8),
        Err(ViewError::Unavailable { content: missing })
    );
}

#[test]
fn ranged_reads_load_only_overlapping_chunks() {
    // A 32-chunk file: chunk i holds byte value i, 10 bytes each.
    // 320 bytes total; chunk boundaries align at multiples of 10.
    let mut inner = MemoryObjectStore::default();
    let mut ids = Vec::new();
    for i in 0..32u8 {
        ids.push(chunk(&mut inner, &[i; 10]));
    }
    let root = tree_of(
        &mut inner,
        vec![Entry::file("wide.bin", 320, false, ids.clone()).unwrap()],
    );
    let store = CountingStore {
        inner,
        gets: std::cell::Cell::new(0),
    };
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );

    let file = view.open(&view.lookup("wide.bin").unwrap()).unwrap();
    // The lookup loaded the root tree; count deltas per read from
    // here so every assertion pins chunk loads only.
    let loads_since = |before: usize| view.store.read().unwrap().gets.get() - before;

    // A small mid-file read touches exactly one chunk's bytes, but chunk
    // sizes are content-defined and unknown without fetching, so the
    // walk loads chunks sequentially from the start: bounded by the
    // offset (16 chunks to reach chunk 15), not by the file.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 155, 3).unwrap();
    assert_eq!(served, vec![15, 15, 15]);
    assert_eq!(loads_since(before), 16, "walk is bounded by the offset");

    // A read spanning a boundary near the start loads only those
    // two chunks.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 8, 4).unwrap();
    assert_eq!(served, vec![0, 0, 1, 1]);
    assert_eq!(loads_since(before), 2, "the range spans two chunks");

    // Reading through EOF walks to the offset, serves to the
    // declared size, and checks the total.
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 312, 100).unwrap();
    assert_eq!(served, vec![31, 31, 31, 31, 31, 31, 31, 31]);
    assert_eq!(loads_since(before), 32, "walk reaches the declared end");

    // The full read loads every chunk (and checks the total).
    let before = view.store.read().unwrap().gets.get();
    let served = view.read(&file, 0, 320).unwrap();
    assert_eq!(served.len(), 320);
    assert_eq!(
        loads_since(before),
        32,
        "whole-file reads are whole-file work"
    );
}

#[test]
fn eof_reads_still_validate_the_whole_file() {
    // Declared 600 bytes, one 5-byte chunk: a non-zero read at and
    // beyond EOF must still report the lying size, not empty
    // success — reads touching the declared end walk the whole list
    // anyway, so they keep full validation.
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"short");
    let root = tree_of(
        &mut store,
        vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 600, 8), Err(ViewError::Corrupt));
    assert_eq!(view.read(&file, 700, 8), Err(ViewError::Corrupt));

    // A zero-size declaration with chunk references is corrupt on
    // any non-zero read, even at EOF.
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"stray");
    let root = tree_of(
        &mut store,
        vec![Entry::file("zero.txt", 0, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("zero.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 4), Err(ViewError::Corrupt));
}

#[test]
fn trailing_chunks_after_the_declared_end_are_corrupt() {
    // The declared size is 5 bytes; the first chunk carries exactly
    // them and a second (valid) chunk trails. A read ending exactly
    // at the declared size must reject the trailing reference.
    let mut store = MemoryObjectStore::default();
    let first = chunk(&mut store, b"exact");
    let extra = chunk(&mut store, b"trailing");
    let root = tree_of(
        &mut store,
        vec![Entry::file("tail.txt", 5, false, vec![first, extra]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 5), Err(ViewError::Corrupt));

    // The same shape with an absent trailing chunk fails on
    // availability, not corruption (the fake materialization
    // reports remote-only for unreferenced content ids).
    let mut store = MemoryObjectStore::default();
    let first = chunk(&mut store, b"exact");
    let absent = ContentId::derive(ObjectKind::Chunk, b"withheld");
    let root = tree_of(
        &mut store,
        vec![Entry::file("tail.txt", 5, false, vec![first, absent]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );
    let file = view.open(&view.lookup("tail.txt").unwrap()).unwrap();
    assert!(matches!(
        view.read(&file, 0, 5),
        Err(ViewError::NotMaterialized { .. })
    ));
}

#[test]
fn lying_size_is_corrupt() {
    let mut store = MemoryObjectStore::default();
    let data = chunk(&mut store, b"short");
    let root = tree_of(
        &mut store,
        vec![Entry::file("lies.txt", 600, false, vec![data]).unwrap()],
    );
    let view = DriveView::new(
        store,
        FakeMaterialization::empty(),
        heads(vec![snapshot(root)]),
    );

    let file = view.open(&view.lookup("lies.txt").unwrap()).unwrap();
    assert_eq!(view.read(&file, 0, 1024), Err(ViewError::Corrupt));
}
