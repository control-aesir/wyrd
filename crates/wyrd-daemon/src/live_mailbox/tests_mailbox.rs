use super::tests_harness::{device_id, envelope, keys, offline_mailbox, temp_path};
use super::*;
use nostr::event::FinalizeEvent;

use std::time::Duration;

/// A poisoned channel lock fails the drain pass instead of panicking
/// the process: poison means a thread panicked mid-critical-section,
/// and serving threads fail the operation, never the process.
#[test]
fn poisoned_channel_lock_fails_recv() {
    let open = keys();
    let mut mailbox = offline_mailbox(&open);
    let incoming = Arc::clone(&mailbox.incoming);
    let poisoner = std::thread::spawn(move || {
        let _guard = incoming.lock().unwrap();
        panic!("poison the channel lock");
    });
    let _ = poisoner.join();
    assert!(
        matches!(mailbox.recv(), Err(MailboxError::Transport(_))),
        "a poisoned channel lock must fail recv, not panic"
    );
}

/// Minting past u64::MAX fails instead of panicking: unreachable in
/// practice, but a violated assumption is a recoverable error.
#[test]
fn exhausted_delivery_ids_fail() {
    let open = keys();
    let mut mailbox = offline_mailbox(&open);
    mailbox.next_delivery = u64::MAX;
    assert!(
        matches!(mailbox.mint_delivery_id(), Err(MailboxError::Transport(_))),
        "an exhausted id space must fail, not panic"
    );
}

#[test]
fn recovery_backoff_doubles_to_a_thirty_second_cap() {
    let delays = [
        recovery_delay(0),
        recovery_delay(1),
        recovery_delay(2),
        recovery_delay(3),
        recovery_delay(4),
        recovery_delay(5),
        recovery_delay(6),
        recovery_delay(u32::MAX),
    ];
    assert_eq!(
        delays,
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ]
    );
}

#[test]
fn offline_mailbox_reports_live_without_relays() {
    // No relays means offline boundary use: liveness is stream-alive
    // alone, and a relay outage is not a state an offline mailbox can
    // be in.
    let open = keys();
    let mailbox = offline_mailbox(&open);
    let health = mailbox.health();
    assert!(health.stream_alive);
    assert_eq!(health.connected_relays, 0);
    assert_eq!(health.total_relays, 0);
    assert!(health.is_live());
}

#[test]
fn seen_store_opens_missing_file_and_persists_acks() {
    let path = temp_path("seen-fresh");
    let _ = std::fs::remove_file(&path);
    let id = EventId::from_byte_array([0u8; 32]);
    {
        let mut store = SeenStore::open(&path).unwrap();
        assert!(!store.contains(&id));
        store.record(&id).unwrap();
    }
    let store = SeenStore::open(&path).unwrap();
    assert!(store.contains(&id));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn dedupe_log_fails_closed_on_read_error() {
    // A directory instead of a file: reading it fails with an I/O
    // error (not NotFound), which must refuse startup rather than
    // start an empty ledger and replay acknowledged wraps.
    let dir = temp_path("seen-dir");
    std::fs::create_dir(&dir).unwrap();
    let error = SeenStore::open(&dir).unwrap_err();
    assert!(matches!(error, MailboxError::Transport(_)));
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn dedupe_log_fails_closed_on_invalid_utf8() {
    let path = temp_path("seen-utf8");
    std::fs::write(&path, b"\xff\xfe\xfd\n").unwrap();
    let error = SeenStore::open(&path).unwrap_err();
    assert!(matches!(error, MailboxError::Transport(_)));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn dedupe_log_fails_closed_on_corrupt_line() {
    let path = temp_path("seen-corrupt");
    std::fs::write(&path, "not-a-hex-id\n").unwrap();
    let error = SeenStore::open(&path).unwrap_err();
    assert!(matches!(error, MailboxError::Transport(_)));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn dedupe_log_truncates_torn_tail_and_stays_appendable() {
    let path = temp_path("seen-torn");
    let first = EventId::from_byte_array([1u8; 32]);
    let second = EventId::from_byte_array([2u8; 32]);
    {
        let mut store = SeenStore::open(&path).unwrap();
        store.record(&first).unwrap();
        // Crash mid-append: the torn tail never synced, so it must be
        // truncated away — both to skip the bogus entry and so later
        // appends cannot weld a fresh id onto it.
        use std::io::Write;
        store.file.write_all(b"deadbeef").unwrap();
    }
    {
        let mut store = SeenStore::open(&path).expect("torn tail recovers");
        assert!(store.contains(&first));
        assert!(!store.contains(&second));
        store.record(&second).unwrap();
    }
    let store = SeenStore::open(&path).unwrap();
    assert!(store.contains(&first));
    assert!(store.contains(&second));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn well_formed_wrap_yields_envelope() {
    let sender = keys();
    let open = keys();
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "sealed control bytes")
        .tag(Tag::public_key(open.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let mailbox = offline_mailbox(&open);
    let envelope = mailbox.envelope_from_wrap(&wrap).expect("valid wrap");
    assert_eq!(envelope.sender, device_id(&sender));
    assert_eq!(envelope.recipient, device_id(&open));
    assert_eq!(envelope.ciphertext, "sealed control bytes");
}

#[test]
fn wrong_rumor_kind_rejected() {
    let sender = keys();
    let open = keys();
    let rumor = EventBuilder::new(Kind::TextNote, "not wyrd")
        .tag(Tag::public_key(open.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let mailbox = offline_mailbox(&open);
    assert!(mailbox.envelope_from_wrap(&wrap).is_err());
}

#[test]
fn foreign_rumor_recipient_rejected() {
    // Wrapped to us, but the Wyrd rumor addresses a different device:
    // malformed for this mailbox even though it decrypts.
    let sender = keys();
    let open = keys();
    let foreign = keys();
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "misfiled")
        .tag(Tag::public_key(foreign.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let mailbox = offline_mailbox(&open);
    assert!(mailbox.envelope_from_wrap(&wrap).is_err());
}

#[test]
fn foreign_wrap_recipient_rejected() {
    // A wrap whose routing tag points elsewhere must be refused
    // before any decryption work, not treated as addressed to us.
    let sender = keys();
    let open = keys();
    let foreign = keys();
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "elsewhere")
        .tag(Tag::public_key(foreign.public_key()))
        .finalize_unsigned(sender.public_key());
    let wrap = GiftWrapBuilder::new(foreign.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let mailbox = offline_mailbox(&open);
    assert!(mailbox.envelope_from_wrap(&wrap).is_err());
}

#[test]
fn impersonated_rumor_rejected() {
    // The rumor claims a different author than the seal's signer:
    // NIP-59 unwrap must fail, so relay metadata can never mint a
    // sender identity.
    let sender = keys();
    let open = keys();
    let impostor = keys();
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "spoofed")
        .tag(Tag::public_key(open.public_key()))
        .finalize_unsigned(impostor.public_key());
    let wrap = GiftWrapBuilder::new(open.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let mailbox = offline_mailbox(&open);
    assert!(mailbox.envelope_from_wrap(&wrap).is_err());
}

#[test]
fn tampered_wrap_rejected() {
    let sender = keys();
    let open = keys();
    let rumor = EventBuilder::new(Kind::Custom(RUMOR_KIND), "payload")
        .tag(Tag::public_key(open.public_key()))
        .finalize_unsigned(sender.public_key());
    let mut wrap = GiftWrapBuilder::new(open.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    // Any mutation invalidates the wrapper signature.
    wrap.created_at = wrap.created_at + Duration::from_secs(1);
    let mailbox = offline_mailbox(&open);
    assert!(mailbox.envelope_from_wrap(&wrap).is_err());
}

// --- integration tests over an in-process relay ---

#[test]
fn signer_owner_mismatch_rejected() {
    // A NIP-46 session pointed at the wrong identity must fail at
    // construction, never receive-as-A-while-publishing-as-B.
    let open = keys();
    let stranger = keys();
    assert!(matches!(
        LiveMailbox::connect(
            stranger,
            open.secret_key().clone(),
            Vec::<String>::new(),
            temp_path("seen-mismatch"),
        ),
        Err(MailboxError::Identity)
    ));
}

#[test]
fn foreign_envelope_sender_rejected() {
    // The caller-supplied envelope sender is metadata the adapter will
    // not let lie: mail leaves under this device's identity or errors.
    let device = keys();
    let stranger = keys();
    let mut mailbox = offline_mailbox(&device);
    assert!(matches!(
        mailbox.send(envelope(
            device_id(&stranger),
            device_id(&keys()),
            "smuggled bytes",
        )),
        Err(MailboxError::Identity)
    ));
}

// --- external-relay interop: opt-in, never in the default gate ---
//
// MiniRelay proves the mailbox against exactly the protocol slice it
// uses, without signature verification, TLS, relay auth, or
// relay-specific replay behavior. This group runs the same
// send/receive/recovery suite against a real public relay:
//
// `WYRD_TEST_RELAY_URL=wss://nos.lol cargo test -p wyrd-daemon
//  external_relay -- --ignored`
//
// Proven against nos.lol; relay.damus.io never completed the attach
// from here, so prefer a relay that answers.
//
// `#[ignore]` keeps the group out of the default `cargo nextest run`
// gate, so third-party availability can never flake CI. Selecting the
// group runs it against `WYRD_TEST_RELAY_URL`, defaulting to the
// proven relay below — real assertions either way, never a silent
// pass. Each run publishes a few gift wraps to fresh random
// recipients — negligible traffic addressed to keys nobody holds.
