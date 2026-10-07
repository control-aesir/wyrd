use super::mini_relay::MiniRelay;
use super::tests_harness::{
    drain_until, keys, keys_for, live_mailbox, temp_path, wait_for_health, DELIVERY_TIMEOUT,
    OUTAGE_TIMEOUT, RECOVERY_TIMEOUT,
};
use super::*;
use nostr::event::FinalizeEvent;
use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, ObjectStore, SnapshotId, Tree};
use wyrd_sync::bulk::IrohBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::runtime::{DrainReport, Engine, MaterializationState, RoutePublishing};
use wyrd_sync::serving::ServingEndpoint;

use std::time::{Duration, Instant};

/// History catch-up over a real relay: an admitted peer disconnects,
/// misses several ordinary snapshots plus an admission it never saw,
/// then reconnects and acquires the full history closure — snapshot
/// bodies, manifests, and demanded content — over live transport.
///
/// Acquisition and convergence assert separately: the reconnect drain
/// must record every missed announcement with the keyless
/// post-admission one still retained (history closure incomplete at
/// exactly the missing epoch key), and only after the heal may the
/// heads match the owner's (state convergence). A garbage wrap
/// injected mid-gap must never become a delivery, and a restart after
/// convergence must stay quiet with heads intact.
///
/// Retention bound: the absent peer is rescued only within relay
/// retention. The owner retires every obligation on relay acceptance,
/// so this scenario proves acquisition from a retaining relay, not
/// repair past eviction.
#[test]
fn disconnected_peer_acquires_missed_history_over_real_relay() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let owner_dir = temp_path("catchup-owner");
    let recipient_dir = temp_path("catchup-recipient");
    let drive_pass = "test-pass";
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_encryption = DeviceEncryptionSecret::generate().unwrap();
    let owner_keys = keys_for(&owner_identity);
    let recipient_keys = keys_for(&recipient_identity);
    let recipient_device = recipient_identity.device_id();

    let mut owner = Engine::create(owner_dir.clone(), drive_pass, owner_identity.clone()).unwrap();
    let drive = owner.drive();
    let invitation = owner
        .admit_device(recipient_device, recipient_encryption.encryption_key())
        .unwrap()
        .invitation;
    let mut recipient = Engine::accept_invitation(
        recipient_dir.clone(),
        drive_pass,
        recipient_identity.clone(),
        recipient_encryption.clone(),
        &invitation,
    )
    .unwrap();

    let mut owner_mailbox = live_mailbox(
        &owner_keys,
        std::slice::from_ref(&url),
        temp_path("catchup-owner-seen"),
    );
    let mut recipient_mailbox = live_mailbox(
        &recipient_keys,
        std::slice::from_ref(&url),
        temp_path("catchup-recipient-seen"),
    );

    // The owner serves its vault over loopback iroh; the route rides
    // every announcement below, so the reconnect fetch runs over live
    // transport too.
    let serving = ServingEndpoint::open_loopback(owner.vault(), &owner_dir).unwrap();
    let route = serving.node_addr_bytes();

    // Baseline: the admission converges over the live relay.
    assert_eq!(owner.deliver_pending(&mut owner_mailbox).unwrap(), 2);
    let setup = drain_until(&mut recipient, &mut recipient_mailbox, 2);
    assert_eq!(setup.accepted, 2);
    assert_eq!(recipient.pending_count(), 0, "admission holds nothing");
    assert_eq!(recipient.membership_log().known_state().unwrap().epoch, 2);

    // The peer disconnects: its mailbox drops while the owner keeps
    // authoring ordinary snapshots it never sees.
    drop(recipient_mailbox);

    let mut author_objects = MemoryObjectStore::default();
    let mut missed: Vec<(SnapshotId, ContentId, ContentId, Vec<u8>)> = Vec::new();
    for index in 0..3 {
        let payload = format!("missed-snapshot-{index}").into_bytes();
        let chunk = author_objects.insert(ObjectKind::Chunk, &payload).unwrap();
        let tree = Tree::from_entries(vec![Entry::file(
            "payload",
            payload.len() as u64,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut author_objects)
        .unwrap();
        let authored = owner.author_snapshot(&author_objects, tree).unwrap();
        let snapshot = authored.snapshot().snapshot_id();
        assert_eq!(
            owner
                .announce_snapshot(&authored, &mut owner_mailbox, Some(&route))
                .unwrap(),
            1,
            "missed snapshot announces while the peer is away"
        );
        missed.push((snapshot, tree, chunk, payload));
    }
    assert!(
        owner.pending_announcements().unwrap().is_empty(),
        "owner outbox discharged"
    );

    // A membership change the peer also misses: admitting a third
    // device, then announcing a snapshot bound to the admission before
    // the transition itself is published. The announcement goes out
    // immediately while the transition waits, so the reconnect meets
    // a genuine missing dependency.
    let device_c_identity = DeviceIdentitySecret::generate().unwrap();
    let device_c_encryption = DeviceEncryptionSecret::generate().unwrap();
    let device_c = device_c_identity.device_id();
    owner
        .admit_device(device_c, device_c_encryption.encryption_key())
        .unwrap();
    let payload_c = b"missed-snapshot-after-admit".to_vec();
    let chunk_c = author_objects
        .insert(ObjectKind::Chunk, &payload_c)
        .unwrap();
    let tree_c = Tree::from_entries(vec![Entry::file(
        "payload",
        payload_c.len() as u64,
        false,
        vec![chunk_c],
    )
    .unwrap()])
    .unwrap()
    .insert_into(&mut author_objects)
    .unwrap();
    let authored_c = owner.author_snapshot(&author_objects, tree_c).unwrap();
    let snapshot_c = authored_c.snapshot().snapshot_id();
    assert_eq!(
        owner
            .announce_snapshot(&authored_c, &mut owner_mailbox, Some(&route))
            .unwrap(),
        2,
        "post-admission snapshot announces to both members"
    );
    missed.push((snapshot_c, tree_c, chunk_c, payload_c));

    // Transport-invalid mail mid-gap: addressed to the peer but not a
    // decryptable wrap. It must never become a delivery.
    let garbage = EventBuilder::new(Kind::GiftWrap, "not a real wrap")
        .tag(Tag::public_key(recipient_keys.public_key()))
        .finalize(&keys())
        .unwrap();
    relay.inject(garbage);

    // The peer reconnects with a fresh mailbox: the relay replays the
    // missed history onto the resubscribe. The loop observes the
    // retained state rather than assuming arrival order — the
    // post-admission announcement must still be skipped (its epoch key
    // arrives only with the heal) while the three ordinary ones are
    // recorded. Skipped mail settles `Retry`: the handover stays in
    // the mailbox's bounded in-memory `unacked` queue and is re-offered
    // round-robin, so the heal needs no second replay — with the
    // consequence that a peer crash before the heal leans on relay
    // retention for the wrap again. The loop breaks on the first pass
    // showing the full picture, since further passes would re-offer
    // the retained envelope.
    let mut recipient_mailbox = live_mailbox(
        &recipient_keys,
        &[url],
        temp_path("catchup-recipient-reconnect"),
    );
    let start = Instant::now();
    let mut acquired = DrainReport::default();
    loop {
        let report = recipient.drain(&mut recipient_mailbox).unwrap();
        acquired.accepted += report.accepted;
        acquired.duplicates += report.duplicates;
        acquired.deferred += report.deferred;
        acquired.skipped += report.skipped;
        acquired.discarded += report.discarded;
        let state = recipient.runtime_state().unwrap();
        let ordinary_recorded = missed[..3]
            .iter()
            .all(|(snapshot, _, _, _)| state.announcement(snapshot).is_some());
        if acquired.accepted >= 3 && ordinary_recorded && acquired.skipped >= 1 {
            break;
        }
        assert!(
            start.elapsed() < DELIVERY_TIMEOUT,
            "reconnect acquires the missed ordinary snapshots and retains the keyless one"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(acquired.accepted, 3, "only the ordinary missed snapshots");
    assert_eq!(
        acquired.skipped, 1,
        "the post-admission announcement retained"
    );
    assert_eq!(acquired.deferred, 0);
    // The setup admission pair replays onto the fresh seen log and
    // collapses by message id: redelivery of committed mail is a
    // duplicate, never a second commit. The counts above depend on
    // relay store order (the keyless announcement replays last), so a
    // reordered gap changes them.
    assert_eq!(acquired.duplicates, 2, "setup admission redelivered once");
    assert_eq!(acquired.discarded, 0, "garbage never reached intake");
    assert_eq!(
        recipient_mailbox.poison_len(),
        1,
        "the mid-gap garbage wrap is recorded as poison, not silently absent"
    );

    // History closure, asserted before any convergence: the missed
    // ordinary snapshots are recorded, the keyless one is retained but
    // not recorded, and membership still ends at the pre-gap epoch.
    let state = recipient.runtime_state().unwrap();
    for (snapshot, _, _, _) in &missed[..3] {
        assert!(
            state.announcement(snapshot).is_some(),
            "missed snapshot recorded"
        );
    }
    assert!(
        state.announcement(&snapshot_c).is_none(),
        "keyless announcement not recorded before its epoch lands"
    );
    assert_eq!(
        recipient.pending_count(),
        0,
        "skipped mail is mailbox-held for re-offer, not engine-held"
    );
    let known = recipient.membership_log().known_state().unwrap();
    assert_eq!(known.epoch, 2, "membership still pre-gap");
    assert_eq!(
        recipient.held_epochs().unwrap(),
        vec![1, 2],
        "epochs contiguous"
    );

    // Heal: publishing the withheld admission converges the new epoch,
    // and the retained announcement opens on re-offer. Arrival order
    // between the transition and the rotation carrying the epoch key
    // is relay timing, so the heal asserts state, not exact counts.
    let sent = owner.deliver_pending(&mut owner_mailbox).unwrap();
    assert!(sent >= 2, "admission transition plus capabilities publish");
    let start = Instant::now();
    loop {
        let _ = recipient.drain(&mut recipient_mailbox).unwrap();
        let state = recipient.runtime_state().unwrap();
        let healed = state.announcement(&snapshot_c).is_some() && recipient.pending_count() == 0;
        let known = recipient.membership_log().known_state().unwrap();
        let member = recipient
            .membership_log()
            .members_of(&known.transition_id)
            .unwrap()
            .contains(&device_c);
        if healed && member {
            break;
        }
        assert!(
            start.elapsed() < DELIVERY_TIMEOUT,
            "retained announcement resolves after its epoch lands"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let state = recipient.runtime_state().unwrap();
    assert!(
        state.announcement(&snapshot_c).is_some(),
        "dependent announcement recorded after the heal"
    );
    for (snapshot, _, _, _) in &missed[..3] {
        assert!(
            state.announcement(snapshot).is_some(),
            "ordinary snapshots still recorded"
        );
    }
    let quiet = recipient.drain(&mut recipient_mailbox).unwrap();
    assert_eq!(quiet.accepted, 0);
    assert_eq!(quiet.deferred, 0);
    assert_eq!(quiet.skipped, 0);
    // The withheld transition re-offers after its rotation already
    // committed it: the document converged via the rotation, so the
    // envelope collapses to a duplicate instead of a second commit.
    assert_eq!(
        quiet.duplicates, 1,
        "rotation-committed transition collapses"
    );
    // Admitting C queued the pre-admission snapshots as newcomer
    // catch-up for the late member: the durable outbox republishes
    // them without re-authoring, and only then is nothing pending for
    // anyone — the no-re-push property made visible.
    assert_eq!(
        owner
            .announce_pending(&mut owner_mailbox, Some(&route))
            .unwrap(),
        3,
        "pre-admission snapshots republish to the late member"
    );
    assert!(
        !owner.has_pending_outbound().unwrap(),
        "owner discharged every obligation, including the withheld admission"
    );

    // The missed bodies, manifests, and demanded content arrive over
    // live iroh: every missed snapshot fetches body plus root
    // manifest on the first pass, with objects unfulfilled until the
    // manifest records publish their routes; the second pass
    // completes the demanded chunks.
    for (_, _, chunk, _) in &missed {
        recipient
            .set_materialization(*chunk, MaterializationState::Pinned)
            .unwrap();
    }
    serving.flush().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async {
        iroh::Endpoint::builder(iroh::endpoint::presets::N0DisableRelay)
            .clear_address_lookup()
            .bind()
            .await
            .unwrap()
    });
    let mut bulk = IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
    let state = recipient.runtime_state().unwrap();
    let routes = bulk.publish_routes(&state).unwrap().published;
    // Four routes per announced snapshot — root-manifest transport,
    // body, eager root, eager body — so the fan-out pins a route
    // regression that still leaves the count above four.
    assert_eq!(routes, 16, "every missed snapshot publishes its routes");
    let mut objects = MemoryObjectStore::default();
    let first = recipient.execute_plan(&mut bulk, &mut objects).unwrap();
    assert_eq!(
        first.snapshot_bodies, 4,
        "all missed bodies over live transport"
    );
    assert_eq!(first.manifests, 4, "all missed root manifests");
    assert_eq!(first.objects, 0);
    assert!(
        first.unfulfilled > 0,
        "objects wait for their manifest routes"
    );
    let state = recipient.runtime_state().unwrap();
    let second_routes = bulk.publish_routes(&state).unwrap().published;
    assert!(second_routes > routes, "the manifest records add routes");
    let second = recipient.execute_plan(&mut bulk, &mut objects).unwrap();
    // Four demanded chunks plus their four tree blobs, which the
    // default policy fetches alongside pinned content.
    assert_eq!(second.objects, 8, "chunks and tree blobs");
    assert_eq!(second.unfulfilled, 0);
    for (_, tree, chunk, payload) in &missed {
        assert_eq!(
            objects.get(chunk).unwrap().as_deref(),
            Some(payload.as_slice()),
            "demanded content bytes match"
        );
        assert!(
            objects.has(tree).unwrap(),
            "tree blob fetched alongside its chunk"
        );
    }
    bulk.shutdown(std::time::Duration::from_secs(10));

    // State convergence, asserted separately from acquisition: with
    // the bodies fetched, the reconnected peer's live heads match the
    // owner's. Heads install only over held bodies, so this asserts
    // after the fetch, never before.
    let mut owner_heads: Vec<SnapshotId> = owner
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    owner_heads.sort();
    let mut peer_heads: Vec<SnapshotId> = recipient
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    peer_heads.sort();
    assert_eq!(peer_heads, owner_heads, "heads converge after the fetch");

    // Restart after convergence: reopening the same directory keeps
    // the acquired history with nothing to redeliver and heads
    // intact.
    drop(recipient);
    let mut reopened = Engine::open(
        recipient_dir.clone(),
        drive,
        recipient_device,
        drive_pass,
        recipient_identity.clone(),
        recipient_encryption.clone(),
    )
    .unwrap();
    let restart = reopened.drain(&mut recipient_mailbox).unwrap();
    assert_eq!(restart.accepted, 0);
    assert_eq!(restart.deferred, 0);
    assert_eq!(restart.skipped, 0);
    assert_eq!(restart.duplicates, 0);
    assert_eq!(reopened.pending_count(), 0);
    let mut reopened_heads: Vec<SnapshotId> = reopened
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    reopened_heads.sort();
    assert_eq!(reopened_heads, owner_heads, "heads survive the restart");

    drop(recipient_mailbox);
    drop(owner_mailbox);
    drop(reopened);
    drop(owner);
    serving
        .shutdown(std::time::Duration::from_secs(10))
        .unwrap();
    std::fs::remove_dir_all(owner_dir).unwrap();
    std::fs::remove_dir_all(recipient_dir).unwrap();
}

/// Acquisition across a relay restart on the production reconnect
/// shape: the peer keeps its mailbox and durable seen log while the
/// relay drops and reboots, so the supervisor's own resubscribe —
/// not a fresh mailbox — replays the missed snapshots onto the same
/// subscription state. Already-acked mail must collapse in the seen
/// log (no intake duplicates); missed mail commits exactly once.
///
/// Recovery pacing belongs to the SDK's auto-reconnect, so the
/// restart legs wait generously.
#[test]
fn same_mailbox_acquires_missed_snapshots_across_relay_restart() {
    let relay = MiniRelay::spawn();
    let url = relay.url().to_string();
    let owner_dir = temp_path("catchup-restart-owner");
    let recipient_dir = temp_path("catchup-restart-recipient");
    let drive_pass = "test-pass";
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_identity = DeviceIdentitySecret::generate().unwrap();
    let recipient_encryption = DeviceEncryptionSecret::generate().unwrap();
    let owner_keys = keys_for(&owner_identity);
    let recipient_keys = keys_for(&recipient_identity);

    let mut owner = Engine::create(owner_dir.clone(), drive_pass, owner_identity.clone()).unwrap();
    let invitation = owner
        .admit_device(
            recipient_identity.device_id(),
            recipient_encryption.encryption_key(),
        )
        .unwrap()
        .invitation;
    let mut recipient = Engine::accept_invitation(
        recipient_dir.clone(),
        drive_pass,
        recipient_identity.clone(),
        recipient_encryption,
        &invitation,
    )
    .unwrap();

    let mut owner_mailbox = live_mailbox(
        &owner_keys,
        std::slice::from_ref(&url),
        temp_path("catchup-restart-owner-seen"),
    );
    let mut recipient_mailbox = live_mailbox(
        &recipient_keys,
        std::slice::from_ref(&url),
        temp_path("catchup-restart-recipient-seen"),
    );

    assert_eq!(owner.deliver_pending(&mut owner_mailbox).unwrap(), 2);
    let setup = drain_until(&mut recipient, &mut recipient_mailbox, 2);
    assert_eq!(setup.accepted, 2);
    let seen_before = recipient_mailbox.seen_len();

    // Two snapshots published, then the relay episode: the restart
    // keeps history but clears subscriptions, so the same client must
    // re-REQ and the replay carries both the acked setup pair and the
    // missed snapshots.
    let mut author_objects = MemoryObjectStore::default();
    let mut missed = Vec::new();
    for index in 0..2 {
        let payload = format!("restart-missed-{index}").into_bytes();
        let chunk = author_objects.insert(ObjectKind::Chunk, &payload).unwrap();
        let tree = Tree::from_entries(vec![Entry::file(
            "payload",
            payload.len() as u64,
            false,
            vec![chunk],
        )
        .unwrap()])
        .unwrap()
        .insert_into(&mut author_objects)
        .unwrap();
        let authored = owner.author_snapshot(&author_objects, tree).unwrap();
        let snapshot = authored.snapshot().snapshot_id();
        assert_eq!(
            owner
                .announce_snapshot(&authored, &mut owner_mailbox, None)
                .unwrap(),
            1
        );
        missed.push(snapshot);
    }

    relay.shutdown();
    wait_for_health(&recipient_mailbox, false, OUTAGE_TIMEOUT);
    relay.restart();
    wait_for_health(&recipient_mailbox, true, RECOVERY_TIMEOUT);
    // Both mailboxes must hold exactly one subscription each after
    // the resubscribe: a leaked second one would double-deliver every
    // replayed wrap, and the seen log would silently swallow the copy
    // this test counts on. Two clients, so two — not one.
    let start = Instant::now();
    while relay.subscription_count() != 2 {
        assert!(
            start.elapsed() < DELIVERY_TIMEOUT,
            "resubscribe holds exactly one subscription per mailbox"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let report = drain_until(&mut recipient, &mut recipient_mailbox, 2);
    assert_eq!(report.accepted, 2, "missed snapshots commit once");
    // The acked setup pair replays onto the same seen log and
    // collapses there, never reaching intake — the production
    // resubscribe shape the fresh-mailbox test does not exercise.
    assert_eq!(report.duplicates, 0, "seen log suppresses the acked prefix");
    assert_eq!(report.skipped, 0);
    assert_eq!(
        recipient_mailbox.seen_len(),
        seen_before + 2,
        "only the two new deliveries join the seen log"
    );
    let state = recipient.runtime_state().unwrap();
    for snapshot in &missed {
        assert!(
            state.announcement(snapshot).is_some(),
            "missed snapshot recorded"
        );
    }
    assert_eq!(recipient.pending_count(), 0, "nothing held");
    let quiet = recipient.drain(&mut recipient_mailbox).unwrap();
    assert_eq!(quiet.accepted, 0);
    assert_eq!(quiet.duplicates, 0);

    drop(recipient_mailbox);
    drop(owner_mailbox);
    drop(recipient);
    drop(owner);
    std::fs::remove_dir_all(owner_dir).unwrap();
    std::fs::remove_dir_all(recipient_dir).unwrap();
}
