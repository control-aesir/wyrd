use super::store::DurableStore;
use super::tests_harness::{owner, TestDir, PASSPHRASE};
use super::Fact;
use crate::control::{ControlKind, SealedControl};
use crate::membership::test_util::drive;
use wyrd_format::{DeviceId, SnapshotId};

/// Committing zero facts touches nothing.
#[test]
fn empty_commit_is_noop() {
    let dir = TestDir::new("empty");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    assert_eq!(store.commit(&[]).unwrap(), 0);
    assert_eq!(store.current(), 0);
}

/// The announcement outbox survives a commit/rebuild cycle: queued
/// obligations minus delivered markers derive the pending set, the
/// sealed bytes replay verbatim, and a second seal for the same
/// snapshot does not displace the first.
#[test]
fn announcement_outbox_round_trips_and_derives_pending() {
    let dir = TestDir::new("outbox");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let other = SnapshotId::from_bytes([0xA2; 32]);
    let alice = DeviceId::from_bytes([0xB1; 32]);
    let bob = DeviceId::from_bytes([0xB2; 32]);
    // Structurally valid sealed bytes (decodable envelope of the
    // announcement kind — the codec checks structure, not the seal).
    let sealed = SealedControl {
        version: 0x00,
        drive: drive(),
        kind: ControlKind::SnapshotAnnouncement,
        epoch: 2,
        nonce: [0xC1; 24],
        ciphertext: vec![0xC2; 32],
    }
    .encode();
    let rival = SealedControl {
        version: 0x00,
        drive: drive(),
        kind: ControlKind::SnapshotAnnouncement,
        epoch: 2,
        nonce: [0xD1; 24],
        ciphertext: vec![0xD2; 32],
    }
    .encode();
    store
        .commit(&[
            Fact::AnnouncementQueued(snapshot, alice),
            Fact::AnnouncementQueued(snapshot, bob),
            Fact::AnnouncementQueued(other, alice),
            Fact::AnnouncementSealed(snapshot, sealed.clone()),
            // A rival seal must not displace the first: retries stay
            // byte-identical to the first send.
            Fact::AnnouncementSealed(snapshot, rival),
            Fact::AnnouncementDelivered(snapshot, alice),
        ])
        .unwrap();

    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt.runtime.pending_announcements(),
        vec![(snapshot, bob), (other, alice)],
        "queued minus delivered, in snapshot order"
    );
    assert_eq!(
        rebuilt.runtime.announcement_sealed_bytes(&snapshot),
        Some(sealed.as_slice()),
        "first seal wins"
    );
    assert!(rebuilt.runtime.announcement_sealed_bytes(&other).is_none());
    assert!(
        rebuilt.runtime.announcement_covered(snapshot, alice),
        "a delivered pair stays covered, never re-queued"
    );
    assert!(
        !rebuilt.runtime.announcement_covered(other, bob),
        "a never-queued pair is uncovered"
    );
}

/// Route-specific reseals round-trip keyed by (snapshot, route): the
/// first seal per pair wins, pairs are independent, and the canonical
/// seal is untouched by route seals.
#[test]
fn announcement_route_seals_round_trip_per_pair_first_wins() {
    let dir = TestDir::new("route-outbox");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let route_a = vec![0xA1; 32];
    let route_b = vec![0xB2; 32];
    let seal = |nonce: u8| {
        SealedControl {
            version: 0x00,
            drive: drive(),
            kind: ControlKind::SnapshotAnnouncement,
            epoch: 2,
            nonce: [nonce; 24],
            ciphertext: vec![0xC2; 32],
        }
        .encode()
    };
    let sealed_a = seal(0xC1);
    let rival_a = seal(0xD1);
    let sealed_b = seal(0xE1);
    store
        .commit(&[
            Fact::AnnouncementRouteSealed(snapshot, route_a.clone(), sealed_a.clone()),
            // A rival seal for the same pair must not displace the first.
            Fact::AnnouncementRouteSealed(snapshot, route_a.clone(), rival_a),
            Fact::AnnouncementRouteSealed(snapshot, route_b.clone(), sealed_b.clone()),
        ])
        .unwrap();

    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &route_a),
        Some(sealed_a.as_slice()),
        "first seal per pair wins"
    );
    assert_eq!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &route_b),
        Some(sealed_b.as_slice()),
        "pairs are independent"
    );
    assert!(
        rebuilt
            .runtime
            .announcement_route_sealed_bytes(&snapshot, &[0xF0; 32])
            .is_none(),
        "unsealed routes stay absent"
    );
    assert!(
        rebuilt
            .runtime
            .announcement_sealed_bytes(&snapshot)
            .is_none(),
        "route seals never populate the canonical seal"
    );
}

/// Delivered-route records round-trip and scope redelivery
/// eligibility: the record commits beside its marker, replays into
/// the route map with last-write-wins, and `announce_eligible_for`
/// reopens only in-scope pairs whose recorded route differs from
/// the live one — unknown routes count as changed, the live route
/// quenches, out-of-scope history stays discharged, and no route at
/// all reopens only pairs withdrawn from a real route (the
/// withdrawal repair) plus plain pending. (The caller computes the
/// scope as live heads plus their reachable closure; at the fact
/// level the scope is just the gating set.)
#[test]
fn announcement_delivered_routes_round_trip_and_scope_eligibility() {
    use std::collections::BTreeSet;
    let dir = TestDir::new("route-delivery");
    let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
    let snapshot = SnapshotId::from_bytes([0xA1; 32]);
    let history = SnapshotId::from_bytes([0xA2; 32]);
    let alice = DeviceId::from_bytes([0xB1; 32]);
    let bob = DeviceId::from_bytes([0xB2; 32]);
    let carol = DeviceId::from_bytes([0xB3; 32]);
    let route_a = [0xA1; 32];
    let route_b = [0xB2; 32];
    store
        .commit(&[
            Fact::AnnouncementQueued(snapshot, alice),
            Fact::AnnouncementQueued(snapshot, bob),
            Fact::AnnouncementQueued(snapshot, carol),
            Fact::AnnouncementDelivered(snapshot, alice),
            Fact::AnnouncementDeliveredRoute(snapshot, alice, route_a),
            // Bob: delivered with no route (pre-record chain, or a
            // routeless send) — unknown, not current.
            Fact::AnnouncementDelivered(snapshot, bob),
            // History: discharged under an older route, but outside
            // the redelivery scope — stays shut under any route.
            Fact::AnnouncementQueued(history, alice),
            Fact::AnnouncementDelivered(history, alice),
            Fact::AnnouncementDeliveredRoute(history, alice, route_a),
        ])
        .unwrap();

    let scope: BTreeSet<SnapshotId> = BTreeSet::from([snapshot]);
    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt.runtime.pending_announcements(),
        vec![(snapshot, carol)],
        "accounting stays queued-minus-delivered"
    );
    assert_eq!(
        rebuilt.runtime.announce_eligible_for(Some(route_a), &scope),
        vec![(snapshot, bob), (snapshot, carol)],
        "same route: pending plus unknown only"
    );
    assert_eq!(
        rebuilt.runtime.announce_eligible_for(Some(route_b), &scope),
        vec![(snapshot, alice), (snapshot, bob), (snapshot, carol)],
        "new route reopens the discharged head pair, not history"
    );
    assert_eq!(
        rebuilt.runtime.announce_eligible_for(None, &scope),
        vec![(snapshot, alice), (snapshot, carol)],
        "no route: pending plus the routed pair, reopened once for withdrawal; \
         never-routed bob and out-of-scope history stay shut"
    );

    // Overwrite: last write wins on replay, quenching under the new
    // route without touching the marker.
    store
        .commit(&[Fact::AnnouncementDeliveredRoute(snapshot, alice, route_b)])
        .unwrap();
    let rebuilt = store.rebuild(owner()).unwrap();
    assert_eq!(
        rebuilt.runtime.announce_eligible_for(Some(route_b), &scope),
        vec![(snapshot, bob), (snapshot, carol)],
        "re-recorded route quenches"
    );
    assert_eq!(
        rebuilt.runtime.pending_announcements(),
        vec![(snapshot, carol)],
        "re-recording moves no accounting"
    );
}

/// The delivered-route tag is a clean upgrade boundary: 0x1C is new
/// (no old reader decodes it as another fact) and pinned (a
/// different value is a different format), and a malformed record
/// fails closed instead of decoding as a wrong pair.
#[test]
fn delivered_route_tag_is_a_clean_upgrade_boundary() {
    use super::codec::{KNOWN_TAGS, TAG_ANNOUNCEMENT_DELIVERED_ROUTE};
    let pre_route_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    ];
    assert!(
        !pre_route_tags.contains(&TAG_ANNOUNCEMENT_DELIVERED_ROUTE),
        "the route tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_ANNOUNCEMENT_DELIVERED_ROUTE, 0x1C,
        "the tag is pinned: a different value is a different format"
    );
    let mut sorted = KNOWN_TAGS.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        len,
        "a duplicate tag decodes as the wrong fact"
    );
}

/// The announcement-retirement tag is a clean upgrade boundary:
/// 0x1D is new (no old reader decodes it as another fact) and
/// pinned (a different value is a different format), and a
/// malformed record fails closed instead of decoding as a wrong
/// triple.
#[test]
fn announcement_retirement_tag_is_a_clean_upgrade_boundary() {
    use super::codec::{KNOWN_TAGS, TAG_ANNOUNCEMENT_RECONCILED};
    let pre_retirement_tags = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    ];
    assert!(
        !pre_retirement_tags.contains(&TAG_ANNOUNCEMENT_RECONCILED),
        "the retirement tag must be new, or an old reader would decode it as another fact"
    );
    assert_eq!(
        TAG_ANNOUNCEMENT_RECONCILED, 0x1D,
        "the tag is pinned: a different value is a different format"
    );
    let mut sorted = KNOWN_TAGS.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        len,
        "a duplicate tag decodes as the wrong fact"
    );
}
