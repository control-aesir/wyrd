use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::{BaoRoot, Change, ContentId, MembershipTransition, SnapshotId};

use crate::control::{CapabilityPayload, Message};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::test_util::{
    admit_engine, announcement_for, announcement_msg_with, capability_message, deliver,
    deliver_from, drain, encryption_key, fixture, identity, queue, transition_message,
};
use crate::transport::mailbox::MemoryMailbox;

#[test]
fn pending_holds_are_bounded() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();

    // A well-formed capability for a transition the engine never
    // observes: every redelivery defers under a distinct message
    // id (fresh seal nonces).
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = builder.child(vec![Change::Admit(Admission {
        device,
        encryption_key: encryption_key(&encryption_sk),
    })]);
    let mut scratch = MembershipLog::new(member_drive());
    scratch.observe(genesis.clone());
    scratch.observe(admission.clone());
    let state = scratch
        .state_of(&admission.transition_id())
        .expect("admission is valid");
    let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
    let capability = Capability::mint(member_drive(), device, &state, &admission, secrets)
        .expect("device is a member");
    let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
    let delivery = Message::Capability(CapabilityPayload {
        device,
        epoch: 2,
        wrapped,
    });
    let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
    for _ in 0..=MAX_PENDING_MESSAGES {
        mail.push(deliver(&fixture, 2, &delivery));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.deferred, MAX_PENDING_MESSAGES + 1);
    // The overflow sheds without a seen-id commit instead of
    // accumulating without bound: nothing is durably consumed.
    assert_eq!(report.accepted, 0);
    assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);
}

#[test]
fn overflowed_hold_survives_queue_pressure() {
    let mut fixture = fixture();
    let (mut builder, genesis) = Builder::genesis(10);
    let child = builder.child(vec![Change::Rotate]);
    // Announcements bound to a transition the engine has not seen:
    // every delivery defers under a distinct message id (fresh
    // seal nonces), so the last one overflows the pending bound.
    let bound = announcement_for(2, child.transition_id());
    let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
    for _ in 0..=MAX_PENDING_MESSAGES {
        mail.push(deliver(&fixture, 2, &bound));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // The overflow must not be durably consumed: nothing commits.
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, MAX_PENDING_MESSAGES + 1);
    assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);

    // The transition lands: everything held commits with it. The
    // relay-held overflow was already offered this pass (ahead of
    // the transitions, in arrival order), so it sheds once more
    // and waits for the next pass — honest relay ordering.
    let unblock = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&child)),
    ];
    queue(&mut fixture, unblock);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 2);
    assert_eq!(fixture.engine.pending_count(), 0);
    // Next pass the overflow is re-offered against resolved state —
    // and acks as a byte-identical duplicate instead of appending a
    // second fact for the same announcement. One announcement, one
    // fact, however many seals carried it. The relay also redelivers
    // the 1024 parked envelopes the flush consumed: already recorded,
    // so they ack as duplicates too.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, MAX_PENDING_MESSAGES + 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 1);
}

#[test]
fn commit_failure_resyncs_uncommitted_views() {
    use std::os::unix::fs::PermissionsExt;

    let mut fixture = fixture();
    let (_, genesis) = Builder::genesis(10);
    let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];

    // Read-only store: the commit fails after inbox ingest marked
    // the message seen and the log observed it.
    std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::set_permissions(
        fixture.dir.path.join("commits"),
        std::fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    // Root bypasses permissions, so probe writability now that the
    // store is supposed to be read-only and skip when the commit
    // failure cannot occur.
    let probe = fixture.dir.path.join(".writetest");
    if std::fs::File::create(&probe).is_ok() {
        std::fs::remove_file(&probe).unwrap();
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        return;
    }
    queue(&mut fixture, mail.clone());
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    assert!(fixture.engine.drain(&mut mailbox).is_err());

    // Permissions restored: the engine resynced on failure, so the
    // same envelope processes fresh instead of reading stale
    // in-memory dedupe as a duplicate.
    std::fs::set_permissions(
        fixture.dir.path.join("commits"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.current(), 1);
}

#[cfg(unix)]
#[test]
fn commit_failure_resyncs_and_retries() {
    use std::os::unix::fs::PermissionsExt;

    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let bound = announcement_for(2, admission.transition_id());
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
        deliver(&fixture, 2, &bound),
    ];
    queue(&mut fixture, mail);

    // Make the store unwritable. Root bypasses permissions, so
    // probe writability after the chmod and skip when the commit
    // failure cannot occur; otherwise assert the failure, restore,
    // and verify redelivery retries cleanly.
    let dir = fixture.dir.path.clone();
    let commits = dir.join("commits");
    for path in [&dir, &commits] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let probe = dir.join(".writetest");
    if std::fs::File::create(&probe).is_ok() {
        std::fs::remove_file(&probe).unwrap();
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        return;
    }

    // The first commit fails: the engine resyncs its views and
    // surfaces the error instead of deciding against uncommitted
    // state or wedging the drain. The queue is untouched (the
    // failure is durable-side), so redelivery handles the retry.
    let recipient = fixture.recipient;
    let mut mailbox = MemoryMailbox {
        relay: &mut fixture.relay,
        owner: recipient,
    };
    assert!(fixture.engine.drain(&mut mailbox).is_err());
    for path in [&dir, &commits] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Retry after the outage: the failed drain settled nothing, so
    // the relay still holds the whole batch in arrival order — no
    // redelivery needed. Genesis commits first this time, so the
    // capability and announcement validate on first sight instead
    // of deferring. Every effect lands durably exactly once.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 4);
    assert_eq!(report.deferred, 0);
    assert_eq!(report.duplicates, 0);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert_eq!(facts.capabilities.len(), 1);
    assert_eq!(facts.announcements.len(), 1);
}

/// A distinct snapshot id for spam announcements: the index in the
/// leading bytes, so every announcement is a distinct valid statement
/// over the same canonical membership.
fn spam_id(index: u32) -> SnapshotId {
    let mut id = [0xA0; 32];
    id[0..4].copy_from_slice(&index.to_be_bytes());
    SnapshotId::from_bytes(id)
}

/// One distinct valid announcement over the canonical membership: a
/// stranger self-signs (strangers commit for the body phase to judge),
/// so each commits an announcement plus its control-message id with no
/// bodies ever existing. The cheapest insider fact-log spam.
fn spam_announcement(admission: &MembershipTransition, index: u32) -> Message {
    let (author_sk, _) = identity(0x22);
    announcement_msg_with(
        &author_sk,
        spam_id(index),
        admission.epoch,
        admission.transition_id(),
        BaoRoot::from_bytes([0x44; 32]),
        ContentId::from_bytes([0x55; 32]),
        BaoRoot::from_bytes([0x66; 32]),
    )
}

#[test]
fn sustained_spam_commits_bounded_facts_per_pass_and_converges() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    // Eight senders, seventy distinct announcements each: every
    // sender stays under its per-sender quota, so only the global
    // per-pass budget binds. (Named off the "flood" substring so the
    // live-mailbox serial group in .config/nextest.toml does not sweep
    // up this MemoryMailbox-only test.)
    let senders: Vec<_> = (0..8u8).map(|i| identity(0x10 + i).0).collect();
    let mut mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    for (s, sender) in senders.iter().enumerate() {
        for j in 0..70u32 {
            mail.push(deliver_from(
                &fixture,
                sender,
                2,
                &spam_announcement(&admission, s as u32 * 70 + j),
            ));
        }
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // Six overhead facts plus 509 announcements (1018 facts) reach the
    // 1024-fact per-pass budget; the remaining 51 stay relay-held for
    // the next pass — paced, never dropped.
    assert_eq!(report.accepted, 512);
    assert_eq!(report.deferred, 51);
    assert_eq!(report.deferred_shed, 51, "budget shed is shed");
    assert_eq!(report.deferred_unseen, 0);
    assert_eq!(report.deferred_status_blocked, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 509);
    // Nothing was lost: the next pass converges everything deferred.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 51);
    assert_eq!(report.deferred, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 560);
}

#[test]
fn per_sender_quota_keeps_one_spammer_from_starving_others() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    // The fixture sender floods first (worst order): 200 distinct
    // announcements, 400 facts against its 256-fact quota. An honest
    // second sender's five queue behind the flood.
    let (honest_sk, _) = identity(0x20);
    let mut mail = Vec::with_capacity(205);
    for j in 0..200u32 {
        mail.push(deliver(&fixture, 2, &spam_announcement(&admission, j)));
    }
    let honest_ids: Vec<_> = (0..5u32).map(|j| spam_id(1000 + j)).collect();
    for j in 0..5u32 {
        mail.push(deliver_from(
            &fixture,
            &honest_sk,
            2,
            &spam_announcement(&admission, 1000 + j),
        ));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    // The flooder commits 128 announcements (its quota), sheds 72
    // relay-held; the honest five commit in the same pass — paced,
    // never starved.
    assert_eq!(report.accepted, 133);
    assert_eq!(report.deferred, 72);
    assert_eq!(report.deferred_shed, 72, "quota shed is shed");
    assert_eq!(report.deferred_unseen, 0);
    assert_eq!(report.deferred_status_blocked, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 133);
    for id in &honest_ids {
        assert!(
            facts.announcements.iter().any(|a| a.snapshot == *id),
            "honest announcement {id:?} commits despite the flood"
        );
    }
    // The shed flood converges on the next pass.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 72);
    assert_eq!(report.deferred, 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), 205);
}

#[test]
fn semantic_duplicates_commit_no_facts() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let bound = announcement_for(2, admission.transition_id());
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
        deliver(&fixture, 2, &bound),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 4);
    // Reseals of already-recorded payloads: fresh nonces make new
    // message ids over byte-identical content. Each must ack as a
    // duplicate without appending another durable fact.
    let mut mail = Vec::with_capacity(14);
    for _ in 0..10 {
        mail.push(deliver(&fixture, 2, &bound));
    }
    for _ in 0..2 {
        mail.push(deliver(&fixture, 1, &transition_message(&genesis)));
    }
    for _ in 0..2 {
        mail.push(deliver(&fixture, 2, &cap));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 14);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.transitions.len(), 2);
    assert_eq!(facts.announcements.len(), 1);
    assert_eq!(facts.capabilities.len(), 1);
}

/// A sustained capability reseal storm: hundreds of fresh seals over
/// one recorded grant, past the per-sender quota — every one acks as
/// a duplicate with no fact, because duplicates never charge the
/// budget. (Named off the "flood" substring so the live-mailbox
/// serial group in .config/nextest.toml does not sweep up this
/// MemoryMailbox-only test.)
#[test]
fn sustained_capability_reseal_commits_no_new_facts() {
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let cap = capability_message(
        device,
        admission.transition_id(),
        2,
        vec![
            EpochSecret::from_bytes([0x08; 32]),
            EpochSecret::from_bytes([0x09; 32]),
        ],
    );
    let mail = vec![
        deliver(&fixture, 1, &transition_message(&genesis)),
        deliver(&fixture, 1, &transition_message(&admission)),
        deliver(&fixture, 2, &cap),
    ];
    queue(&mut fixture, mail);
    assert_eq!(drain(&mut fixture).accepted, 3);
    // Three hundred reseals from one sender: past the 256-fact
    // per-sender quota, which binds nothing because no reseal
    // commits.
    let mut mail = Vec::with_capacity(300);
    for _ in 0..300 {
        mail.push(deliver(&fixture, 2, &cap));
    }
    queue(&mut fixture, mail);
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.duplicates, 300);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.capabilities.len(), 1);
}
