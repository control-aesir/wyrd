use super::*;

use wyrd_format::membership::Admission;
use wyrd_format::Change;

use crate::control::{CapabilityPayload, Message};
use crate::keys::capability::Capability;
use crate::keys::{DeviceEncryptionSecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::membership::MembershipLog;
use crate::runtime::test_util::{
    admit_engine, announcement_for, capability_message, deliver, drain, encryption_key, fixture,
    queue, transition_message, MemoryMailbox,
};

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
    // Next pass the overflow is re-offered against resolved state
    // and commits instead of staying lost.
    let report = drain(&mut fixture);
    assert_eq!(report.accepted, 1);
    assert_eq!(fixture.engine.pending_count(), 0);
    let facts = fixture.engine.store.load().expect("loads");
    assert_eq!(facts.announcements.len(), MAX_PENDING_MESSAGES + 1);
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
