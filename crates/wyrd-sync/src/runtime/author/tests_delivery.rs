use super::delivery::{
    announcement_obligation, capability_obligation, send_sealed_to, transition_obligation,
};
use super::tests_harness::mint_setup;
use crate::durable::Fact;
use crate::runtime::test_util::CapturedLogs;
use crate::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};
use wyrd_format::SnapshotId;
/// Send-only mailbox fakes for the warn-marker tests: refusal keeps
/// the obligation pending, acceptance discharges it. `recv`/`settle`
/// never run on this path.
struct RefusingMailbox;
struct AcceptingMailbox;

impl Mailbox for RefusingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 0 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

impl Mailbox for AcceptingMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// The warn-once marker keys (kind, obligation, recipient): every
/// control kind warns on its first refusal, repeats stay at debug,
/// and discharge clears the marker so a re-queued obligation warns
/// again. Driven through `send_sealed_to` directly — the three call
/// sites share this path, so one test pins the obligation plumbing
/// for all of them.
#[test]
fn refusal_warn_marker_covers_every_control_kind() {
    let (_dir, mut engine, _keyring, recipient, genesis_id) = mint_setup();
    let snapshot = SnapshotId::from_bytes([0x41; 32]);
    let obligations = [
        ("transition", transition_obligation(&genesis_id)),
        ("capability", capability_obligation(1, &recipient)),
        ("announcement", announcement_obligation(&snapshot)),
    ];
    let discharged = [
        Fact::TransitionDelivered(genesis_id, recipient),
        Fact::CapabilityDelivered(1, recipient),
        Fact::AnnouncementDelivered(snapshot, recipient),
    ];
    let logs = CapturedLogs::default();
    let dispatch = tracing::Dispatch::new(logs.clone());
    let warns = || {
        logs.snapshot()
            .iter()
            .filter(|(level, _)| *level == tracing::Level::WARN)
            .count()
    };
    tracing::dispatcher::with_default(&dispatch, || {
        for ((kind, obligation), delivered) in obligations.iter().zip(discharged) {
            let before = warns();
            send_sealed_to(
                &mut engine,
                &mut RefusingMailbox,
                kind,
                obligation,
                &[0x02; 64],
                [recipient],
                |_| vec![delivered.clone()],
            )
            .expect("refusal is pending, not an error");
            assert_eq!(warns(), before + 1, "{kind}: the first refusal warns");
            send_sealed_to(
                &mut engine,
                &mut RefusingMailbox,
                kind,
                obligation,
                &[0x02; 64],
                [recipient],
                |_| vec![delivered.clone()],
            )
            .expect("refusal is pending, not an error");
            assert_eq!(warns(), before + 1, "{kind}: the repeat stays at debug");
            send_sealed_to(
                &mut engine,
                &mut AcceptingMailbox,
                kind,
                obligation,
                &[0x02; 64],
                [recipient],
                |_| vec![delivered.clone()],
            )
            .expect("acceptance discharges");
            send_sealed_to(
                &mut engine,
                &mut RefusingMailbox,
                kind,
                obligation,
                &[0x02; 64],
                [recipient],
                |_| vec![delivered.clone()],
            )
            .expect("refusal is pending, not an error");
            assert_eq!(
                warns(),
                before + 2,
                "{kind}: discharge clears the marker, so a re-queued obligation warns again"
            );
        }
    });
}
