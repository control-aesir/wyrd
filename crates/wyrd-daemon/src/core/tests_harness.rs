use super::*;

use wyrd_sync::{runtime::Engine, transport::mailbox::Mailbox};

use std::sync::Arc;
use std::time::Duration;

use wyrd_format::{DeviceId, DriveId, ObjectStore};

use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use wyrd_sync::transport::mailbox::{Delivery, DeliveryId, Disposition, MailboxEnvelope};

pub(super) struct NoopMailbox;

impl Mailbox for NoopMailbox {
    fn send(
        &mut self,
        _envelope: MailboxEnvelope,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, wyrd_sync::transport::mailbox::MailboxError> {
        Ok(None)
    }

    fn settle(
        &mut self,
        _id: DeliveryId,
        _disposition: Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Ok(())
    }
}

/// An isolated engine over a scratch directory, removed by the caller
/// after the daemon (and with it the store lock) is dropped.
pub(super) fn scratch_engine() -> (Engine, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-daemon-core-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let engine = Engine::open(
        dir.clone(),
        DriveId::from_bytes([0xEE; 32]),
        DeviceId::from_bytes([0xD0; 32]),
        "daemon-test",
        DeviceIdentitySecret::from_bytes([0x11; 32]).unwrap(),
        DeviceEncryptionSecret::from_bytes([0x22; 32]).unwrap(),
    )
    .unwrap();
    (engine, dir)
}

/// A fresh single-member drive over a scratch directory: the engine
/// can author from the start, and the caller can reopen the drive
/// from custody after the daemon (and with it the store lock) is
/// dropped.
pub(super) fn scratch_drive() -> (Engine, std::path::PathBuf, DeviceIdentitySecret) {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-daemon-write-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = DeviceIdentitySecret::generate().unwrap();
    let engine = Engine::create(dir.clone(), "daemon-test-pass", identity.clone()).unwrap();
    (engine, dir, identity)
}

/// Spawn the live loop on its own thread and return the stop flag
/// and join handle. The backend half stays on the test thread, so a
/// blocking mutation submit is completed by the loop concurrently.
pub(super) fn spawn_live_loop<S: ObjectStore + Send + Sync + 'static>(
    live: LiveDaemon<S>,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<Result<LiveSummary, LiveError>>,
)
where
    S::Error: std::fmt::Debug,
{
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_stop = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut live = live;
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &LiveConfig {
                interval: Duration::from_millis(10),
                error_base_delay: Duration::from_millis(5),
                error_max_delay: Duration::from_millis(20),
                max_consecutive_errors: 10,
                budgets: ResourceBudgets::default(),
            },
            &mut |_, _| {},
        )
    });
    (stop, handle)
}

/// A mailbox whose settlement always fails: every pass offers the
/// same envelope and every settle aborts the drain, so the loop's
/// error cap trips instead of the loop idling forever.
pub(super) struct SettlementFailingMailbox;

impl Mailbox for SettlementFailingMailbox {
    fn send(
        &mut self,
        _envelope: MailboxEnvelope,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, wyrd_sync::transport::mailbox::MailboxError> {
        Ok(Some(Delivery::new(
            DeliveryId::new(1),
            MailboxEnvelope {
                sender: DeviceId::from_bytes([0xD0; 32]),
                recipient: DeviceId::from_bytes([0xD0; 32]),
                ciphertext: "not-a-seal".to_string(),
            },
        )))
    }

    fn settle(
        &mut self,
        _id: DeliveryId,
        _disposition: Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Err(wyrd_sync::transport::mailbox::MailboxError::Transport(
            "boom".into(),
        ))
    }
}

/// A queue-backed mailbox fake: `send` enqueues, `recv` offers the
/// front without consuming, `Ack` removes, `Retry` requeues at the
/// back. Unknown ids are an error, matching the live adapter.
pub(super) struct QueueMailbox {
    pub(super) queue: std::collections::VecDeque<(DeliveryId, MailboxEnvelope)>,
    pub(super) next: u64,
}

impl QueueMailbox {
    pub(super) fn new() -> Self {
        QueueMailbox {
            queue: std::collections::VecDeque::new(),
            next: 1,
        }
    }

    pub(super) fn push(&mut self, envelope: MailboxEnvelope) {
        let id = DeliveryId::new(self.next);
        self.next += 1;
        self.queue.push_back((id, envelope));
    }
}

impl Mailbox for QueueMailbox {
    fn send(
        &mut self,
        envelope: MailboxEnvelope,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        self.push(envelope);
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, wyrd_sync::transport::mailbox::MailboxError> {
        Ok(self
            .queue
            .front()
            .map(|(id, envelope)| Delivery::new(*id, envelope.clone())))
    }

    fn settle(
        &mut self,
        id: DeliveryId,
        disposition: Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        use wyrd_sync::transport::mailbox::MailboxError;
        let Some(pos) = self.queue.iter().position(|(held, _)| *held == id) else {
            return Err(MailboxError::Transport("unknown delivery".into()));
        };
        match disposition {
            Disposition::Ack => {
                self.queue.remove(pos);
            }
            Disposition::Retry => {
                let held = self.queue.remove(pos).expect("position is valid");
                self.queue.push_back(held);
            }
        }
        Ok(())
    }
}
