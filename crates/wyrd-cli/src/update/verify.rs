use crate::CliError;
use std::path::Path;
use wyrd_format::envelope::VERSION as ENVELOPE_VERSION;
use wyrd_sync::control::{ControlError, CONTROL_VERSION};
use wyrd_sync::durable::DurableError;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, EngineError};
use zeroize::Zeroizing;

use super::identity::*;
use super::snapshot::*;
/// How a `__update_verify` failure reports: operational failures are
/// usage errors with no verdict (the checks never completed — a
/// verdict without checks would be fabrication, the `Unobserved`
/// rule applied to upgrades), while decode failures are
/// incompatibilities naming their invariant.
#[derive(Debug)]
pub(crate) enum VerifyFailure {
    Operational(CliError),
    Incompatible { invariant: u8, detail: String },
}

/// Map an open failure to its report. Version-shaped refusals name
/// invariant 10 with the offending version; explicitly-versioned
/// formats that fail to decode name invariant 2 with the underlying
/// error; custody and contention are operator-fixable and carry no
/// verdict; anything else propagates as an operational error.
pub(crate) fn classify_open_error(drive_dir: &Path, error: EngineError) -> VerifyFailure {
    match error {
        EngineError::Durable(DurableError::StoreLocked) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "{} is held by a running process; stop it first",
                drive_dir.display()
            )))
        }
        EngineError::Durable(DurableError::StoreKey(error)) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "store key failed ({error}); check the passphrase file"
            )))
        }
        EngineError::Durable(DurableError::Crypto(error)) => {
            VerifyFailure::Operational(CliError::Usage(format!(
                "custody decryption failed ({error}); check the passphrase and identity files"
            )))
        }
        EngineError::MalformedKeystore => VerifyFailure::Operational(CliError::Usage(format!(
            "{}: keystore is missing or malformed",
            drive_dir.display()
        ))),
        EngineError::Durable(DurableError::Control(
            ControlError::UnknownVersion(version) | ControlError::UnknownKind(version),
        )) => VerifyFailure::Incompatible {
            invariant: 10,
            detail: format!("unknown control version 0x{version:02x}"),
        },
        EngineError::Durable(other) => VerifyFailure::Incompatible {
            invariant: 2,
            detail: format!("explicitly-versioned format failed to decode: {other}"),
        },
        other => VerifyFailure::Operational(CliError::Engine(other)),
    }
}

/// The verification boundary (`docs/update.md` §5): open the store
/// with the new binary, replay durable facts through its readers,
/// and prove it authored nothing. Prints the U4 report in every
/// case the checks complete; operational failures print no verdict
/// at all. Exit 0 if and only if the report is verified.
pub(crate) fn run_update_verify(
    drive_dir: &Path,
    identity: DeviceIdentitySecret,
    passphrase: &Zeroizing<String>,
) -> Result<(), CliError> {
    let incompatible = |invariant: u8, detail: String| -> CliError {
        let status = CompatibilityStatus::Incompatible { invariant, detail };
        println!("{}", render_compatibility(&status));
        CliError::Verification(match status {
            CompatibilityStatus::Incompatible { invariant, detail } => {
                format!("incompatible (invariant {invariant}: {detail})")
            }
            _ => unreachable!("just constructed incompatible"),
        })
    };
    let pre = snapshot_durable_files(drive_dir)?;
    let engine = match Engine::open_keystore(drive_dir.to_path_buf(), passphrase, identity) {
        Ok(engine) => engine,
        Err(error) => match classify_open_error(drive_dir, error) {
            VerifyFailure::Operational(error) => return Err(error),
            VerifyFailure::Incompatible { invariant, detail } => {
                return Err(incompatible(invariant, detail));
            }
        },
    };
    let mut checks = vec![format!(
        "store opens under this build (envelope 0x{ENVELOPE_VERSION:02x}, control 0x{CONTROL_VERSION:02x})"
    )];
    let seq = engine.current();
    checks.push(format!("{seq} commits replay through this build's readers"));
    let heads = match engine.live_heads() {
        Ok(heads) => heads,
        Err(EngineError::InvalidHead(rejection)) => {
            return Err(incompatible(
                1,
                format!("live snapshot failed authorization: {rejection:?}"),
            ));
        }
        Err(error) => match classify_open_error(drive_dir, error) {
            VerifyFailure::Operational(error) => return Err(error),
            VerifyFailure::Incompatible { invariant, detail } => {
                return Err(incompatible(invariant, detail));
            }
        },
    };
    checks.push(format!(
        "{} live heads authorize under this build",
        heads.len()
    ));
    checks.push("epoch keys restored for held epochs".to_owned());
    let transitions = engine.membership_log().observed_ids();
    let genesis = engine.membership_log().canonical_genesis();
    let post = snapshot_durable_files(drive_dir)?;
    let diffs = pre.diff(&post);
    if !diffs.is_empty() {
        // Anything authored is a membership-affecting write until
        // proven otherwise: the keystore carries the transition log,
        // so a keystore difference names invariant 6; commit-set
        // differences name invariant 8.
        let (invariant, what) = if diffs.iter().any(|d| d == "keystore changed") {
            (6u8, "verification emitted durable state")
        } else {
            (8u8, "verification authored commits")
        };
        return Err(incompatible(
            invariant,
            format!("{}: {}", what, diffs.join(", ")),
        ));
    }
    match genesis {
        Some(tip) => checks.push(format!(
            "membership log byte-identical: {} transitions, genesis {tip}",
            transitions.len()
        )),
        None => checks.push(format!(
            "membership log byte-identical: {} transitions, no genesis yet",
            transitions.len()
        )),
    }
    checks.push(format!(
        "no commits authored: CURRENT and {} commit files unchanged",
        post.commits.len()
    ));
    println!(
        "{}",
        render_compatibility(&CompatibilityStatus::Verified { checks })
    );
    Ok(())
}
