use crate::CliError;
use std::path::Path;
use wyrd_format::envelope::VERSION as ENVELOPE_VERSION;
use wyrd_sync::control::CONTROL_VERSION;

/// Advisory preflight against the staged binary: run its
/// lock-free self-report and compare with this build's. A staged
/// binary that cannot report is broken — refuse before the swap.
/// Anything it reports is advisory per [`preflight_report`]: the
/// lines print, and the transaction proceeds.
pub(crate) fn run_preflight(next: &Path) -> Result<(), CliError> {
    let output = std::process::Command::new(next)
        .arg("__build_info")
        .output()
        .map_err(|source| {
            CliError::Usage(format!(
                "staged binary failed to execute ({source}); refusing the swap"
            ))
        })?;
    if !output.status.success() {
        return Err(CliError::Usage(
            "staged binary refused its self-report; refusing the swap".to_string(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let staged = parse_build_info(&text).ok_or_else(|| {
        CliError::Usage(format!(
            "staged binary reported unparsable versions ({text:?}); refusing the swap"
        ))
    })?;
    for line in preflight_report(&own_build_info(), &staged) {
        println!("{line}");
    }
    Ok(())
}

/// A binary's lock-free self-report for the advisory preflight
/// (U2-A): compiled format versions, comparable without opening
/// any store. `__build_info` prints exactly these lines; the
/// preflight compares them across the running and staged builds.
pub(crate) struct BuildInfo {
    pub app: String,
    pub envelope: u8,
    pub control: u8,
}

pub(crate) fn own_build_info() -> BuildInfo {
    BuildInfo {
        app: env!("CARGO_PKG_VERSION").to_owned(),
        envelope: ENVELOPE_VERSION,
        control: CONTROL_VERSION,
    }
}

pub(crate) fn render_build_info(info: &BuildInfo) -> String {
    format!(
        "update build: {}\nupdate envelope: 0x{:02x}\nupdate control: 0x{:02x}",
        info.app, info.envelope, info.control
    )
}

/// Parse the three lines `__build_info` prints. `None` means the
/// staged binary is broken — itself a refusal, since a binary that
/// cannot report its versions cannot be verified either.
pub(crate) fn parse_build_info(output: &str) -> Option<BuildInfo> {
    let mut lines = output.lines();
    let app = lines.next()?.strip_prefix("update build: ")?.to_owned();
    let envelope =
        u8::from_str_radix(lines.next()?.strip_prefix("update envelope: 0x")?, 16).ok()?;
    let control = u8::from_str_radix(lines.next()?.strip_prefix("update control: 0x")?, 16).ok()?;
    if app.is_empty() {
        return None;
    }
    Some(BuildInfo {
        app,
        envelope,
        control,
    })
}

/// Numeric-prefix app-version ordering for the downgrade warning:
/// compare leading `major.minor.patch` numerically, ignore the
/// prerelease tail. Unparsable versions compare equal — no warning
/// on what cannot be ordered.
pub(crate) fn app_version_older(staged: &str, current: &str) -> bool {
    fn numeric(prefix: &str) -> Vec<u64> {
        prefix
            .split(['.', '-'])
            .take_while(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .filter_map(|part| part.parse().ok())
            .collect()
    }
    let (mut a, mut b) = (numeric(staged), numeric(current));
    a.resize(3, 0);
    b.resize(3, 0);
    a < b
}

/// The advisory preflight: compare the staged binary's self-report
/// against this build's. Today's format versions are single values
/// with no minimum-readable concept, so no version inequality is
/// structurally impossible — the report is printed and the
/// transaction proceeds, except for a downgrade, which warns
/// (older alphas may not read stores newer ones wrote; the
/// verification in the gap decides). Advisory means exactly this:
/// cheap, lock-free, and never the load-bearing check.
pub(crate) fn preflight_report(own: &BuildInfo, staged: &BuildInfo) -> Vec<String> {
    let mut lines = vec![
        format!("update preflight: staged build {}", staged.app),
        format!(
            "update preflight: envelope 0x{:02x} -> 0x{:02x}, control 0x{:02x} -> 0x{:02x}",
            own.envelope, staged.envelope, own.control, staged.control
        ),
    ];
    if app_version_older(&staged.app, &own.app) {
        lines.push(format!(
            "update preflight: warning: staged {} is older than running {}; verification decides",
            staged.app, own.app
        ));
    }
    lines
}
