//! The `foo@N` version-selection grammar: pure path rules for
//! addressing one version of a conflicted path. `@N` is lookup syntax,
//! never a stored entry: nothing synthetic exists in the projected
//! namespace and `readdir` never lists it. Versions are numbered
//! deterministically in SnapshotId byte order, so the same head set
//! always numbers the same way. The grammar requires a conflict at the
//! unversioned name and applies only where the literal path does not
//! exist — real stored names win at every level — so a stored name
//! containing `@` is addressed by its own spelling first, and if that
//! stored name is itself conflicted, its versions are reachable one
//! suffix further (`name@1@2`). Only the final suffix is ever
//! interpreted.

use wyrd_format::Component;

use super::types::{ConflictVersion, ViewError};

/// A parsed version reference: component `index` carries `@version` on
/// top of the stored `name`.
pub(crate) struct VersionRef {
    pub index: usize,
    pub name: String,
    pub version: u32,
}

/// Parse the version reference: the rightmost component carrying an
/// `@N` suffix with `N >= 1` and a non-empty name. Anything else —
/// no suffix, a non-numeric or zero version, an empty name — is not
/// grammar, and the path stays a literal lookup.
pub(crate) fn parse_ref(components: &[Component]) -> Option<VersionRef> {
    components
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, component)| {
            let (name, suffix) = component.as_str().rsplit_once('@')?;
            if name.is_empty() {
                return None;
            }
            let version: u32 = suffix.parse().ok()?;
            (version >= 1).then(|| VersionRef {
                index,
                name: name.to_string(),
                version,
            })
        })
}

/// Rebuild the lookup prefix with the version suffix stripped: the
/// conflict itself is resolved at the unversioned name. A name that is
/// not a valid component can never address a conflict — a stored name
/// containing `@` is tried literally first, and only a conflict at
/// that literal spelling reaches this function.
pub(crate) fn unversioned_prefix(
    components: &[Component],
    target: &VersionRef,
) -> Result<Vec<Component>, ViewError> {
    let mut prefix: Vec<Component> = components[..target.index].to_vec();
    prefix.push(Component::new(&target.name).map_err(|_| ViewError::NotFound)?);
    Ok(prefix)
}

/// Order conflict versions deterministically (SnapshotId byte order)
/// and select version N (1-based). Out-of-range versions select
/// nothing: the caller maps that to not-found.
pub(crate) fn select_version(
    versions: &mut [ConflictVersion],
    version: u32,
) -> Option<&ConflictVersion> {
    versions.sort_by(|a, b| a.snapshot.as_bytes().cmp(b.snapshot.as_bytes()));
    versions.get((version - 1) as usize)
}
