use super::tests_harness::{plant_stale_obligation, replacement_crash_matrix};

/// The superseded-`0x01` trigger: the replacement commit is atomic at
/// every crash stage.
#[test]
fn replacement_commit_is_atomic_at_every_crash_stage() {
    replacement_crash_matrix(plant_stale_obligation);
}
