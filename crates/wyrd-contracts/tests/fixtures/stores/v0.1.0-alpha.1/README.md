# v0.1.0-alpha.1 fixture

Genuine previous-release store bytes: produced by the tagged
`v0.1.0-alpha.1` tree (commit c0582305) via a throwaway in-crate
emitter test (since removed), committing genesis, one child
transition, and an epoch-1 capability through that release's own
durable codec, store passphrase `contracts`.

Deliberately manifest-free: the manifest record layout changed
after this release, so manifests are covered by the loud-refusal
rows, not by replay. Transitions and capability records are the
Level-1 continuity evidence: the current build must open and
replay these bytes.

Regeneration: check out the tag in a worktree, re-append the
emitter (see the upgrade-contracts issue thread), run it, copy
DRIVE, CURRENT, store-key.wrap, and commits/ here. Never
regenerate with current code: that would silently convert this
into a second dev fixture.
