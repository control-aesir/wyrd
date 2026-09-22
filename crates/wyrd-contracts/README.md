# wyrd-contracts

Wyrd's cross-crate architectural contract suite: one named test per review
contract, each composed end to end through the public APIs of
`wyrd-format → wyrd-sync → wyrd-fuse → wyrd-daemon`, so an invariant
regression fails a test instead of a deployment. `wyrd-cli` is a
binary-only process host, so no crate can depend on it; its edges are
pinned by contract 34's member-wide dependency check instead.

## What belongs here

- One test per architectural contract, named after the invariant it pins;
  the catalog with each contract's normative doc home lives in `src/lib.rs`
- The shared rig (`support.rs`): a real engine over a scratch store, a
  signed membership/announcement fixture with honest transport roots, and
  the in-memory relay/bulk/object fakes the composition needs
- Composition tests only: everything runs through public APIs, never crate
  internals

## What does not belong here

Library code, fixtures other crates import, or tests that could live in a
single crate's own suite (unit behavior belongs in that crate). The suite
is a workspace leaf: it depends on every crate and nothing depends on it.

## Rules

- A contract test names its invariant and cites the normative doc section,
  so a failure reads as a violated contract, not a broken unit.
- Contracts exercise the real verification paths (signatures,
  authorization, classification): fixture signatures verify through the
  public paths, so drift fails here locally instead of as a generic
  rejection in whichever contract runs first.