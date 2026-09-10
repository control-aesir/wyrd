# Goal

{{One-sentence statement of the desired end state.}}

# Context

- {{Why this is needed — the spec section, review finding, or motivating
  constraint.}}
- {{Which docs govern the work (`docs/architecture.md`, `docs/object-model.md`,
  `docs/trust.md`, `docs/epochs.md`) and what they currently say.}}
- {{Any decisions already recorded in decision records that this must not
  relitigate.}}

# Current state

- {{What exists today (files, sections, status lines) and what is missing,
  underspecified, or marked DRAFT.}}
- {{Current status claims in docs that will change (e.g. "Status: DRAFT").}}

# Decisions taken

| Decision  | Choice                          |
| --------- | ------------------------------- |
| {{Topic}} | {{Choice + one-line rationale}} |
| {{Topic}} | {{Choice + one-line rationale}} |

# Open decisions to resolve here

1. {{Question to settle, with options and a recommendation if one exists.}}

# Files to create / modify

## 1. `{{path}}` — {{purpose}}

{{What changes, in enough detail that an agent can implement without
re-deriving the design.}}

# Verification

1. {{Doc-level check: cross-references valid, status lines updated, decision
   records extended, no dangling "DRAFT" claims.}}
2. Code-level: `devenv shell -- cargo check && devenv shell -- cargo nextest run`
   green (docs-only changes still run it — hooks run clippy/rustfmt/typos on
   every commit).
3. {{Any new test that pins an invariant the change introduces.}}

# Branch / PR

- Branch: `pr/<branch>` (never commit to `master` directly)
- This issue references the plan; the PR description references this issue as
  `nostr:nevent1...` (the ID `ngit issue create` returns)
- Commit messages: Conventional Commits

# Out of scope (intentionally)

- {{Explicit list of adjacent work this issue deliberately does not touch, so
  reviewers and future agents don't try to fold it in.}}
