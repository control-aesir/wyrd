# Contributing

Wyrd is pre-alpha software. Prefer small, focused changes that preserve the
architecture and documented contracts. Read `AGENTS.md` and
`docs/architecture.md` before making changes.

## Collaboration

Follow [`docs/collaboration-workflow.md`](docs/collaboration-workflow.md) for
the complete issue, triage, PR, review, and merge workflow.

Every open issue should have exactly one label from each category:

- Type: `bug`, `enhancement`, or `chore`.
- Priority: `P0`, `P1`, `P2`, `P3`, or `P4`.
- Milestone: one `release:*` label.

Apply these labels in a deliberate triage pass after creating the issue. Do
not pass them to `ngit issue create --label`: creation-time labels are
lowercased and embedded in the issue event. Use `ngit issue label` so priority
case is preserved and the label is a separate, manageable event.

The current milestone labels are:

- `release:v0.1.0-alpha`: minimum set required to cut the first Alpha; critical bugs only.
- `release:v0.2.0-alpha`: non-blocking features and follow-ups for the next Alpha.
- `release:v0.9.0-beta`: required before entering feature-complete Beta.
- `release:v1.0.0`: general availability.
- `release:backlog`: explicitly deferred beyond the immediate roadmap.

Do not stack milestone labels. Remove the old milestone before applying a new
one through the available project tooling.

## Code Changes

- Use Conventional Commits.
- Work on `pr/<name>` branches; do not commit directly to `master`.
- Keep `wyrd-format` free of networking, async, and FUSE dependencies.
- Run the relevant checks before publishing a PR.
