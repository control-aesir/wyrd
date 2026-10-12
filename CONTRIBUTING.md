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

Apply these labels in a deliberate triage pass after creating the issue.
Never pass them to `ngit issue create --label`: creation-time labels are
lowercased, embedded permanently in the issue event, and cannot be removed
afterwards — not even with `ngit issue label --remove-label`, which only
retracts labels applied during triage. A wrong label at creation is forever.
Use `ngit issue label` so priority case is preserved and the label is a
separate, manageable event.

The current milestone labels are:

- `release:v0.1.0-alpha`: shipped; retained on its issues for history.
- `release:v0.2.0-alpha`: shipped; retained on its issues for history.
- `release:v0.3.0-alpha`: the current milestone (see `ROADMAP.md`).
- `release:v0.4`, `release:v0.5`, `release:v0.6`, `release:v0.7`,
  `release:v0.8`: bare, with no qualifier suffix.
- `release:v0.9.0-beta`: required before entering feature-complete Beta.
- `release:v1.0`: general availability.
- `release:backlog`: explicitly deferred beyond the immediate roadmap. This
  is the parked state: no triaged issue is ever without a `release:*` label.

Do not stack milestone labels. Swap with `ngit issue label --remove-label`
before applying the new one through the available project tooling.

## Code Changes

- Use Conventional Commits.
- Work on `pr/<name>` branches; do not commit directly to `master`.
- Keep `wyrd-format` free of networking, async, and FUSE dependencies.
- Run the relevant checks locally while the PR is in draft. Marking the PR
  ready (`ngit pr ready`) moves it to open and triggers CI for PRs
  touching the workflow's filtered paths (docs-only PRs trigger none).
