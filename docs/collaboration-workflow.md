# Collaboration Workflow

This is the project workflow for issues and pull requests over ngit,
driven through `gate` (verbs encode the correct procedure; `gate help`
lists them, the gate skill documents them). Run `gate` inside the repo's
`devenv` shell; never pipe or redirect its output.

## 1. Create An Issue

Describe the problem or proposed change, its context, and a concrete
verification target. Use a clear Conventional Commit-style subject when the
issue maps directly to an implementation change. Implementation issues
state their persistent-format impact in one line — which durable
formats or protocol bytes change and what that means for
`docs/upgrade-contract.md`, or explicitly `none`.

```bash
gate issue create --subject "feat(format): path-level tree mutation" \
  --body-file issue.md
```

Never add project labels during creation. Creation-time labels are lowercased,
embedded permanently in the issue event, and cannot be removed through a
later `ngit label` event — `--remove-label` only retracts labels applied
during triage. Create issues bare and label them in triage.

## 2. Triage The Issue

Apply exactly one label from each category:

- Type: `bug`, `enhancement`, or `chore`.
- Priority: `P0` through `P4`.
- Milestone: one `release:*` label. Match it against the milestone
  thesis in `ROADMAP.md` (including the v0.2 entry test) — never
  guess from recency or from the current release line. Visible future work
  with no commitment takes `release:backlog`; no triaged issue is ever
  without a `release:*` label.

```bash
gate issue label <id> --type enhancement
gate issue label <id> --priority P2
gate issue label <id> --milestone release:v0.3.0-alpha
```

Do not stack milestones. Swap deliberately with
`gate issue label <id> --remove-label <old> --milestone <new>` when scope
or priority changes. Keep the issue open while work is in progress.

These three categories are a closed set: do not invent labels outside them
(`test`, `docs`, component names, and the like are Conventional Commit
scopes for the subject line, not labels). Creation labels cannot be removed
through a later ngit label event, so prefer creating bare — when in doubt,
list existing issues first to see the labels in use rather than guessing a
new one (`gate issue list --limit 20` lists open issues; `--search`,
`--label` and `--status` refine it, never pipe through `head`/`grep`). Capture the created
issue's id from the `create` output and reuse it; never run `create`
again to "check" something, and verify any unfamiliar subcommand flag with
`--help` before running a command that writes.

## 3. Create A PR

Create a `pr/<name>` branch from the current `master` (worktrees are linked
under `../pr/<name>`; agents never touch the `master` worktree, so the
human creates the worktree or an explicit exception covers it). Make
focused commits using Conventional Commit subjects. The first push creates
the PR when the branch uses the required `pr/` prefix, and gate drafts it
immediately (`auto_draft` in `gate.toml`, replacing the old CI draft job):

```bash
git worktree add -b pr/<name> ../pr/<name> master
# ... work, commit ...
gate pr push
```

`gate pr push` refuses a dirty tree or a non-`pr/` branch instead of
publishing half-finished work, and knows first push vs fast-forward vs
rewrite. Verify the branch and its draft state afterward:

```bash
gate pr status
```

Hooks verify the staged tree, not the worktree: each commit in a
multi-commit stack must compile standalone, or keep the PR to a single
commit. A stack that only builds as a whole fails the hooks on every
commit but the last.

CI runs on `ready_for_review` only, for PRs touching the paths listed in
the workflows under `.ngit/act/workflows/` (`workflow.yml` covers
`crates/**`, `Cargo.toml`, `Cargo.lock`, `deny.toml`,
`rust-toolchain.toml`, `flake.*`, the workflow itself, and
`.ngit/scripts/*.sh`) — docs-only PRs run no CI, and drafts run none.
The merge check below verifies the final revision is green. Work stays in
draft (from the first push's auto-draft) until it is ready.

Set the PR description at creation
(`git push -o 'title=...' -o 'description=...'`, which `gate pr push` does
not forward — use a plain `git push` for a titled first push, then
`gate pr push` after) or right after pushing
(`ngit pr set-cover-note <id> --body "..."`; no gate verb sets the cover
note): link the issue with a `nostr:nevent1...` URI and summarize the
change. An empty description is a review finding. Do not rely on an
unqualified issue number or raw event ID.

## 4. Review And Update

Read the PR thread as plain text, oldest first. Address concrete findings
with new commits, run the relevant checks locally, and push the branch
again. Keep the PR in draft while iterating. Do not change branches during
a review: all related work stays on the PR's branch until it merges —
switching branches mid-review orphans the review context and the CI
attached to the branch.

```bash
gate pr status
gate review show
# ... address findings, commit, push ...
gate pr push
```

Fire the reviewer (its prompt and model come from `gate.toml`), then block
until it covers the tip — never a shell polling loop:

```bash
gate review run
gate review wait
```

Replies to review comments post as yourself, not as the review signer
(`gate review post` always posts as the review signer, so it is
reviewer-only). Reply from the PR worktree:

```bash
ngit pr comment <id> --body "Addressed in <commit>."
```

When the work is ready, mark the PR ready and let CI run. `gate pr ready`
refuses unless the review covers the tip and CI is green on it, naming
whichever leg is missing; `gate ci run` performs the correct CI procedure
for the current tip, and `gate ci wait` blocks until CI settles (skip the
wait when `ci status` is `none` — docs-only PRs run no CI):

```bash
gate ci run
gate ci wait
gate pr ready
```

If CI fails on a PR, it posts the truncated failure tail as a PR comment
and returns the PR to draft automatically. Push the fix (drafts run no
CI) and mark ready again to re-trigger. Master-push failures have no PR
to report to and change no PR state.

Do not rewrite published history unless the workflow explicitly requires it.
A sync merge from the target (pulling `master` in for review tooling) is
fine — gate tolerates it at merge time. A stacked merge that pulls in
another branch's commits is not: rebase those out. Keep unrelated
worktree changes out of the PR.

## 5. Merge

Before merging, verify the PR is `open` (not `draft`), the final revision
is correct, and CI is green where CI runs. CI results attach to revisions,
so check green for the final revision itself — a green run on an older
revision does not qualify:

```bash
gate pr status
gate ci status
```

Docs-only PRs run no CI: merge those on green local hooks plus review.
Merge from the `master` worktree — agents never touch `master`, so merging
needs the user or an explicit exception — then publish `master` with a
human-signed push (gate never pushes the target):

```bash
gate pr merge pr/<name>
git push origin master
```

The merge command creates the merge commit locally; the push publishes it and
the applied status. Confirm the PR is `applied` afterward with
`gate pr status`.

## 6. Resolve The Issue

Commits only auto-resolve issues when the commit message contains `fixes` or
`resolves` followed by the issue ID or `nostr:nevent1...` reference. If the
issue was not linked that way, resolve it explicitly after the merge:

```bash
gate issue resolve <id> --reason "Implemented and merged in nostr:nevent1..."
```

Use `gate issue close` for rejected, duplicate, or otherwise non-completed
work. Use `gate issue resolve` for work that was completed.

## 7. CI trigger and identifier discipline

`gate ci run` is the trigger procedure — never hand-roll `ngit ci trigger`
commands. Manual triggering is retry-only anyway: tag and branch pushes
already fire the matching workflows, and duplicate triggers cannot be
cancelled. Check `gate ci status` before triggering anything. Signed
per-job logs for failures arrive as PR comments and as Blossom `.asc`
links.

Never retype a bech32 identifier (npub, nevent, naddr) from memory:
transcription silently corrupts them. Let gate resolve them — `gate pr id`
resolves the current branch once, and every verb takes it from there.
Never pipe gate output through `python3 -c`, `head`, `grep`, or into files
to plumb IDs between commands; gate's exit code and refusal block are the
signal. Verify any unfamiliar subcommand flag with `--help` before running
a command that writes.

## 8. Releases

Cutting a release follows the checklist and runbook in
`docs/release-process.md` (version bump, changelog, fixture, gates,
tag, multi-platform build, publish), plus the ngit, suite, and docs
lessons recorded there from the v0.2.0-alpha cut. The `release:*`
milestone on the release issue is the tracking spine; the v0.3
umbrella carries the next cut.
