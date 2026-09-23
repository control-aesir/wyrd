# Collaboration Workflow

This is the project workflow for issues and pull requests over ngit.

## 1. Create An Issue

Describe the problem or proposed change, its context, and a concrete
verification target. Use a clear Conventional Commit-style subject when the
issue maps directly to an implementation change. Implementation issues
state their persistent-format impact in one line — which durable
formats or protocol bytes change and what that means for
`docs/upgrade-contract.md`, or explicitly `none`.

```bash
ngit issue create --subject "feat(format): path-level tree mutation" \
  --body "$(cat issue.md)" --json
```

Do not add project labels during creation. Creation-time labels are lowercased
and embedded permanently in the issue event.

## 2. Triage The Issue

Apply exactly one label from each category:

- Type: `bug`, `enhancement`, or `chore`.
- Priority: `P0` through `P4`.
- Milestone: one `release:*` label.

```bash
ngit issue label <issue> --label enhancement --json
ngit issue label <issue> --label P2 --json
ngit issue label <issue> --label release:v0.1.0-alpha --json
```

Do not stack milestones. Update the labels deliberately when scope or
priority changes. Keep the issue open while work is in progress.

These three categories are a closed set: do not invent labels outside them
(`test`, `docs`, component names, and the like are Conventional Commit
scopes for the subject line, not labels). Creation labels cannot be removed,
so a wrong label is permanent — when in doubt, list existing issues first to
see the labels in use rather than guessing a new one. Capture the created
issue's id from the `create --json` output and reuse it; never run `create`
again to "check" something, and verify any unfamiliar subcommand flag with
`--help` before running a command that writes.

## 3. Create A PR

Create a `pr/<name>` branch from the current `master`. Make focused commits
using Conventional Commit subjects. The first push creates the PR when the
branch uses the required `pr/` prefix.

```bash
git checkout -b pr/<name>
git push -u origin pr/<name>
```

Verify the branch before every commit: `checkout -b` on an already
existing name fails and leaves you wherever you were, so a quiet
checkout followed by a commit can land work on the wrong branch —
including `master`, where nothing commits directly. Chain the check
into the commit so a wrong branch aborts the sequence:

```bash
git branch --show-current && git commit -m "..."
```

Hooks verify the staged tree, not the worktree: each commit in a
multi-commit stack must compile standalone, or keep the PR to a single
commit. A stack that only builds as a whole fails the hooks on every
commit but the last.

Set the PR to draft immediately after the first push. CI runs on
`ready_for_review` only, for PRs touching the paths listed in the workflows
under `.ngit/act/workflows/` (`workflow.yml` covers `crates/**`,
`Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml`, `flake.*`,
the workflow itself, and `.ngit/scripts/*.sh`) — docs-only PRs run no CI,
and drafts run none. The merge check below verifies the final revision is
green.
Work stays in draft until it is ready:

```bash
ngit pr draft <pr> --reason "work in progress" --json
```

Reference the issue in the PR description with a `nostr:nevent1...` URI. Do
not rely on an unqualified issue number or raw event ID.

## 4. Review And Update

Inspect the PR and comments with ngit. Address concrete findings with new
commits, run the relevant checks locally, and push the branch again. Keep
the PR in draft while iterating. Do not change branches during a review:
all related work stays on the PR's branch until it merges — switching
branches mid-review orphans the review context and the CI attached to
the branch.

```bash
ngit pr view <pr> --comments --json
ngit pr comment <pr> --body "Addressed in <commit>." --json
git push origin pr/<name>
```

When the work is ready, mark the PR ready. This moves it from draft to
open and triggers CI for PRs touching the filtered paths
(`ready_for_review` is the only `pull_request` trigger; drafts and
docs-only PRs trigger none):

```bash
ngit pr ready <pr> --reason "ready for review" --json
```

If CI fails on a PR, it posts the truncated failure tail as a PR comment
and returns the PR to draft automatically. Push the fix (drafts run no
CI) and mark ready again to re-trigger. Master-push failures have no PR
to report to and change no PR state.

Do not rewrite published history unless the workflow explicitly requires it.
Keep unrelated worktree changes out of the PR.

## 5. Merge

Before merging, verify the PR is `open` (not `draft`), the final revision
is correct, and CI is green where CI runs. CI results attach to revisions,
so check green for the final revision itself — a green run on an older
revision does not qualify:

```bash
ngit ci status <pr> --require-ci-trust maintainer-directed --json
```

Docs-only PRs run no CI: merge those on green local hooks plus review. Use
ngit's merge command, then publish `master`.

```bash
ngit merge <pr> --json
git push origin master
```

The merge command creates the merge commit locally; the push publishes it and
the applied status. Confirm the PR is `applied` afterward.

## 6. Resolve The Issue

Commits only auto-resolve issues when the commit message contains `fixes` or
`resolves` followed by the issue ID or `nostr:nevent1...` reference. If the
issue was not linked that way, resolve it explicitly after the merge:

```bash
ngit issue resolved <issue> \
  --reason "Implemented and merged in nostr:nevent1..." --json
```

Use `ngit issue close` for rejected, duplicate, or otherwise non-completed
work. Use `ngit issue resolved` for work that was completed.

## 7. CI trigger and identifier discipline

Manual `ngit ci trigger` is retry-only: tag and branch pushes already fire
the matching workflows, and duplicate triggers cannot be cancelled (`ci
stop` ends all CI for the repo). Check `ngit ci status <commit>` before
triggering anything. Signed per-job logs for failures arrive as PR comments
and as Blossom `.asc` links; `ci status --log-tail` only embeds tails for
non-successful jobs.

Never retype a bech32 identifier (npub, nevent, naddr) from memory:
transcription silently corrupts them. Resolve once into a variable or file
and reuse it:

```bash
COORD=$(ngit ci status <commit> --json | python3 -c "...")
ngit ci trigger "$COORD" <ref> --workflow <file> --json
ngit pr list --json --offline | python3 -c "..." # stash the PR id, then
ngit merge $(cat /tmp/prid.txt) --json
```
