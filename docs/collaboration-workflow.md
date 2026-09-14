# Collaboration Workflow

This is the project workflow for issues and pull requests over ngit.

## 1. Create An Issue

Describe the problem or proposed change, its context, and a concrete
verification target. Use a clear Conventional Commit-style subject when the
issue maps directly to an implementation change.

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

## 3. Create A PR

Create a `pr/<name>` branch from the current `master`. Make focused commits
using Conventional Commit subjects. The first push creates the PR when the
branch uses the required `pr/` prefix.

```bash
git checkout -b pr/<name>
git push -u origin pr/<name>
```

Set the PR to draft immediately after the first push. CI only runs on
`ready_for_review`, so work stays in draft until it is ready:

```bash
ngit pr draft <pr> --reason "work in progress" --json
```

Reference the issue in the PR description with a `nostr:nevent1...` URI. Do
not rely on an unqualified issue number or raw event ID.

## 4. Review And Update

Inspect the PR and comments with ngit. Address concrete findings with new
commits, run the relevant checks locally, and push the branch again. Keep
the PR in draft while iterating.

```bash
ngit pr view <pr> --comments --json
ngit pr comment <pr> --body "Addressed in <commit>." --json
git push origin pr/<name>
```

When the work is ready, mark the PR ready. This moves it from draft to
open and triggers CI (`ready_for_review` is the only `pull_request`
trigger in `.ngit/act/workflows/rust-ci.yml`):

```bash
ngit pr ready <pr> --reason "ready for review" --json
```

Do not rewrite published history unless the workflow explicitly requires it.
Keep unrelated worktree changes out of the PR.

## 5. Merge

Before merging, verify the PR is `open` (not `draft`), the final revision
is correct, and CI is green. Use ngit's merge
command, then publish `master`.

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
