# Full branch code review vs master, posted to PR

Review the current branch against `master` and post the review to its existing Nostr PR.

Repository root:!`pwd`
Current branch:!`git branch --show-current`
PR state:!`gate pr status`
Recent commits:!`git log master..HEAD --oneline`
Diff stats:!`git diff master..HEAD --stat`

## Hard constraints (violations abort the run)

**Sandbox**
* Never read, write, list, redirect to, or delete anything outside the repository: no `/tmp`, no home directory, no scratch checkouts, worktrees, or clones. Shell redirection (`>`, `>>`) outside the repository is forbidden — compare revisions with stdin pipes (`git show master:path | wc -l`), never scratch files. If a check needs a scratch file, put it in the worktree and delete it before posting, or skip the check and mark the claim `Unverified`. If the harness refuses a tool call, never retry it: route around it (stdin pipe, worktree scratch) or skip as `Unverified`. A refusal is information, never a fatal error — the run continues.
* Sole exception: read-only access to `~/.cargo/registry/src/**` for vendored dependency semantics.
* Never touch live external systems: VMs, containers, daemons, devices, relays, or their CLIs (`limactl`, `ssh`, `nix/microvm/run-microvm.sh`, `~/.lima`, `/var/lib/wyrd-microvm`), not even read-only probes. Validate orchestration code by reading it against repo templates and scripts. Anything needing a live machine is `Unverified` with that reason.

**Behavior**
* Do not modify files, add tests, create probes, commit, push, or change the branch.
* No subagents. No web search unless a current external fact is required and not derivable from the repo.
* Run everything in the foreground. Never background commands or redirect gate output to logs.
* Batch read-only commands into one invocation (devenv shell setup is slow, and hung calls burn their full timeout); gate reads (`gate pr status`, `gate review show`) batch the same way.
* Never infer paths from shortened project names; locate and verify first. Don't reopen unchanged files or repeat successful checks.

## Scope

* Review only `master..HEAD`. Use the current tree for context; don't turn pre-existing code into findings.
* Don't read prior review documents unless the issue, PR, or changed code requires them.
* Don't audit architecture, security, crypto, manifest, storage, or recovery boundaries the diff doesn't change or cross. Mark them `Not applicable` with a reason and one `file:line` citation.
* Docs/changelog-only changes: skip `docs/architecture.md` unless needed for a concrete finding.
* Rust source or architectural/config changes: read `docs/architecture.md` first, then only the normative docs relevant to the changed subsystem.
* The PR description is a frozen creation-time snapshot. Never request a description edit. Check the cover note and comments for the author's current claims, and direct staleness findings there (or at the code/docs if they're wrong).

## Base freshness (do first)

1. Compare `git merge-base HEAD master` with `master`. If they differ, `master..HEAD` includes the inverse of master commits the branch never saw.
2. Establish the branch-authored set with `git log master..HEAD --oneline` and `git diff --name-status $(git merge-base HEAD master)..HEAD`.
3. A path in `master..HEAD` that no branch commit touches is a stale-base artifact. Don't investigate it, don't read master-side history beyond establishing artifact vs authorship, and file no per-file findings. Deletions the branch never authored are a base problem, not a quality verdict.
4. Staleness is **Blocking** only if it pollutes the review (master-side commits in the log, or reversions of master files). If the log holds only the branch's own commits and the authored diff is clean, file one Non-blocking rebase note and review normally.

Then classify the changed paths from `git diff --name-status master..HEAD` before reading source.

## Resolve the PR and load history

`gate` exists inside the dev shell and resolves the PR itself from the
checked-out branch — never hand-pick, retype, or reconstruct a bech32
identifier. Obey literally:
* Run gate directly and read its output as-is. Never pipe or redirect it
  (`| head`, `| grep`, `> file`, command substitution): its exit code and
  refusal block are the signal. No `$(...)` id plumbing is needed.
* Don't nest shells (`devenv shell -- bash -lc ...`); the git guard shim refuses bare `git` there.

```
devenv shell -- gate pr status
devenv shell -- gate review show
```

This loads the PR state plus the full comment thread as plain text, oldest
first. `gate review show` refuses loud when no proposal matches; `gate pr
status` refreshes tip, PR, CI, and review state with observation times.

Extract every linked issue reference from the PR description, preserving exact `nostr:nevent1...` text. If the description points at issue history without a link, resolve the issue via the CHANGELOG entry's nevent or the branch name, and file a Non-blocking finding about the missing link. If the issue or PR has zero comments, record that once and don't repeat the lookup.

Treat issue and PR history as architectural specification. New commits can regress guardrails that earlier commits satisfied.

### First review
Read the linked issue body, all issue comments, and all PR comments. Build the complete guardrail list from them.

### Follow-up review
1. Read the previous review comment and identify commits/comments added since.
2. Read only those, plus the relevant changed diff.
3. Carry the previous guardrail list forward verbatim; change it only when new history changes a requirement. Rebuild from full history only if the previous list is unavailable or its provenance is ambiguous.
4. Report only what changed. Do not repost the full template.

## Analysis

Before drafting, identify: changed behavior; affected invariants; trust, durability, concurrency, and recovery boundaries; whether each issue is **introduced/regressed**, **pre-existing but relevant**, or a **stale-base artifact**; and the smallest affected package set.

Trace where authentication, authorization, integrity, and identity are actually established. Don't assume a type name or caller validation suffices.

Classify the diff (one or more): docs/changelog-only; formatting/comments-only; source-only; source + tests; build/config/tooling; protocol/format/security-sensitive; storage/durability/recovery-sensitive; transport/concurrency-sensitive. Classification selects validation evidence only; it never weakens substantive review.

Inspect all changed code plus enough surrounding code to understand handle, inode, path, lock, publication, and error lifecycles. Consider: stale handles; concurrent mutations; durability and recovery; conflicted heads; repeated flush/fsync; authorization failures; malformed input; resource ceilings; lock poisoning and shutdown; path/inode/handle identity after rename, unlink, replacement, and recreation.

## Guardrails

Extract every guardrail stated in issue/PR history, plus directly applicable invariants of the changed subsystem. Preserve `nostr:` references. Each gets exactly one verdict: `Satisfied`, `Violated`, `Unverified`, or `Not applicable`, with repo-relative `file:line` evidence. Never mark `Satisfied` merely because no violation was found; cite positive behavior or a passing test.

## Validation

Use the smallest scope the changed boundary justifies. Validation is evidence, not a substitute for reasoning.

* **Docs/changelog-only:** no test suite or clippy unless the PR claims code behavior. Run `cargo fmt --check` when applicable.
* **Rust source:** run each gate once (retry only after a source change or to diagnose a failure), using the smallest explicit package set from the repo's package mapping:
```
  devenv shell -- cargo check 2>&1
  devenv shell -- cargo nextest run 2>&1
  devenv shell -- cargo clippy 2>&1
  devenv shell -- cargo fmt --check 2>&1
```
* nextest uses the `default` profile explicitly (`.config/nextest.toml`; there is no `pr` profile). Don't run the full workspace when the affected set is known.
* Doctests: `cargo test -p <changed-pkg> --doc`, never `--workspace --doc` unless the change spans packages.
* Use `--profile slow` only when the default profile is insufficient, with the narrowest relevant filter.
* Protocol, format, trust, storage, durability, recovery, or transport changes may justify broader integration coverage, but only as far as the boundary requires.
* Existing test/e2e evidence counts only if its revision, command, profile, and boundary are established; otherwise it's context. Don't rerun expensive evidence just because it's documented.
* Piping through `tail` is allowed for presentation only, preserving exit status (`set -o pipefail`). Report the trailing nextest `Summary` (pass/fail/skip), clippy warning/error lines, and rustfmt result as the verdict. Don't claim a pass from truncated output. Report clippy separately from rustfmt. Name skipped tests only if visible in output; never rerun to enumerate them.
* Distinguish: pass, failure, warning, interruption, timeout, tool failure.

### E2E (revision-bound)
When the diff touches teardown, transport shutdown, or CLI mount paths, a Lima e2e result is valid only at the revision it ran on. With no e2e evidence at `HEAD` and a boundary the suite covers, mark the stop-budget guardrail `Unverified`. If the diff can't affect the e2e-covered boundary, mark the e2e guardrail `Not applicable` with evidence. Don't start a full e2e run merely because the PR mentions it.

## Performance

Only where the branch changes or crosses a performance boundary, with evidence from the changed code or a clearly affected path: repeated fs/fsync work, redundant serialization/hashing, repeated relay operations, lock contention or locks held across waits, unbounded allocation/queues, repeated KDF/crypto, polling where events would work, heavy test setup, new hot-path work. No theoretical micro-optimizations.

## Review format

Use exactly these sections:

```
## Overall assessment
## Changed behavior
## Guardrails
## Findings
## Architecture
## Tests
## Code quality
## Performance
## Suggested changes
## Review conclusion
```

Cover: overall assessment (no score, ranking, or LGTM verdict); changed behavior; every guardrail with verdict and evidence; bugs and edge cases, each **Blocking** or **Non-blocking** and tagged introduced / pre-existing-relevant; architecture and doc compliance; trust boundaries (authn, authz, crypto, manifests, IDs, snapshot authorship, capabilities, storage, untrusted input); durability, concurrency, recovery, and crash windows where relevant; test gaps (failure, concurrency, recovery); code quality; clippy findings; performance; specific actionable improvements. State explicitly when a relevant boundary is unaffected instead of auditing it.

## Process order

Resolve PR and history → check base freshness and `--name-status` → classify and scope validation → read architecture/normative docs if applicable → inspect changed code → extract and verify guardrails → run justified gates → draft once → post once.

## Post

Write the review body to a file in the worktree (never `/tmp`, never home —
writing this one file is the allowed worktree write), post it with gate
(which posts as Scout and verifies the comment landed), then delete the file:

```
devenv shell -- gate review post --body-file ./review-body.md
```

`gate review post` refuses an empty body and refuses when review already
covers the tip (each tip gets at most one review); a missing comment
afterward is unknown, never a cue to post again.

If publication fails, times out, or aborts: stop, report exact local and remote state, and do not retry or use another method. A successful post ends the review.

End the review body with exactly:

```
N blocking findings, M non-blocking findings, K guardrails unverified.
Reviewing model: <actual model name>
```
