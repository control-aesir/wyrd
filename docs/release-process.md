# Release process (hard-won, v0.2.0-alpha)

Manual flow through v0.x, fully automated by v1. The `dist.yml` x86_64
leg is part of the manual flow, not separate from it: without it there
is no mirror tarball to fetch in step 5.

## Retrospective: what went wrong and right cutting v0.2.0-alpha

Wrong:

- Three duplicate proposals for one branch. Every push on
  `pr/release-0.2` published a new PR instead of updating (leading
  hypothesis: the dot vs the normalized proposal name breaks
  push-to-proposal matching; dash-only branches update fine).
  Each dupe burned a full CI run on shared hardware.
- Kept pushing on a theory ("the force push did it") after the
  first surprise instead of stopping to diagnose. The fast-forward
  push forked too, which disproved the theory one push too late.
- Rebases treated as routine: a rebase forces `--force`, and a
  rewritten history is exactly the case that needs `ngit send
  --in-reply-to`, not a bare push.
- Drifted from the odin skill: unannounced ssh, background pipes
  that died with ephemeral shells. Cost two corrections.
- First published as the default identity; the server refused with
  `application_author_mismatch`. Release authority belongs to the
  app owner (control here), not the repo default. Verify who can
  publish before attempting, not after failing.
- Marked a PR ready with the tip newer than the last review (even a
  docs-only delta). Transparent in the reply, but still corner-cutting.
- Left A-3 (dist archive naming) unverified until the last hour.

Right:

- Stopped on "ground yourself", re-read the skill references, and
  diagnosed from evidence instead of pushing a fourth time.
- Two consecutive identical microVM failures called a regression;
  the Lima rerun going green called a flake. Both calls held.
- Asked instead of guessed on every scope fork (gate flip, milestone
  set, manual-vs-automated), which avoided permanent issue-label
  damage and seven junk issues.
- Verified hashes at every transfer (mirror fetch, renames,
  publish); all four release hashes matched end to end.
- Killed the stuck Lima run by PID on both sides before rerunning,
  instead of stacking a second suite on a wedged one.
- Filed an issue for everything found, including the build.sh
  rename bug and the negative-contract gap, so the next pass
  inherits the list instead of the memory.
- Page-lock re-pins done twice with slot-copy verification first;
  no pin drifted silently.
- Review rounds shepherded to explicit verdicts (four on the CLI
  fix, three on the docs), which is why the merge decisions were
  cheap at the end.

## Cut checklist

1. Prep PR: version bump, `CHANGELOG.md ## [Unreleased]` entries,
   fresh fixture under `tests/fixtures/stores/<tag>/`, re-enabled
   replay test, upgrade-contract brought current. No gates, no tag.
2. Confirm `nix build .#wyrd-dist` archives under the new version name.
3. Cut PR: flip `dist.yml` (`if: false`), drop the `release.yaml`
   banner, rename `[Unreleased]` to the version, carve the scope line
   in `ROADMAP.md`, re-pin any drifted page slots. Merge.
4. Green gates, revision-bound to the release tip: microVM from the
   gate plus Lima locally. A green run on a pre-rebase tip does not
   cover the rebased tip; re-run after the final rebase.
4. Pre-tag compatibility read (runbook step 1 in `release.yaml`).
   Tagging is the point of no return.
5. Tag `v<version>` on the merge commit, push the tag. This fires
   `dist.yml`, which builds x86_64 natively and uploads to the
   Blossom mirrors. There is no cancel (`ci stop` ends all CI), so
   check `ci status` before any manual trigger, and never trigger
   by hand as well.
6. Fetch the linux-x86_64 tarball by its printed sha256 from any
   listed mirror into `dist/` under its canonical name and verify
   the hash. CI uploads with an ephemeral key, so the hash
   comparison is the trust anchor: never skip it. Record the hash
   at once: the run log is the primary source, and the signed
   `.asc` record lands on the odin Blossom server as backup.
7. `build.sh <version> --strict --remote-builders aarch64-darwin
   x86_64-darwin aarch64-linux` in the devenv shell. Name the
   systems: a bare `--strict` re-attempts linux-x86_64 locally and
   fails without an x86 builder. Input is pinned to the release tag
   in a detached worktree, never the working copy. Re-running over
   `dist/` needs the read-only hash-prefixed files deleted first.
   `--verify` needs system FUSE on macOS or the just-built binary
   dies in dyld (exit 134): environment gap, not a broken binary.
8. Run the linux-aarch64 artifact in the Lima guest (unpack, `--version`,
   `init` + `sync status` on a scratch drive) before publishing.
9. `ngit release publish <version>` with `--blossom-server` (plus
   `--relay` as needed), as the app owner — `--signer control`
   here; the default identity is refused fail-closed with
   `application_author_mismatch`, which is the check working, not
   an error to route around. v0.2.0-alpha assets went to
   `blossom.primal.net`. The first publish creates the `wyrd`
   application owned by the publisher; repository maintainership
   alone grants no release authority, so decide the owner first.
10. Record findings on the release issue for the next automation pass.

## ngit lessons (paid for in duplicate PRs and CI burns)

- No dots in `pr/` branch names. Every push on `pr/release-0.2`
  published a new proposal instead of updating; dash-only branches
  update fine. Until confirmed otherwise, treat dotted names as
  fork-on-push.
- After any rebase, update via `ngit send --in-reply-to <PR>`,
  never a bare push. A bare `--force` after a rebase is a new-PR
  machine until proven otherwise.
- A fast-forward bare push is safe on dash-named branches (all
  five sync-now updates went through that way). On the dotted
  branch even a fast-forward forked, so the rule is about the
  name, not the push shape: bare pushes only where updates have
  already been observed to work; anywhere else, `ngit send
  --in-reply-to` from the start.
- Verify every push with `ngit pr list --json --offline` and confirm
  exactly one proposal per branch before doing anything expensive.
  A surprise `[new branch]` line or a second entry means stop and
  diagnose, never push again on the theory.
- Closing the stale duplicate is safe; the review thread stays
  readable on it. Point the live PR at it with a comment (comments
  are the robust channel; the description field has shown stale or
  synthesized text).
- Creation labels on issues are permanent. Milestone labels only
  after creation, one call per category.
- Do not trust PR CI state at face value: this cut saw `stale`,
  phantom `running`, and an auto-draft job's red, all while the
  code gates were green. Read `revision_matched` plus the run
  list; master CI plus local gates carried the merge decisions.
  (A CI failure auto-returns its PR to draft with the failure tail
  as a comment — a draft PR with red CI may just be that loop, not
  a verdict on the code.)

## Suite lessons

- Lima: compound shell commands (`&&` chains, redirections) do not
  survive the `limactl shell` channel; run steps singly. A killed run
  leaves the wrapper, guest contract, relay, and mounts behind: kill
  by PID on both sides before rerunning. A repeated `FAIL:` line is
  a stop; a run that needs `kill -9` to reap is itself a data point.
- odin: announce every ssh before running it. The agent locks
  intermittently and needs a physical touch; batch around that.
  Background pipes die with ephemeral shells — open the pipe exactly
  per the skill pattern and poll the local mirror. Never touch
  odin's master worktree; verify tips with `rev-parse` after every
  sync. Teardown with `--teardown` and confirm `tap-r` is gone.
- microVM forensics: leg logs first (`leg-*.out`), then the matching
  `mount-*.err` by mtime. A leg that ends with no `die`/`FAIL` line
  is a silent `set -e` death (unguarded command substitution is the
  classic shape); everything after it, including the sibling leg's
  truncation and the clean unmounts, is runner-trap collateral.
  Non-verbose mounts log no per-request lines, so absence of errors
  proves nothing. One rerun distinguishes flake from regression;
  two identical failures are a regression until proven otherwise.
- Only one full Lima suite at a time; odin microVM is host-global
  behind `/var/lib/wyrd-microvm/lock`. Check both before launching.
- e2e evidence is revision-bound: a green run on a pre-rebase tip
  does not cover the rebased tip.

## Docs mechanics that bite during releases

- `ROADMAP.md` and `docs/trust.md` sections are page-check pinned:
  any edit drifts `map.lock.json`. Re-read the slot copy, confirm
  the mustContain phrases hold, re-pin with `--update`, verify green.
- `CHANGELOG.md`: `ngit release publish` extracts the section
  matching the version; the `[Unreleased]` rename is part of the cut,
  not the prep.
- Fixture per release under `tests/fixtures/stores/<tag>/` with a
  digest pin in the replay test; the generator stays `#[ignore]`d
  so CI replays frozen bytes. Next release re-runs the generator
  under its tag and repoints the constant.
- Normative-doc changes need an additional review pass beyond the
  branch review: `trust.md`, `epochs.md`, `object-model.md`, and
  the contract doc of whichever invariant the release touches
  (`upgrade-contract.md` here). Report the normative surface file
  by file and route it explicitly; an uncommitted diff is cheap,
  an unreviewed normative edit is not.
