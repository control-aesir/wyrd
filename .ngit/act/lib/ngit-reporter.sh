#!/usr/bin/env bash
# Shared failure reporter for the act CI workflows (rust-ci.yml, nix.yml).
#
# On `pull_request` failures: post a truncated failure tail on the PR and
# return it to draft. Master pushes and dispatch runs have no PR to draft.
# NGIT_NSEC lives only in the calling step's env: earlier steps run
# untrusted PR code and must never see it. The CI identity must be a
# confirmed co-maintainer; third-party PRs run with empty secrets by
# design, so a withheld secret skips gracefully instead of failing. After
# auto-draft the author pushes the fix (drafts run no CI) and marks ready
# again to re-trigger.
#
# Sourced (not executed) from a `run:` step under `set -euo pipefail`,
# with these variables set:
#   NGIT_NSEC             the CI bot credential (empty skips gracefully)
#   GITHUB_SHA            checked-out head sha (primary resolution key)
#   NGIT_CI_TRIGGER_EVENT coordinator trigger event, when provided
#   PR_BRANCH             pull_request.head.ref, when provided
#   RUNNER_TEMP           temp dir for the secret file
# Arguments: failure-tail log files to include, in order.
#
# PR resolution keys on the checked-out head sha first: it is exact even
# with several PRs open and needs no trigger context. The trigger-event
# and head-ref paths below stay as alternatives for coordinators that
# provide them — the installed coordinator documents no
# NGIT_CI_TRIGGER_EVENT, and synthesized pull_request events carry no
# head.ref (GITHUB_REF is just refs/pull/ngit). Every ngit call passes
# --repo explicitly: the coordinator checks out over https/file with no
# nostr remote, and ngit fails rather than guessing. Unresolvable runs
# fail loudly, never skip silently.
#
# This repo's naddr (ngit 3.0.1 rejects the raw 30617: coordinate form);
# refresh it with `ngit repo --json | jq -r .coordinate` if the repo is
# republished.
REPO_NADDR="naddr1qqz8w7tjvspzpv7ftn3nm75yxfnpr69h48qsk7xl9p65cw93q6jtcqvkhxl97nj2qvzqqqrhnyzuuxrw"

# Bound every ngit call: a hung relay must fail fast and loud, never
# stall the reporter into the job timeout. Kills are safe on the
# read path (list/view/status are side-effect free); on the publish
# path a kill risks a half-done report, which still beats a hung job.
# `timeout` may be absent on some runners; degrade to a direct call.
bounded_ngit() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 120 ngit "$@"
  else
    ngit "$@"
  fi
}

report_failure_to_pr() {
  if [ "$#" -eq 0 ]; then
    echo "report_failure_to_pr: no log files given" >&2
    exit 1
  fi

  # Withheld bot credential: nothing to publish with, and no
  # connected relay for this identity. Skip without masking the
  # real test failure.
  if [ -z "${NGIT_NSEC:-}" ]; then
    echo "NGIT_NSEC is not configured; skipping PR failure report."
    exit 0
  fi

  command -v jq >/dev/null || {
    echo "jq is required for PR resolution" >&2
    exit 1
  }

  command -v git >/dev/null || {
    echo "git is required for PR resolution" >&2
    exit 1
  }

  # ngit commands anchor on a git repository, but the act checkout can
  # carry a stub or no .git metadata at all. A bare init suffices: the
  # target travels in --repo explicitly, so no remotes are needed.
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    git init -q
  fi

  local PR_ID=""
  # Primary resolution: match the checked-out head sha against
  # per-revision commits in each open/draft PR's CI record. Multiple
  # matches fail loudly below — never guess.
  if [ -n "${GITHUB_SHA:-}" ]; then
    local sha_matches=()
    local candidates candidate
    candidates="$(
      bounded_ngit --repo "$REPO_NADDR" pr list --json --status open,draft |
        jq -r '.[].id' || true
    )"
    # Intentional word splitting: ngit emits one id per line.
    for candidate in $candidates; do
      if bounded_ngit --repo "$REPO_NADDR" pr view "$candidate" --json |
        jq -e --arg sha "$GITHUB_SHA" '
          ([(.ci.runs // [] | .[].commit),
            (.ci.outdated // [] | .[].commit)]
           | map(select(. != null))
           | any(. == $sha))' >/dev/null 2>&1; then
        sha_matches+=("$candidate")
      fi
    done
    if [ "${#sha_matches[@]}" -eq 1 ]; then
      PR_ID="${sha_matches[0]}"
    elif [ "${#sha_matches[@]}" -gt 1 ]; then
      echo "Head sha matches multiple PRs; refusing to guess: ${sha_matches[*]}" >&2
      exit 1
    fi
  fi

  # Alternative for coordinators that export the trigger event: ngit maps
  # a 1618 proposal or a 1619 revision to its PR.
  if [ -z "$PR_ID" ] && [ -n "${NGIT_CI_TRIGGER_EVENT:-}" ]; then
    PR_ID="$(
      bounded_ngit --repo "$REPO_NADDR" \
        ci status "$NGIT_CI_TRIGGER_EVENT" --json |
        jq -r '.target.pr // empty' || true
    )"
  fi

  # Alternative for triggers that still carry the branch (e.g. opened).
  # Listed branches render as `pr/<name>(<short-id>)`, so match the
  # bare name too.
  if [ -z "$PR_ID" ] && [ -n "${PR_BRANCH:-}" ]; then
    PR_ID="$(
      bounded_ngit --repo "$REPO_NADDR" pr list --json |
        jq -r --arg branch "$PR_BRANCH" '
          .[] |
          select(.branch == $branch or
            (.branch | startswith($branch + "("))) |
          .id
        ' | head -n1 || true
    )"
  fi

  if [ -z "$PR_ID" ] || [ "$PR_ID" = "null" ]; then
    echo "Could not resolve the PR for this run; refusing to skip silently." >&2
    echo "trigger=${NGIT_CI_TRIGGER_EVENT:-unknown} branch=${PR_BRANCH:-unknown} sha=${GITHUB_SHA:-unknown}" >&2
    exit 1
  fi

  echo "Reporting CI failure on PR: $PR_ID"

  # Keep the secret out of every other process environment: file it,
  # drop it from env, and remove the file as soon as ngit is done.
  NGIT_NSEC_FILE="$RUNNER_TEMP/ngit-nsec"
  printf '%s' "$NGIT_NSEC" > "$NGIT_NSEC_FILE"
  chmod 600 "$NGIT_NSEC_FILE"
  unset NGIT_NSEC
  trap 'rm -f "$NGIT_NSEC_FILE"' EXIT

  # Truncated failure tail: last lines of whichever gate logs exist.
  # Capped so the comment stays a readable signal, not a log dump.
  COMMENT_BODY="/tmp/failure-comment.md"
  {
    echo "## CI failed - PR returned to draft"
    echo ""
    echo "Commit: \`${GITHUB_SHA:-unknown}\`"
    echo ""
    echo "The failing run's tail is below (truncated). Push the fix"
    echo "(drafts run no CI) and mark ready again to re-trigger."
    echo ""
    local log
    for log in "$@"; do
      if [ -f "$log" ]; then
        echo "<details>"
        echo "<summary><code>$(basename "$log")</code> (last 100 lines)</summary>"
        echo ""
        echo '```'
        tail -n 100 "$log"
        echo '```'
        echo "</details>"
        echo ""
      fi
    done
  } > "$COMMENT_BODY"

  # Bound the event payload: keep the header, cut the tail to size.
  if [ "$(wc -c < "$COMMENT_BODY")" -gt 8000 ]; then
    tail -c 8000 "$COMMENT_BODY" > "$COMMENT_BODY.trimmed"
    {
      echo "## CI failed - PR returned to draft"
      echo ""
      echo "(Failure tail truncated to the last 8 KB.)"
      echo ""
      cat "$COMMENT_BODY.trimmed"
    } > "$COMMENT_BODY"
    rm -f "$COMMENT_BODY.trimmed"
  fi

  bounded_ngit --repo "$REPO_NADDR" \
    --nsec-file "$NGIT_NSEC_FILE" \
    pr comment "$PR_ID" \
    --body "$(cat "$COMMENT_BODY")" \
    --json

  bounded_ngit --repo "$REPO_NADDR" \
    --nsec-file "$NGIT_NSEC_FILE" \
    pr draft "$PR_ID" \
    --reason "CI failed - returned to draft automatically" \
    --json
}
