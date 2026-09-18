#!/usr/bin/env bash
# Shared PR lifecycle helpers for the act CI pipeline
# (.ngit/act/workflows/workflow.yml): failure reporting and auto-draft.
#
# Sourced (not executed) from a `run:` step under `set -euo pipefail`,
# with these variables set:
#   NGIT_NSEC             the CI bot credential (empty skips gracefully)
#   GITHUB_SHA            checked-out head sha (primary resolution key)
#   NGIT_CI_TRIGGER_EVENT coordinator trigger event, when provided
#   PR_BRANCH             pull_request.head.ref, when provided
#   RUNNER_TEMP           temp dir for the secret file
#
# The CI identity must be a confirmed co-maintainer; third-party runs
# carry empty secrets by design, so withheld credentials skip gracefully
# instead of failing. NGIT_NSEC lives only in the calling step's env:
# earlier steps run untrusted code and must never see it.
#
# PR resolution keys on the checked-out head sha first: it is exact even
# with several PRs open and needs no trigger context. The trigger-event
# and head-ref paths stay as alternatives for coordinators that provide
# them — the installed coordinator documents no NGIT_CI_TRIGGER_EVENT,
# and synthesized pull_request events carry no head.ref (GITHUB_REF is
# just refs/pull/ngit). Every ngit call passes --repo explicitly: the
# coordinator checks out over https/file with no nostr remote, and ngit
# fails rather than guessing. Unresolvable runs fail loudly, never skip
# silently.
#
# This repo's naddr (ngit 3.0.1 rejects the raw 30617: coordinate form);
# refresh it with `ngit repo --json | jq -r .coordinate` if the repo is
# republished.
REPO_NADDR="naddr1qqz8w7tjvspzpv7ftn3nm75yxfnpr69h48qsk7xl9p65cw93q6jtcqvkhxl97nj2qvzqqqrhnyzuuxrw"

# Event-cache override: the pipeline restores/saves this directory around
# red runs so relay reads warm up instead of cold-syncing full repo state
# on every reporter invocation. Defaults here so the helpers work
# standalone; a calling step may export its own value first.
: "${NGIT_CACHE_DIR:=$HOME/.ngit-event-cache}"

# Bound every ngit call: a hung relay must fail fast and loud, never
# stall the job into its timeout. Kills are safe on the read path
# (list/view/status are side-effect free); on the publish path a kill
# risks a half-done report, which still beats a hung job. `timeout` may
# be absent on some runners; degrade to a direct call.
bounded_ngit() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 120 ngit "$@"
  else
    ngit "$@"
  fi
}

# Resolve the PR for this run and print its id. Fails loudly when no
# path matches — never guess. Needs jq, git, and a git repository
# anchor (a bare init suffices: the target travels in --repo, so no
# remotes are needed). Callers keep their own secret policy.
resolve_pr() {
  command -v jq >/dev/null || {
    echo "jq is required for PR resolution" >&2
    exit 1
  }

  command -v git >/dev/null || {
    echo "git is required for PR resolution" >&2
    exit 1
  }

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
    # Overall deadline: every ngit call cold-syncs full repo state, so
    # per-call timeouts alone still allow a multi-minute loop. Expire
    # the whole scan loudly instead of stalling into the job timeout.
    # Overridable for tests; production default bounds the scan while
    # leaving healthy (tens of seconds) syncs room.
    local deadline=$((SECONDS + ${RESOLUTION_DEADLINE_SECS:-240}))
    for candidate in $candidates; do
      if [ "$SECONDS" -ge "$deadline" ]; then
        echo "PR resolution by head sha timed out" >&2
        exit 1
      fi
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

  printf '%s' "$PR_ID"
}

# File the bot credential for ngit publish calls: write it with
# owner-only permissions, drop it from the environment so no other
# process inherits it, and remove the file on exit.
seal_nsec() {
  NGIT_NSEC_FILE="$RUNNER_TEMP/ngit-nsec"
  printf '%s' "$NGIT_NSEC" > "$NGIT_NSEC_FILE"
  chmod 600 "$NGIT_NSEC_FILE"
  unset NGIT_NSEC
  trap 'rm -f "$NGIT_NSEC_FILE"' EXIT
}

# Post a truncated failure tail on the PR and return it to draft.
# Arguments: failure-tail log files to include, in order.
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

  local PR_ID
  PR_ID="$(resolve_pr)"
  echo "Reporting CI failure on PR: $PR_ID"
  seal_nsec

  # Truncated failure tail: last lines of whichever gate logs exist.
  # Capped so the comment stays a readable signal, not a log dump. Plain
  # markdown headings, not <details> collapsibles: renderers escape raw
  # HTML, so the tags would show up as literal text.
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
        echo "### \`$(basename "$log")\` (last 100 lines)"
        echo ""
        echo '```'
        tail -n 100 "$log"
        echo '```'
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

# Draft a newly opened PR: silent state change, no comment. The project
# works draft-first (CI runs on ready_for_review only), so creation
# drafts immediately instead of waiting for a human pass.
draft_new_pr() {
  # Withheld bot credential: nothing to publish with. Skip without
  # failing the run — the author can draft manually.
  if [ -z "${NGIT_NSEC:-}" ]; then
    echo "NGIT_NSEC is not configured; skipping auto-draft."
    exit 0
  fi

  local PR_ID
  PR_ID="$(resolve_pr)"
  seal_nsec

  bounded_ngit --repo "$REPO_NADDR" \
    --nsec-file "$NGIT_NSEC_FILE" \
    pr draft "$PR_ID" \
    --reason "new PRs start as drafts" \
    --json
}
