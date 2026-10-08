#!/usr/bin/env bash
# Agent-facing review helpers for Nostr PRs: resolve-pr, pr-context,
# post-comment.
#
# Thin wrappers over ngit so review agents stop re-deriving ceremony (and
# bech32 ids) from `--help` output on every run. Called from
# ../../.agents/prompts/branch-review.md; exposed in dev shells as
# `review` (see devenv.nix).
#
# Subcommands:
#   resolve-pr [--online]       print the PR id for the current branch
#                               (stdout carries only the id, so capture it
#                               in a variable; never retype it)
#   pr-context <id> [--online]  print the PR view with its full comment
#                               thread as one JSON document
#   post-comment <id>           read the body from stdin, post it once as
#                               the review signer, and verify it landed
#
# Reads are offline-first (local cache, no relay round trip); pass
# --online for a network refresh. Posting always goes online, exactly
# once, and fails loud: no retry, no fallback, no alternate method.
# An empty body is refused before any ngit call.
#
# Shared constants (REPO_NADDR) and per-call bounding come from ngit.sh,
# the CI pipeline's library next to this file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Library location for ngit.sh. Normally the sibling file next to this
# script, but devenv installs this script into the Nix store without
# its sibling, so devenv.nix exports REVIEW_LIB_DIR pointing at the
# stored scripts directory instead.
LIB_DIR="${REVIEW_LIB_DIR:-$SCRIPT_DIR}"
# shellcheck disable=SC1091
source "$LIB_DIR/ngit.sh"

# Review identity for published comments. Overridable for tests; the
# prompt pins the default.
REVIEW_SIGNER="${REVIEW_SIGNER:-Wyrd AI Review}"

usage() {
  cat >&2 <<'EOF'
Usage:
  review.sh resolve-pr [--online]
  review.sh pr-context <id> [--online]
  review.sh post-comment <id>   (body on stdin)
EOF
  exit 1
}

# Offline-first flag pair for read commands. `--offline` is a
# per-subcommand flag (not global like `--repo` and `--json`), so it
# must follow the subcommand: `ngit --repo N pr list --json --offline`.
# Echoes `--offline` unless the caller asked for a network refresh.
read_flags() {
  if [ "${1:-}" = "--online" ]; then
    return 0
  fi
  printf '%s' "--offline"
}

# Resolve the current branch to its PR id and print only the id. Zero
# or multiple matches fail loudly; never guess. Starts from the
# caller's checkout: hook runners export GIT_DIR into their hooks, so
# repo discovery is reset to plain cwd lookup first.
cmd_resolve_pr() {
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
  local online="${1:-}"
  [ "$online" = "--online" ] || [ -z "$online" ] || usage

  local branch
  branch="$(git branch --show-current)" || {
    echo "resolve-pr: cannot determine the current branch" >&2
    exit 1
  }
  if [ -z "$branch" ]; then
    echo "resolve-pr: cannot determine the current branch (detached HEAD?)" >&2
    exit 1
  fi

  local matches
  matches="$(
    bounded_ngit --repo "$REPO_NADDR" pr list --json $(read_flags "$online") |
      jq -r --arg branch "$branch" '
        .[] |
        select(.branch == $branch or
          (.branch | startswith($branch + "("))) |
        .id
      '
  )"
  if [ -z "$matches" ]; then
    echo "resolve-pr: no PR matches branch '$branch'; refusing to guess" >&2
    exit 1
  fi
  local count
  count="$(printf '%s\n' "$matches" | grep -c .)"
  if [ "$count" -gt 1 ]; then
    echo "resolve-pr: branch '$branch' matches multiple PRs; refusing to guess:" >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
  printf '%s\n' "$matches"
}

# Print the PR view with its full comment thread as one JSON document.
cmd_pr_context() {
  local id="${1:-}"
  [ -n "$id" ] || usage
  local online="${2:-}"
  [ "$online" = "--online" ] || [ -z "$online" ] || usage

  bounded_ngit --repo "$REPO_NADDR" \
    pr view "$id" --json $(read_flags "$online") --comments
}

# Post stdin as a comment on the PR, exactly once, then verify the
# comment landed. Verification requires a matching comment that was
# not present before publishing: threads can hold older identical
# bodies, and those must never satisfy the check. Any failure stops
# loudly: no retry (a retry risks a double post) and no alternate
# publication method.
cmd_post_comment() {
  local id="${1:-}"
  [ -n "$id" ] || usage
  [ -z "${2:-}" ] || usage

  local body
  body="$(cat)"
  if [ -z "$body" ]; then
    echo "post-comment: refusing to post an empty body" >&2
    exit 1
  fi

  local before
  before="$(bounded_ngit --repo "$REPO_NADDR" pr view "$id" --json --offline --comments |
    jq -r '(.comments // [])[].id')"

  bounded_ngit --signer "$REVIEW_SIGNER" --repo "$REPO_NADDR" \
    pr comment "$id" --body "$body" --json

  local view
  view="$(bounded_ngit --repo "$REPO_NADDR" pr view "$id" --json --offline --comments)"
  if printf '%s' "$view" |
    jq -e --arg body "$body" --arg before "$before" '
      ((.comments // []) | map(select(.body == $body) | .id)
        - ($before | split("\n"))) | length > 0' >/dev/null; then
    echo "post-comment: verified comment present on $id" >&2
  else
    echo "post-comment: no new matching comment on $id after posting; refusing to retry" >&2
    exit 1
  fi
}

cmd="${1:-}"
case "$cmd" in
  resolve-pr) shift; cmd_resolve_pr "$@" ;;
  pr-context) shift; cmd_pr_context "$@" ;;
  post-comment) shift; cmd_post_comment "$@" ;;
  *) usage ;;
esac
