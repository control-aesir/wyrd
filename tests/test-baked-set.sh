#!/usr/bin/env bash
# tests/test-baked-set.sh — stub suite guarding the microVM image contract:
# every repo file a guest-run script sources or executes must be baked into
# /etc/wyrd-tests (nix/microvm/common.nix). The violation broke every
# microVM phase 1 when step-grammar.sh reached alpha-lima.sh but not the
# image, and Lima can never catch that class because it runs off the share.
# Pure bash + grep, no guest, no nix: run it anywhere with
# `bash tests/test-baked-set.sh`. (Wired into CI shell-tests alongside the
# step-grammar stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
die() { echo "  FAIL: $1" >&2; exit 1; }

# required_from <script>: basenames this guest-run script needs from the
# image. Directory prefixes may be variables ($SCRIPT_DIR, /etc/...), so
# the basename is taken first and only it must be a strict filename;
# anything dynamic (the generated env file, shellcheck directives) fails
# the character class and is excluded. Both the $SCRIPT_DIR form (Lima
# share) and the /etc/wyrd-tests form (microVM image) resolve to the same
# basename, so one list covers both harnesses.
required_from() {
  {
    grep -hoE 'source[[:space:]]+[^[:space:];]+' "$1" 2>/dev/null || true
    grep -hoE 'python3[[:space:]]+[^[:space:];]+\.py' "$1" 2>/dev/null || true
  } | sed -E 's#["'"'"']$##; s#^.*[/"'"'"']##' | grep -E '^[A-Za-z0-9_.-]+\.(sh|py)$' || true
}

GUEST_SCRIPTS="alpha-lima.sh alpha-microvm-legs.sh alpha-common.sh"
REQUIRED=""
for _s in $GUEST_SCRIPTS; do
  REQUIRED="$REQUIRED
$(required_from "$SCRIPT_DIR/$_s")"
done
REQUIRED="$(printf '%s\n' "$REQUIRED" | grep -E '.' | sort -u)"
unset _s

BAKED="$(grep -hoE '"wyrd-tests/[^"]+"' "$ROOT/nix/microvm/common.nix" \
  | sed -E 's#"wyrd-tests/##; s#"$##' | sort -u)"

[[ -n "$REQUIRED" ]] || die "no required files extracted (parser broken)"
[[ -n "$BAKED" ]] || die "no baked files extracted (parser broken)"
pass "extracted $(printf '%s\n' "$REQUIRED" | wc -l | tr -d ' ') required and $(printf '%s\n' "$BAKED" | wc -l | tr -d ' ') baked files"

MISSING="$(comm -23 <(printf '%s\n' "$REQUIRED") <(printf '%s\n' "$BAKED"))"
[[ -z "$MISSING" ]] || die "guest-run scripts need files missing from the image: $(printf '%s' "$MISSING" | tr '\n' ' ')"
pass "every sourced file is baked into the image"

echo "baked-set: $PASS checks passed"
