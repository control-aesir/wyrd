#!/usr/bin/env bash
# tests/test-runner-fd.sh — stub pinning the run-lock fd discipline in
# nix/microvm/run-microvm.sh: every backgrounded launch (a line ending
# in a lone `&`) must close fd 9 (`9>&-`), like the virtiofsd, qemu,
# and suite launches, or a SIGTERM'd build sibling holds the whole-run
# flock past a build failure and refuses the next run and --teardown.
# Pure bash + grep, no guest, no nix: run it anywhere with
# `bash tests/test-runner-fd.sh`. (Wired into CI shell-tests alongside
# the step-grammar stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
die() { echo "  FAIL: $1" >&2; exit 1; }

RUNNER="$ROOT/nix/microvm/run-microvm.sh"
[[ -f "$RUNNER" ]] || die "runner missing at $RUNNER"

# A trailing `&&` is not a launch; only a lone `&` backgrounds.
LAUNCHES="$(grep -cE '[^&]&$' "$RUNNER" || true)"
(( LAUNCHES > 0 )) || die "no background launches found (parser broken)"
pass "found $LAUNCHES background launch sites"

LEAKY="$(grep -E '[^&]&$' "$RUNNER" | grep -v '9>&-' || true)"
[[ -z "$LEAKY" ]] || die "background launches without 9>&-: $LEAKY"
pass "every background launch closes fd 9"

echo "runner-fd: $PASS checks passed"
