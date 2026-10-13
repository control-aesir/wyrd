#!/usr/bin/env bash
# tests/test-bash-syntax.sh — stub suite for
# tests/check-bash-syntax.sh (the pre-commit bash -n entry). Pure
# bash, no harness, no guest, no nix: run it anywhere with
# `bash tests/test-bash-syntax.sh`. It pins the sweep semantics the
# gate depends on: a broken file fails even when preceded by clean
# ones (the exact `bash -n file...` footgun the wrapper exists for),
# and clean files pass. (Wired into the CI shell-tests job
# alongside the other harness stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASS=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf 'echo ok\n' > "$TMP/clean-a.sh"
printf 'echo ok\n' > "$TMP/clean-b.sh"
# Unterminated if: bash -n rejects it on its own.
printf 'if true; then\n  echo broken\n' > "$TMP/broken.sh"

# Clean files pass, alone and together.
bash "$SCRIPT_DIR/check-bash-syntax.sh" "$TMP/clean-a.sh" \
  || { echo "FAIL: clean file rejected" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: clean file accepted"
bash "$SCRIPT_DIR/check-bash-syntax.sh" "$TMP/clean-a.sh" "$TMP/clean-b.sh" \
  || { echo "FAIL: clean files rejected" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: clean files accepted"

# A broken file fails on its own.
rc=0
bash "$SCRIPT_DIR/check-bash-syntax.sh" "$TMP/broken.sh" 2>/dev/null || rc=$?
[[ "$rc" != 0 ]] || { echo "FAIL: broken file accepted alone" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: broken file rejected alone"

# A broken file fails when preceded by clean ones: this is the
# regression the wrapper pins (bare `bash -n` would parse only the
# first argument and report green).
rc=0
bash "$SCRIPT_DIR/check-bash-syntax.sh" "$TMP/clean-a.sh" "$TMP/broken.sh" "$TMP/clean-b.sh" 2>/dev/null || rc=$?
[[ "$rc" != 0 ]] || { echo "FAIL: broken file accepted after clean ones" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: broken file rejected after clean ones"

echo "bash-syntax: $PASS checks passed"
