#!/usr/bin/env bash
# tests/test-relay-forensics.sh — stub suite for the relay-flap
# forensics wiring (the 2026-10-08 ~30s relay outages left neither
# guest logs nor a host load record, so neither layer could be
# classified). Pure bash, no guest, no nix: run it anywhere with
# `bash tests/test-relay-forensics.sh`. It pins the two halves the
# classification depends on: the relay guest's journal timer in
# nix/microvm/relay.nix, and the host availability logger in
# nix/microvm/run-microvm.sh. (Wired into the CI shell-tests job
# alongside the other harness stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELAY_NIX="$SCRIPT_DIR/../nix/microvm/relay.nix"
RUNNER="$SCRIPT_DIR/../nix/microvm/run-microvm.sh"

PASS=0

# The relay guest dumps its current-boot journal into the state share
# on a timer: teardown destroys the VM, and the relay carries no ssh
# key by design, so this dump is the only post-mortem path.
grep -q 'wyrd-relay-journal' "$RELAY_NIX" \
  || { echo "FAIL: relay.nix has no journal persistence unit" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal unit declared"
grep -q 'OnUnitActiveSec' "$RELAY_NIX" \
  || { echo "FAIL: relay journal unit is not on a repeating timer" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal dump repeats on a timer"
grep -q 'journalctl -b' "$RELAY_NIX" \
  || { echo "FAIL: relay journal dump does not capture the current boot" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal dump captures the current boot"
grep -q 'relay-journal.log' "$RELAY_NIX" \
  || { echo "FAIL: relay journal dump target path missing" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal dump lands in the run logs"

# The host logger backgrounds with the lock fd closed: an orphaned
# logger holding fd 9 would wedge the flock for every later run and
# --teardown (the exact fd-inheritance class the e2e-guard stubs
# pin). Without this pin the rule returns via a one-line edit.
grep -q 'availability_loop 9>&-' "$RUNNER" \
  || { echo "FAIL: availability logger backgrounds without closing the lock fd" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: availability logger closes the lock fd"
# Per-tick open-append-close: the phase-1 guest pre-clean unlinks
# $RUN/logs once per run, and a held fd would keep writing the
# unlinked inode invisibly past the wipe.
grep -q '>> "$AVAIL_LOG"' "$RUNNER" \
  || { echo "FAIL: availability logger does not append per tick" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: availability logger appends per tick"
# Stopped on both exits: explicitly after a green suite, and in
# teardown() (EXIT trap) for the failure path. A logger that
# outlives the run writes a torn-down run's file.
[[ "$(grep -c 'LOGGER_PID=""' "$RUNNER")" == 1 ]] \
  || { echo "FAIL: availability logger is not cleared after the suite" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: availability logger stops after the suite"
grep -q 'kill "$LOGGER_PID"' "$RUNNER" \
  || { echo "FAIL: teardown does not kill the availability logger" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: teardown kills the availability logger"

echo "relay-forensics: $PASS checks passed"
