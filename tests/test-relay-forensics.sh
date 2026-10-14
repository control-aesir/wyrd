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
# The destination must be the host-visible run log dir, not just a
# file with the right name: a one-segment change to the share path
# keeps every name assertion green while writing where no run reads.
grep -q '/mnt/wyrd-state/run/logs/relay-journal.log' "$RELAY_NIX" \
  || { echo "FAIL: relay journal dump is not aimed at the host-visible run logs" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal dump aims at the host-visible run logs"
# The 60s freshness bound needs AccuracySec: systemd's default 1min
# scheduling slop would otherwise make the worst-case gap ~2min.
grep -q 'AccuracySec' "$RELAY_NIX" \
  || { echo "FAIL: relay journal timer has no accuracy bound" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal timer bounds its scheduling slop"
# Ordered on the share mount, not merely timed: an early tick before
# the virtiofs mount lands writes onto the guest-local root, where
# the mount then hides it — failing invisibly in exactly the way the
# dump exists to fix.
grep -q 'mnt-wyrd' "$RELAY_NIX" \
  || { echo "FAIL: relay journal unit is not ordered on the state-share mount" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal unit waits for the state-share mount"
# The heartbeat must mean a successful dump: staged through a temp
# file and renamed on success, so a failed journalctl can never
# leave a fresh heartbeat over a truncated log. The read is bounded
# too — a wedged journalctl stalls the oneshot and systemd skips
# timer elapses while it runs, silently ending the dump series.
grep -q '\.relay-journal\.tmp' "$RELAY_NIX" \
  || { echo "FAIL: relay journal dump is not staged through a temp file" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal dump stages through a temp file"
grep -q 'TimeoutStartSec' "$RELAY_NIX" \
  || { echo "FAIL: relay journal unit has no read bound" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay journal read is bounded"
# The ordering is the property, not the two files: the heartbeat
# must be the last && segment of the dump chain, so moving the date
# line back to the front (the exact R2 regression) fails even
# though both filenames are still present.
LAST_SEG="$(sed -n '/wyrd-relay-journal = {/,/};/p' "$RELAY_NIX" | tr '\n' ' ' | sed 's/.*&& //')"
printf '%s\n' "$LAST_SEG" | grep -q 'relay-journal\.ts' \
  || { echo "FAIL: relay heartbeat is not written after the dump" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: relay heartbeat is written after the dump"

# The host logger backgrounds with the lock fd closed: an orphaned
# logger holding fd 9 would wedge the flock for every later run and
# --teardown (the exact fd-inheritance class the e2e-guard stubs
# pin). Without this pin the rule returns via a one-line edit.
grep -q '9>&-' "$RUNNER" \
  || { echo "FAIL: availability logger backgrounds without closing the lock fd" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: availability logger closes the lock fd"
# Self-exit when the runner is gone on an untrapped signal: the
# runner holds the run lock for the whole run, so an acquirable lock
# means the logger is orphaned — it must stop instead of appending
# to a dead run's file (and double-writing beside the next run).
grep -q 'flock -n 8' "$RUNNER" \
  || { echo "FAIL: availability logger has no orphan self-exit" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: availability logger exits when orphaned"
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
