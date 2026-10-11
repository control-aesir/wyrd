#!/usr/bin/env bash
# tests/test-probe-mark.sh — stub pinning the probe_mark line grammar in
# tests/alpha-microvm-legs.sh: every mark prints
# `step<PROBE_STEP> probe <name>=<Ns>` with a single `=`, defaulting to
# step 9. The helper is extracted verbatim from the legs file (which is
# not sourceable standalone: it pulls the guest env and common lib at
# load), so this pins the real bytes, not a copy. Pure bash, no guest,
# no nix: run it anywhere with `bash tests/test-probe-mark.sh`.
# (Wired into CI shell-tests alongside the other stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
die() { echo "  FAIL: $1" >&2; exit 1; }

LEGS="$ROOT/tests/alpha-microvm-legs.sh"
[[ -f "$LEGS" ]] || die "legs file missing at $LEGS"

# Verbatim helper: from the PROBE_STEP default through the closing
# brace of probe_mark. Non-empty means the extraction tracks the file.
HELPER="$(sed -n '/^PROBE_STEP=/,/^}$/p' "$LEGS")"
[[ -n "$HELPER" ]] || die "probe_mark helper not found in $LEGS"
pass "helper extracts verbatim from the legs file"

eval "$HELPER"

# A synthetic one-second gap renders the documented shape exactly.
# (Retried: a clock tick landing between the mark and the call would
# read 2s. Three consecutive boundary hits is impossible in practice.)
GOT=""
for _ in 1 2 3; do
  # PROBE_MARK is read by the eval'd helper above (opaque to shellcheck).
  # shellcheck disable=SC2034
  PROBE_MARK=$((SECONDS - 1))
  GOT="$(probe_mark converged_wait)"
  [[ "$GOT" == "step9 probe converged_wait=1s" ]] && break
done
[[ "$GOT" == "step9 probe converged_wait=1s" ]] \
  || die "shape mismatch, got '$GOT'"
pass "one-second gap renders step9 probe converged_wait=1s"

# The recovery name carries the attempt count with no second `=`.
# (Elapsed is clock-coupled, so only the shape is asserted.)
GOT="$(probe_mark "recovery(attempts=1)")"
[[ "$GOT" == "step9 probe recovery(attempts=1)="* ]] \
  || die "recovery shape mismatch, got '$GOT'"
[[ "$(grep -o '=' <<<"$GOT" | wc -l)" -eq 2 ]] \
  || die "recovery line has more than name=value shape: '$GOT'"
pass "recovery mark is awk-able with the count matching its label"

# An explicit PROBE_STEP overrides the prefix instead of lying. Only
# the prefix is asserted: the elapsed value is clock-coupled.
GOT="$(PROBE_STEP=12 probe_mark scratch)"
[[ "$GOT" == "step12 probe scratch="* ]] \
  || die "step override mismatch, got '$GOT'"
pass "PROBE_STEP overrides the prefix"

# Every instrumented phase-13 leg keeps its marks: a leg that silently
# loses its instrumentation must fail here, not in an odin log. The
# legs file is not sourceable, so bodies are sliced textually from the
# function header to its closing brace.
for leg in leg_crash_owner leg_steady_member leg_crash_member leg_steady_owner; do
  BODY="$(awk "/^$leg\(\) \{/{f=1} f{print} /^\}$/{if (f) exit}" "$LEGS")"
  [[ -n "$BODY" ]] || die "leg body not found: $leg"
  grep -q 'PROBE_STEP=13' <<<"$BODY" \
    || die "$leg lost its PROBE_STEP=13 override"
  [[ "$(grep -c 'probe_mark ' <<<"$BODY")" -ge 1 ]] \
    || die "$leg lost its probe marks"
done
pass "all four phase-13 legs keep their step override and marks"

echo "probe-mark: $PASS checks passed"
