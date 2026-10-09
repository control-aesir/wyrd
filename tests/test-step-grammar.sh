#!/usr/bin/env bash
# tests/test-step-grammar.sh — stub suite for tests/step-grammar.sh. Pure
# bash, no harness, no guest, no nix: run it anywhere with
# `bash tests/test-step-grammar.sh`. It pins the contract the harnesses
# share, so a grammar change fails here before it can reach Lima or odin.
# (Not wired into the CI shell-tests job; that suite covers the ngit
# helpers. Wiring this in is a follow-up, not a drive-by.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/step-grammar.sh"

PASS=0
check() { # <name> <got> <want>
  [[ "$2" == "$3" ]] || { echo "FAIL: $1: got [$2], want [$3]" >&2; exit 1; }
  PASS=$((PASS + 1))
  echo "  PASS: $1"
}

expect_max() { # <lo> <hi> <selection> <want-max>
  local got
  got="$(step_max "$1" "$2" "$3")" \
    || { echo "FAIL: '$3' rejected, want max $4" >&2; exit 1; }
  check "step_max $1 $2 '$3' -> $4" "$got" "$4"
}

expect_reject() { # <lo> <hi> <selection>
  local got rc=0
  got="$(step_max "$1" "$2" "$3" 2>/dev/null)" || rc=$?
  [[ "$rc" == 1 ]] || { echo "FAIL: '$3' accepted with [$got], want reject" >&2; exit 1; }
  [[ -z "$got" ]] || { echo "FAIL: '$3' printed [$got] on reject, want silence" >&2; exit 1; }
  PASS=$((PASS + 1))
  echo "  PASS: step_max $1 $2 '$3' rejected silently"
}

# --- valid selections, Lima range ------------------------------------------
expect_max 1 6 "1" "1"
expect_max 1 6 "6" "6"
expect_max 1 6 "3" "3"
expect_max 1 6 "1,4,6" "6"
expect_max 1 6 "6,1" "6"
expect_max 1 6 "2,2,2" "2"
expect_max 1 6 "1,2,3,4,5,6" "6"
# Leading zeros canonicalize (deliberate loosening, see step-grammar.sh).
expect_max 1 6 "01" "1"
expect_max 1 6 "06,02" "6"

# --- valid selections, microVM range ----------------------------------------
expect_max 1 12 "12" "12"
expect_max 1 12 "10,12" "12"
expect_max 1 12 "7" "7"
expect_max 1 12 "1,12" "12"

# --- malformed selections, both ranges ---------------------------------------
for sel in "" " " "1, 2" "1 ,2" "1,,2" ",1" "1," "," "a" "1,a" "-" "1-3" \
           "1.5" " 1" "1 " "0" "00" "07,0"; do
  expect_reject 1 6 "$sel"
done
# Range enforcement is the only per-harness difference.
expect_reject 1 6 "7"
expect_reject 1 6 "12"
expect_reject 1 6 "99"
expect_reject 1 12 "0"
expect_reject 1 12 "13"
expect_reject 1 12 "99"
# Base-10, never octal: 08 and 09 are ordinary out-of-range entries.
expect_reject 1 6 "08"
expect_reject 1 6 "09"
# 08 IS in range for 1-12; it must be accepted as 8, not misparsed.
expect_max 1 12 "08" "8"

# --- glob safety --------------------------------------------------------------
# A selection of '*' must not pathname-expand into digit-named files in the
# working directory. Prove it where such files exist.
GLOBTMP="$(mktemp -d)"
touch "$GLOBTMP/1" "$GLOBTMP/6"
(
  cd "$GLOBTMP"
  expect_reject 1 6 "*"
  expect_reject 1 12 "*"
  # And a valid list still resolves literally, not by expansion.
  expect_max 1 6 "1,6" "6"
)
rm -rf "$GLOBTMP"

echo "step-grammar: $PASS checks passed"
