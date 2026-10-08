#!/usr/bin/env bash
# Runs every shell suite in this directory (stubbed ngit/timeout: no
# relay, credential, or network). Used by the review-tests git hook
# and the CI shell-tests job.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail=0
for suite in "$SCRIPT_DIR"/test-*.sh; do
  echo "=== $suite ==="
  bash "$suite" || fail=1
done

exit "$fail"
