#!/usr/bin/env bash
# tests/check-bash-syntax.sh — pre-commit entry for the bash syntax
# gate (see the bash-syntax hook in devenv.nix). bash -n parses only
# its first file argument and treats the rest as positional
# parameters, so passing staged files straight to `bash -n` checks
# exactly one of them and reports green. This wrapper loops over
# every argument instead: any staged shell script with a syntax
# error fails the commit. Pinned by tests/test-bash-syntax.sh.
set -euo pipefail
rc=0
for f in "$@"; do
  bash -n "$f" || rc=1
done
exit "$rc"
