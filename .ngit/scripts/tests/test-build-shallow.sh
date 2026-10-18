#!/usr/bin/env bash
# build.sh must deepen a shallow checkout before exporting the release
# input: nix locks `git+file://` flake inputs by revision count, which
# a shallow repo cannot provide (master CI failed the archive smoke
# test with `revCount is not available`). Runs the real build.sh
# against a file:// fixture with a stub nix (no builds, no network),
# and asserts the export the stub saw was full history.
#
# Run from the checkout: ./.ngit/scripts/tests/test-build-shallow.sh.
# Exits nonzero on any failure.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hook runners export GIT_DIR into hook processes; drop repo discovery
# so the scratch repo below is a real fresh repo. Isolate host git
# config too: a global branch.*.remote would leak warnings into the
# fixture's remote operations.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

command -v git >/dev/null || { echo "SKIP: git is required" >&2; exit 1; }

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1"; }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d "${TMPDIR:-/tmp}/build-shallow-test.XXXXXXXX")"
[ -d "$T" ] || { echo "FAIL: scratch dir setup failed" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT

# Fixture origin: three commits, so a depth-1 clone is genuinely
# shallow (no user config on the harness: -c flags inline). The tag
# sits on the oldest commit, so a depth-1 clone lacks it until
# deepened — phase 4's shallow-tag case.
git init -q -b master "$T/origin"
git -C "$T/origin" -c user.email=t@t -c user.name=t commit -q --allow-empty -m one
git -C "$T/origin" -c user.email=t@t -c user.name=t tag v9.9.9-tag HEAD
git -C "$T/origin" -c user.email=t@t -c user.name=t commit -q --allow-empty -m two
git -C "$T/origin" -c user.email=t@t -c user.name=t commit -q --allow-empty -m three
git clone -q --depth 1 "file://$T/origin" "$T/clone" 2>/dev/null
[ "$(git -C "$T/clone" rev-parse --is-shallow-repository)" = "true" ] ||
  { echo "FAIL: fixture clone is not shallow" >&2; exit 1; }

# Stub nix: record the shallowness of every flake-ref path arg, fake
# the build out-link, answer the platform probe. No builds, no network.
mkdir -p "$T/bin"
cat > "$T/bin/nix" <<'STUB'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    *#*)
      path="${arg%%#*}"
      git -C "$path" rev-parse --is-shallow-repository >> "$SHALLOW_LOG" 2>/dev/null || echo "n/a" >> "$SHALLOW_LOG"
      ;;
  esac
  if [ "${want_outlink:-}" = "1" ]; then
    touch "$arg"
    want_outlink=0
  elif [ "$arg" = "--out-link" ]; then
    want_outlink=1
  fi
done
echo "aarch64-darwin"
STUB
chmod +x "$T/bin/nix"
export PATH="$T/bin:$PATH"
export SHALLOW_LOG="$T/shallow.log"
: > "$SHALLOW_LOG"

# Phase 1: shallow clone with a reachable origin. build.sh must
# deepen it, exit 0, and hand nix a full-history export.
(cd "$T/clone" && bash "$SCRIPT_DIR/../build.sh" 0.0.0-test --ref HEAD aarch64-darwin >"$T/build.log" 2>&1)
code=$?
if [ "$code" -eq 0 ]; then
  ok "build.sh exits 0 on the deepened fixture"
else
  bad "build.sh exit code=$code (see build.log)"
fi

# The export nix saw must be full history: without the deepen step it
# stays "true" and nix refuses the input with `revCount is not available`.
seen="$(cat "$SHALLOW_LOG")"
if [ "$seen" = "false" ]; then
  ok "release export is full history"
else
  bad "release export shallowness=[$seen] (want exactly [false])"
fi

if [ "$(git -C "$T/clone" rev-parse --is-shallow-repository)" = "false" ]; then
  ok "fixture checkout is deepened in place"
else
  bad "fixture checkout is still shallow after build.sh"
fi

# Phase 2: full clone. The deepen step must skip untouched: exit 0,
# export full, and no deepening message in the log.
git clone -q "file://$T/origin" "$T/full" 2>/dev/null
: > "$SHALLOW_LOG"
(cd "$T/full" && bash "$SCRIPT_DIR/../build.sh" 0.0.0-test --ref HEAD aarch64-darwin >"$T/build-full.log" 2>&1)
code=$?
if [ "$code" -eq 0 ] && [ "$(cat "$SHALLOW_LOG")" = "false" ] &&
  ! grep -q "shallow checkout detected" "$T/build-full.log"; then
  ok "full clone skips the deepen step untouched"
else
  bad "full clone phase: code=$code export=[$(cat "$SHALLOW_LOG")]"
fi

# Phase 3: shallow clone with no reachable remote. Deepening must fail
# loudly, before nix ever runs. (A fetch with no remote configured is
# a silent no-op success, so the stranded shape also proves the
# still-shallow verification, not just the fetch error path.)
git clone -q --depth 1 "file://$T/origin" "$T/stranded" 2>/dev/null
git -C "$T/stranded" remote remove origin
: > "$SHALLOW_LOG"
(cd "$T/stranded" && bash "$SCRIPT_DIR/../build.sh" 0.0.0-test --ref HEAD aarch64-darwin >"$T/build-stranded.log" 2>&1)
code=$?
if [ "$code" -ne 0 ] && grep -q "refusing a release from shallow history" "$T/build-stranded.log" &&
  [ ! -s "$SHALLOW_LOG" ]; then
  ok "unreachable remote aborts loudly before nix runs"
else
  bad "stranded shallow phase: code=$code (want nonzero with the shallow-history refusal, no nix call)"
fi

# Phase 4: shallow clone resolving a ref only full history provides.
# The tag sits on the oldest commit, so the depth-1 clone lacks it;
# deepen-first must fetch it before PIN verification. Proves the
# reorder's motivating case, not just `--ref HEAD`.
git clone -q --depth 1 "file://$T/origin" "$T/tagged" 2>/dev/null
if git -C "$T/tagged" rev-parse --verify --quiet v9.9.9-tag >/dev/null 2>&1; then
  bad "tag phase setup: tag unexpectedly present in the depth-1 clone"
else
  : > "$SHALLOW_LOG"
  (cd "$T/tagged" && bash "$SCRIPT_DIR/../build.sh" 9.9.9 --ref v9.9.9-tag aarch64-darwin >"$T/build-tag.log" 2>&1)
  code=$?
  if [ "$code" -eq 0 ] && [ "$(cat "$SHALLOW_LOG")" = "false" ]; then
    ok "shallow tag ref deepens first, then builds"
  else
    bad "tag phase: code=$code export=[$(cat "$SHALLOW_LOG")] (want 0 / [false])"
  fi
fi

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
