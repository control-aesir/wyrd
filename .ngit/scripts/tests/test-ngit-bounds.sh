#!/usr/bin/env bash
# Tests for ../ngit.sh call bounding: resolve_pr caps every scan call
# at the time left on the scan deadline (bounded_scan), so the scan
# can never outlive RESOLUTION_DEADLINE_SECS no matter how slowly one
# call syncs, while the default per-call bound stays 300s.
#
# Uses a stub timeout (records its seconds argument, then runs the
# command) and a stub ngit (replays fixtures), plus a scratch git
# repo. No relay, credential, or network is touched.
#
# Run from the checkout: ./.ngit/scripts/tests/test-ngit-bounds.sh.
# Exits nonzero on any failure.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hook runners export GIT_DIR into hook processes; drop repo discovery
# so the scratch repo below is a real fresh repo (see test-review.sh).
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR

# shellcheck disable=SC1091
source "$SCRIPT_DIR/../ngit.sh"

command -v jq >/dev/null || { echo "SKIP: jq is required" >&2; exit 1; }
command -v git >/dev/null || { echo "SKIP: git is required" >&2; exit 1; }

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1"; }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d "${TMPDIR:-/tmp}/ngit-bounds-test.XXXXXXXX")"
[ -d "$T" ] || { echo "FAIL: scratch dir setup failed" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT

# Stub timeout: record the seconds bound, then run the command.
mkdir -p "$T/bin"
cat > "$T/bin/timeout" <<'STUB'
#!/usr/bin/env bash
echo "$1" >> "$TIMEOUT_LOG"
shift
exec "$@"
STUB
# Stub ngit: one PR matching the scratch branch.
cat > "$T/bin/ngit" <<'STUB'
#!/usr/bin/env bash
echo "ngit $*" >> "$STUB_LOG"
case "$*" in
  *"pr list"*) printf '[{"id": "nevent1testpr1", "branch": "pr/test-helpers(abc123)"}]\n' ;;
  *) printf '{}\n' ;;
esac
STUB
chmod +x "$T/bin/timeout" "$T/bin/ngit"
export PATH="$T/bin:$PATH"
export STUB_LOG="$T/ngit.log" TIMEOUT_LOG="$T/timeout.log"

git init -q -b pr/test-helpers "$T/repo"
[ "$(git -C "$T/repo" branch --show-current)" = "pr/test-helpers" ] ||
  { echo "FAIL: scratch repo setup failed" >&2; exit 1; }

export PR_BRANCH="pr/test-helpers"
unset NGIT_CI_TRIGGER_EVENT GITHUB_SHA

# 1. Ample deadline: the scan call uses the default 300s bound.
export RESOLUTION_DEADLINE_SECS=1000
: > "$STUB_LOG"; : > "$TIMEOUT_LOG"
out="$(cd "$T/repo" && resolve_pr 2>"$T/err")"
if [ "$out" = "nevent1testpr1" ] && [ "$(cat "$TIMEOUT_LOG")" = "300" ]; then
  ok "ample deadline resolves under the default 300s bound"
else
  bad "ample deadline: out=[$out] bound=[$(cat "$TIMEOUT_LOG")]"
fi

# 2. Short deadline: the scan call is capped at the time remaining.
export RESOLUTION_DEADLINE_SECS=40
: > "$STUB_LOG"; : > "$TIMEOUT_LOG"
out="$(cd "$T/repo" && resolve_pr 2>"$T/err")"
bound="$(head -n 1 "$TIMEOUT_LOG")"
if [ "$out" = "nevent1testpr1" ] && [ "$bound" -ge 1 ] && [ "$bound" -le 40 ]; then
  ok "short deadline caps the call at the remaining time ($bound)"
else
  bad "short deadline: out=[$out] bound=[$bound]"
fi

# 3. Expired deadline: no ngit call happens at all.
export RESOLUTION_DEADLINE_SECS=0
: > "$STUB_LOG"; : > "$TIMEOUT_LOG"
out="$(cd "$T/repo" && resolve_pr 2>"$T/err")"
code=$?
if [ $code -ne 0 ] && [ ! -s "$TIMEOUT_LOG" ] && grep -q "timed out" "$T/err"; then
  ok "expired deadline fails before any ngit call"
else
  bad "expired deadline: code=$code calls=$(wc -l <"$TIMEOUT_LOG")"
fi
unset RESOLUTION_DEADLINE_SECS

# 4. Publish path keeps the default bound (no deadline context).
: > "$TIMEOUT_LOG"
bounded_ngit --repo "$REPO_NADDR" pr list --json >/dev/null 2>&1
if [ "$(cat "$TIMEOUT_LOG")" = "300" ]; then
  ok "publish path keeps the default 300s bound"
else
  bad "publish path bound: [$(cat "$TIMEOUT_LOG")]"
fi

# 5. Publish under an ample step budget uses the default bound.
step_deadline=$((SECONDS + 1000))
: > "$TIMEOUT_LOG"
bounded_publish --repo "$REPO_NADDR" pr comment --json >/dev/null 2>&1
if [ "$(cat "$TIMEOUT_LOG")" = "300" ]; then
  ok "publish under ample budget keeps the default bound"
else
  bad "publish ample budget: [$(cat "$TIMEOUT_LOG")]"
fi

# 6. Publish under a tight step budget is capped at what is left.
step_deadline=$((SECONDS + 45))
: > "$TIMEOUT_LOG"
bounded_publish --repo "$REPO_NADDR" pr comment --json >/dev/null 2>&1
bound="$(head -n 1 "$TIMEOUT_LOG")"
if [ "$bound" -ge 1 ] && [ "$bound" -le 45 ]; then
  ok "publish under tight budget capped at remainder ($bound)"
else
  bad "publish tight budget: bound=[$bound]"
fi

# 7. Publish with an exhausted step budget fails before any ngit call.
# (Subshell: the loud failure is `exit`, which must not kill this suite.)
step_deadline=$((SECONDS - 1))
: > "$TIMEOUT_LOG"
(bounded_publish --repo "$REPO_NADDR" pr comment --json >/dev/null 2>"$T/err")
code=$?
if [ $code -ne 0 ] && [ ! -s "$TIMEOUT_LOG" ] && grep -q "budget exhausted" "$T/err"; then
  ok "publish with exhausted budget fails before any call"
else
  bad "publish exhausted budget: code=$code calls=$(wc -l <"$TIMEOUT_LOG")"
fi
unset step_deadline

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
