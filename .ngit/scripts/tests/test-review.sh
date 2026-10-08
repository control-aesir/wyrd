#!/usr/bin/env bash
# Tests for ../review.sh. Runs the helper against a stub ngit earlier on
# PATH plus a scratch git repo, so no relay, credential, or network is
# touched. Each case asserts argument passing, output purity, and
# failure semantics (zero/multiple matches, empty body, missing
# verification, publish failure with no retry).
#
# Run from the checkout: ./.ngit/scripts/tests/test-review.sh.
# Not installed into dev shells: fixtures resolve source-relative
# paths. Exits nonzero on any failure.
set -uo pipefail

# Hook runners (prek via devenv git-hooks) export GIT_DIR into hook
# processes; any git call then obeys it instead of its own path
# argument (`git init <dir>` re-inits that repo, `git -C` stays put).
# The scratch repo below must be immune, so drop repo discovery from
# the environment before touching git.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVIEW_SH="$SCRIPT_DIR/../review.sh"

command -v jq >/dev/null || { echo "SKIP: jq is required" >&2; exit 1; }
command -v git >/dev/null || { echo "SKIP: git is required" >&2; exit 1; }

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1"; }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d "${TMPDIR:-/tmp}/review-test.XXXXXXXX")"
[ -d "$T" ] || { echo "FAIL: scratch dir setup failed" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT

# Stub ngit: logs every invocation, then replays fixture files. Fails
# the publish path on STUB_COMMENT_FAIL.
mkdir -p "$T/bin"
cat > "$T/bin/ngit" <<'STUB'
#!/usr/bin/env bash
echo "ngit $*" >> "$STUB_LOG"
args="$*"
case "$args" in
  *"pr list"*) cat "$STUB_LIST_JSON" ;;
  *"pr view"*)
    # The first view call replays STUB_VIEW_FIRST when set (the
    # pre-publish snapshot); later calls replay STUB_VIEW_JSON.
    if [ -n "${STUB_VIEW_FIRST:-}" ] && [ "$(grep -c "pr view" "$STUB_LOG")" = "1" ]; then
      cat "$STUB_VIEW_FIRST"
    else
      cat "$STUB_VIEW_JSON"
    fi
    ;;
  *"pr comment"*)
    if [ "${STUB_COMMENT_FAIL:-0}" = "1" ]; then
      echo "stub: publish failed" >&2
      exit 1
    fi
    printf '{"command_status":"ok"}\n'
    ;;
  *) echo "stub: unexpected ngit call: $args" >&2; exit 2 ;;
esac
STUB
chmod +x "$T/bin/ngit"
export PATH="$T/bin:$PATH"
export STUB_LOG="$T/ngit.log"

# Scratch repo on a pr/ branch for resolve-pr's branch detection.
# Fail loud here: a bad scratch repo cascades into confusing
# downstream failures (notably under hook runners, whose env differs
# from an interactive shell).
git init -q -b pr/test-helpers "$T/repo"
[ "$(git -C "$T/repo" branch --show-current)" = "pr/test-helpers" ] ||
  { echo "FAIL: scratch repo setup failed" >&2; exit 1; }

LIST_ONE="$T/list-one.json"
LIST_NONE="$T/list-none.json"
LIST_TWO="$T/list-two.json"
VIEW_WITH="$T/view-with.json"
VIEW_WITHOUT="$T/view-without.json"
cat > "$LIST_ONE" <<'EOF'
[{"id": "nevent1testpr1", "branch": "pr/test-helpers(abc123)"}]
EOF
echo '[]' > "$LIST_NONE"
cat > "$LIST_TWO" <<'EOF'
[{"id": "nevent1testpr1", "branch": "pr/test-helpers(aaa)"},
 {"id": "nevent1testpr2", "branch": "pr/test-helpers(bbb)"}]
EOF
cat > "$VIEW_WITH" <<'EOF'
{"id": "nevent1testpr1", "comments": [
  {"id": "nevent1comment1", "author": "Wyrd AI Review",
   "body": "hello review", "created_at": 1, "reply_to": null}]}
EOF
echo '{"id": "nevent1testpr1", "comments": []}' > "$VIEW_WITHOUT"

export STUB_LIST_JSON="$LIST_ONE" STUB_VIEW_JSON="$VIEW_WITHOUT"
export REVIEW_SIGNER="Test Reviewer"
: > "$STUB_LOG"

# 1. resolve-pr prints only the id on a unique match.
out="$(cd "$T/repo" && "$REVIEW_SH" resolve-pr 2>"$T/err")"
if [ "$out" = "nevent1testpr1" ]; then ok "resolve-pr prints only the id"; else bad "resolve-pr output: [$out]"; fi

# 2. resolve-pr reads offline by default and pins the repo.
# (--offline is per-subcommand: it must follow `pr list --json`.)
if grep -q "pr list --json --offline" "$STUB_LOG" && grep -q -- "--repo" "$STUB_LOG"; then
  ok "resolve-pr defaults to offline with explicit repo"
else
  bad "resolve-pr default flags: $(cat "$STUB_LOG")"
fi

# 3. resolve-pr --online drops --offline.
: > "$STUB_LOG"
(cd "$T/repo" && "$REVIEW_SH" resolve-pr --online >/dev/null 2>&1)
if grep -q "pr list" "$STUB_LOG" && ! grep -q -- "--offline" "$STUB_LOG"; then
  ok "resolve-pr --online skips --offline"
else
  bad "resolve-pr --online flags: $(cat "$STUB_LOG")"
fi

# 4. resolve-pr fails loudly with nothing on stdout on zero matches.
export STUB_LIST_JSON="$LIST_NONE"
out="$(cd "$T/repo" && "$REVIEW_SH" resolve-pr 2>"$T/err")"
code=$?
if [ $code -ne 0 ] && [ -z "$out" ] && grep -q "no PR matches" "$T/err"; then
  ok "resolve-pr zero matches fails loud, stdout empty"
else
  bad "resolve-pr zero matches: code=$code out=[$out]"
fi

# 5. resolve-pr fails loudly on multiple matches, never guessing.
export STUB_LIST_JSON="$LIST_TWO"
out="$(cd "$T/repo" && "$REVIEW_SH" resolve-pr 2>"$T/err")"
code=$?
if [ $code -ne 0 ] && [ -z "$out" ] && grep -q "refusing to guess" "$T/err"; then
  ok "resolve-pr multiple matches refuses to guess"
else
  bad "resolve-pr multiple matches: code=$code out=[$out]"
fi
export STUB_LIST_JSON="$LIST_ONE"

# 6. pr-context passes the id through with comments as one JSON doc.
out="$("$REVIEW_SH" pr-context nevent1testpr1 2>"$T/err")"
if [ "$out" = "$(cat "$VIEW_WITHOUT")" ] && grep -q "pr view nevent1testpr1 --json --offline --comments" "$STUB_LOG"; then
  ok "pr-context returns view with comments for the given id"
else
  bad "pr-context: out=[$out]"
fi

# 7. post-comment posts stdin once with the signer and verifies a
# NEW matching comment (pre-publish view is empty).
export STUB_VIEW_FIRST="$VIEW_WITHOUT" STUB_VIEW_JSON="$VIEW_WITH"
: > "$STUB_LOG"
printf 'hello review' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>"$T/err"
code=$?
comment_calls="$(grep -c "pr comment" "$STUB_LOG")"
if [ $code -eq 0 ] && [ "$comment_calls" = "1" ] &&
  grep -q -- '--signer Test Reviewer' "$STUB_LOG" &&
  grep -q "verified comment present" "$T/err"; then
  ok "post-comment posts once with signer and verifies"
else
  bad "post-comment happy path: code=$code calls=$comment_calls"
fi
unset STUB_VIEW_FIRST

# 8. post-comment refuses an empty body before any ngit call.
: > "$STUB_LOG"
printf '' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>"$T/err"
code=$?
if [ $code -ne 0 ] && [ ! -s "$STUB_LOG" ] && grep -q "empty body" "$T/err"; then
  ok "post-comment refuses empty body without calling ngit"
else
  bad "post-comment empty body: code=$code logbytes=$(wc -c <"$STUB_LOG")"
fi

# 9. post-comment fails when verification finds no comment (no retry).
export STUB_VIEW_JSON="$VIEW_WITHOUT"
: > "$STUB_LOG"
printf 'hello review' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>"$T/err"
code=$?
comment_calls="$(grep -c "pr comment" "$STUB_LOG")"
if [ $code -ne 0 ] && [ "$comment_calls" = "1" ] && grep -q "refusing to retry" "$T/err"; then
  ok "post-comment fails loud on missing verification, no retry"
else
  bad "post-comment missing verify: code=$code calls=$comment_calls"
fi

# 10. post-comment surfaces a publish failure with exactly one attempt.
export STUB_COMMENT_FAIL=1
: > "$STUB_LOG"
printf 'hello review' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>"$T/err"
code=$?
comment_calls="$(grep -c "pr comment" "$STUB_LOG")"
if [ $code -ne 0 ] && [ "$comment_calls" = "1" ]; then
  ok "post-comment publish failure fails loud, single attempt"
else
  bad "post-comment publish failure: code=$code calls=$comment_calls"
fi
unset STUB_COMMENT_FAIL

# 11. REVIEW_LIB_DIR override is honored (devenv store layout).
mkdir -p "$T/lib"
cp "$SCRIPT_DIR/../ngit.sh" "$T/lib/ngit.sh"
out="$(cd "$T/repo" && REVIEW_LIB_DIR="$T/lib" "$REVIEW_SH" resolve-pr 2>/dev/null)"
if [ "$out" = "nevent1testpr1" ]; then
  ok "REVIEW_LIB_DIR override locates ngit.sh"
else
  bad "REVIEW_LIB_DIR override: out=[$out]"
fi

# 12. post-comment rejects a stale duplicate: the identical body
# pre-exists and nothing new arrived.
export STUB_VIEW_FIRST="$VIEW_WITH" STUB_VIEW_JSON="$VIEW_WITH"
: > "$STUB_LOG"
printf 'hello review' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>"$T/err"
code=$?
if [ $code -ne 0 ] && grep -q "refusing to retry" "$T/err"; then
  ok "post-comment refuses stale duplicate bodies"
else
  bad "post-comment stale duplicate: code=$code"
fi
unset STUB_VIEW_FIRST

# 13. post-comment publishes online: no --offline on the publish call.
export STUB_VIEW_FIRST="$VIEW_WITHOUT" STUB_VIEW_JSON="$VIEW_WITH"
: > "$STUB_LOG"
printf 'hello review' | "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>&1
comment_calls="$(grep -c "pr comment" "$STUB_LOG")"
if [ "$comment_calls" = "1" ] && ! grep "pr comment" "$STUB_LOG" | grep -q -- "--offline"; then
  ok "post-comment publishes without --offline"
else
  bad "post-comment publish argv: calls=$comment_calls $(grep 'pr comment' "$STUB_LOG")"
fi
unset STUB_VIEW_FIRST

# 14. Default signer is Wyrd AI Review when REVIEW_SIGNER is unset.
export STUB_VIEW_FIRST="$VIEW_WITHOUT" STUB_VIEW_JSON="$VIEW_WITH"
: > "$STUB_LOG"
printf 'hello review' | env -u REVIEW_SIGNER "$REVIEW_SH" post-comment nevent1testpr1 >/dev/null 2>&1
if grep -q -- '--signer Wyrd AI Review' "$STUB_LOG"; then
  ok "post-comment defaults to the Wyrd AI Review signer"
else
  bad "post-comment default signer: $(cat "$STUB_LOG")"
fi
unset STUB_VIEW_FIRST

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
