#!/usr/bin/env bash
# tests/alpha-lima.sh — the Lima e2e contract. Runs INSIDE the NixOS guest
# (via lima/run-alpha.sh); every assertion here is the suite. Steps mirror
# the Lima issue's scope 1-6; each step function locks its invariants.
#
# Layout (all guest-local disk, never the 9p share — FUSE mountpoints and
# drive dirs over 9p are unsupported):
#   $E2E_ROOT/drives/<name>   drive directories under test
#   $E2E_ROOT/creds/<name>    identity/passphrase files (0600)
#   $E2E_ROOT/mnt/<name>      FUSE mountpoints
#   $E2E_ROOT/logs/           per-step stderr captures, copied to the host
#                             share on exit (trap) for collection.
set -euo pipefail

# shellcheck source=/dev/null
source /tmp/lima/e2e-env.sh

E2E_ROOT="/tmp/wyrd-e2e"
DRIVES="$E2E_ROOT/drives"
CREDS="$E2E_ROOT/creds"
MNTS="$E2E_ROOT/mnt"
LOGDIR="$E2E_ROOT/logs"
HOST_LOGS="/tmp/lima/logs/$(date +%Y%m%d-%H%M%S)"

collect_logs() {
  mkdir -p "$HOST_LOGS"
  cp -r "$LOGDIR/." "$HOST_LOGS/" 2>/dev/null || true
  echo "logs collected under $HOST_LOGS (host: /tmp/lima/logs/)"
}

# A failed step must never strand a mount: unmount everything and kill
# leftover mount processes, so the next run starts clean. The unmount is
# attempted unconditionally — gating on `mountpoint -q` or `-e` can skip a
# live mount whose FUSE fs misbehaves under stat.
cleanup_mounts() {
  local m pidf
  for m in "$MNTS"/*; do
    [[ -e "$m" || -L "$m" ]] || continue
    fusermount3 -uz "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
  done
  for pidf in "$E2E_ROOT"/mount-*.pid; do
    [[ -f "$pidf" ]] || continue
    kill -KILL "$(cat "$pidf")" 2>/dev/null || true
  done
  # Reap anything we killed so no zombies linger.
  wait 2>/dev/null || true
  # A just-killed mount can need a beat before the kernel releases it.
  sleep 1
  for m in "$MNTS"/*; do
    [[ -e "$m" || -L "$m" ]] || continue
    fusermount3 -uz "$m" 2>/dev/null || true
  done
}
trap 'cleanup_mounts; collect_logs' EXIT

PASS_COUNT=0
step()  { echo "=== step $1: $2 ==="; }
pass()  { PASS_COUNT=$((PASS_COUNT + 1)); echo "  PASS: $1"; }
die()   { echo "  FAIL: $1" >&2; exit 1; }

wyrd() { "$WYRD_BIN" "$@"; }

# with_creds <cred-dir> <subcommand> <args...>: credential flags precede
# positionals on every subcommand (`wyrd <sub> --identity-file ... <dirs>`).
with_creds() {
  local c="$1" sub="$2"; shift 2
  "$WYRD_BIN" "$sub" --identity-file "$c/identity" --passphrase-file "$c/passphrase" "$@"
}

# expect_exit <code> <log-name> <cmd...>: run, capture stderr to the log,
# assert the exit code. stdout passes through for command substitution.
expect_exit() {
  local want="$1" name="$2"; shift 2
  local err="$LOGDIR/$name.stderr"
  local out
  set +e
  out="$("$@" 2>"$err")"
  local got=$?
  set -e
  [[ $got -eq "$want" ]] || die "$name: exit $got, want $want (stderr: $(cat "$err"))"
  printf '%s' "$out"
}

# expect_fail2 <log-name> <cmd...>: exit 2 with `error: ...` on stderr.
# A usage error is a bug in the suite, not a closed failure: reject it so a
# misspelled invocation can never pass as a negative case.
expect_fail2() {
  local name="$1"; shift
  expect_exit 2 "$name" "$@" >/dev/null
  grep -qE "Usage:|unexpected argument" "$LOGDIR/$name.stderr" \
    && die "$name: usage error, not a closed failure"
  head -c 7 "$LOGDIR/$name.stderr" | grep -q "^error: " \
    || die "$name: stderr does not start with 'error: '"
  pass "$name fails closed (exit 2, error: ...)"
}

# expect_usage2 <log-name> <cmd...>: exit 2 with a usage error
# (the complement of expect_fail2: here a bad invocation IS the case).
expect_usage2() {
  local name="$1"; shift
  expect_exit 2 "$name" "$@" >/dev/null
  grep -qE "Usage:|unexpected argument" "$LOGDIR/$name.stderr" \
    || die "$name: expected a usage error"
  pass "$name refused as a usage error (exit 2)"
}

# Credential factories. Secrets stay in files plus shell vars for the
# leak check; they never reach logs (asserted per step).
gen_identity() { # <out>: 32 random bytes as 64 hex chars, mode 600
  python3 -c 'import secrets; print(secrets.token_hex(32))' > "$1"
  chmod 600 "$1"
}
gen_passphrase() { # <out>: random passphrase with trailing newline, 600
  python3 -c 'import secrets; print("e2e-" + secrets.token_hex(16))' > "$1"
  chmod 600 "$1"
}

# check_no_leaks <log-file> <secret...>: fail if any secret bytes appear.
check_no_leaks() {
  local log="$1"; shift
  local s
  for s in "$@"; do
    grep -qF "$s" "$log" && die "secret leaked into $log"
  done
  pass "no secrets in $(basename "$log")"
}

# --- mount helpers -------------------------------------------------------
# Mounts run as background jobs in this shell so `wait` reports their real
# exit status. Readiness is polled via mountpoint(1), not via listing: an
# unmounted empty dir lists fine too.
poll_until() { # <seconds> <cmd...>
  local n="$1"; shift
  local i
  for ((i = 0; i < n * 5; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

start_mount() { # <name> <cred-dir> <drive> <mnt> [mount args...]
  local name="$1" c="$2" d="$3" m="$4"; shift 4
  mkdir -p "$m"
  # Debug passthrough for stuck-peer forensics (E2E_RUST_LOG=wyrd_core=debug):
  # empty means the binary's default info level, never an empty filter.
  # Scoped to the mount process only: offline assertions require stderr
  # to start with `error: `, so the restored shell must not leak it.
  local old_rust_log="${RUST_LOG-__unset}"
  [[ -n "${E2E_RUST_LOG:-}" ]] && export RUST_LOG="$E2E_RUST_LOG"
  with_creds "$c" mount "$d" "$m" "$@" \
    >"$LOGDIR/mount-$name.out" 2>"$LOGDIR/mount-$name.err" &
  echo $! > "$E2E_ROOT/mount-$name.pid"
  if [[ "$old_rust_log" == "__unset" ]]; then unset RUST_LOG; else export RUST_LOG="$old_rust_log"; fi
  poll_until 20 mountpoint -q "$m" \
    || die "$name: mountpoint never came up (see mount-$name.err)"
  pass "$name: mountpoint up"
}

stop_mount() { # <name> <signal> [budget-s = 15]: signal, wait for exit,
  # assert exit 0 + unmounted. The budget is a bound, not a target: a
  # mount holding a large vault persists its serving store on the way
  # out, so step 6's post-bulk stop gets a larger one.
  local name="$1" sig="$2" budget="${3:-15}"
  local pid started elapsed
  started=$(date +%s)
  pid="$(cat "$E2E_ROOT/mount-$name.pid")"
  kill "-$sig" "$pid"
  local i status="timeout"
  for ((i = 0; i < budget * 5; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e; wait "$pid"; status=$?; set -e
      break
    fi
    sleep 0.2
  done
  elapsed=$(( $(date +%s) - started ))
  [[ "$status" == "0" ]] || die "$name: shutdown exit $status on $sig after ${elapsed}s, want clean 0"
  mountpoint -q "$MNTS/$name" && die "$name: still mounted after $sig"
  pass "$name: clean shutdown on $sig (exit 0, unmounted, ${elapsed}s)"
}

# stop_relay: TERM, poll briefly, then KILL — never a bare `wait` on a
# process that may ignore or delay SIGTERM. An unbounded wait here is
# how a failed check once hung the whole run: the guest shell sat in
# do_wait on nostr-rs-relay for 44 minutes, and the EXIT trap could not
# run because it came after the wait.
stop_relay() {
  local pid i
  [[ -f "$E2E_ROOT/relay.pid" ]] || { pkill -x nostr-rs-relay 2>/dev/null || true; return 0; }
  pid="$(cat "$E2E_ROOT/relay.pid")"
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 25; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# --- step 2: local-only mount --------------------------------------------
step1_init() {
  step 1 "init lifecycle"
  local d="$DRIVES/owner" c="$CREDS/owner"
  mkdir -p "$c"
  gen_identity "$c/identity"; gen_passphrase "$c/passphrase"
  local identity passphrase
  identity="$(cat "$c/identity")"; passphrase="$(cat "$c/passphrase")"

  wyrd --version >/dev/null
  wyrd --help >/dev/null
  pass "version/help exit 0"

  expect_exit 0 step1-init with_creds "$c" init "$d" >/dev/null
  pass "init creates a drive"
  [[ -f "$d/mount.log" ]] && die "init wrote a mount log"
  pass "init logs nothing to disk"

  # The cheapest reopen probe doubles as the credential-hardening probe:
  # `device id` opens the keystore, which exercises credential hardening.
  expect_fail2 step1-reinit with_creds "$c" init "$d"

  local bad="$c/case"; mkdir -p "$bad"
  cp "$c/identity" "$bad/identity"; cp "$c/passphrase" "$bad/passphrase"

  mv "$bad/identity" "$bad/identity-real"
  ln -s "$bad/identity-real" "$bad/identity"
  expect_fail2 step1-identity-symlink \
    with_creds "$bad" device "$d" id
  rm "$bad/identity"; mv "$bad/identity-real" "$bad/identity"

  chmod 640 "$bad/identity"
  expect_fail2 step1-identity-group-readable \
    with_creds "$bad" device "$d" id
  chmod 600 "$bad/identity"

  sudo chown root "$bad/identity"
  expect_fail2 step1-identity-wrong-owner \
    with_creds "$bad" device "$d" id
  sudo chown "$(id -un)" "$bad/identity"

  printf 'not-hex-at-all!!' > "$bad/identity-junk"
  chmod 600 "$bad/identity-junk"
  cp "$bad/identity-junk" "$bad/identity"
  expect_fail2 step1-identity-bad-content \
    with_creds "$bad" device "$d" id
  cp "$c/identity" "$bad/identity"

  python3 -c 'import sys; sys.stdout.write("x" * 5000)' > "$bad/passphrase-big"
  chmod 600 "$bad/passphrase-big"
  cp "$bad/passphrase-big" "$bad/passphrase"
  expect_fail2 step1-passphrase-too-big \
    with_creds "$bad" device "$d" id
  cp "$c/passphrase" "$bad/passphrase"

  mv "$bad/passphrase" "$bad/passphrase-real"
  ln -s "$bad/passphrase-real" "$bad/passphrase"
  expect_fail2 step1-passphrase-symlink \
    with_creds "$bad" device "$d" id
  rm "$bad/passphrase"; mv "$bad/passphrase-real" "$bad/passphrase"

  # init itself rejects bad credentials too (fresh dir, junk identity).
  cp "$bad/identity-junk" "$bad/identity"
  expect_fail2 step1-init-bad-identity \
    with_creds "$bad" init "$DRIVES/owner-bad"
  cp "$c/identity" "$bad/identity"
  [[ -e "$DRIVES/owner-bad" ]] && die "failed init left a drive dir behind"

  # Good credentials still open after all the negative cases.
  expect_exit 0 step1-reopen with_creds "$c" device "$d" id >/dev/null
  pass "good credentials still open"

  local f
  for f in "$LOGDIR"/step1-*.stderr; do
    check_no_leaks "$f" "$identity" "$passphrase"
  done
}

step2_mount() {
  step 2 "local-only mount"
  local d="$DRIVES/owner" c="$CREDS/owner"

  start_mount local "$c" "$d" "$MNTS/local"
  grep -q "warning: no --relay given; control-plane intake stays idle" \
    "$LOGDIR/mount-local.err" || die "local: no idle-intake warning on stderr"
  pass "local: idle-intake warning on stderr"
  grep -q "control-plane intake stays idle: no --relay given" "$d/mount.log" \
    || die "local: idle-intake line missing from mount.log"
  pass "local: idle-intake line in mount.log"

  echo "local-write" > "$MNTS/local/note.txt"
  [[ "$(cat "$MNTS/local/note.txt")" == "local-write" ]] || die "local: read-your-write failed"
  pass "local: reads/writes serve without a relay"

  local first_id
  first_id="$(grep -o "serving over iroh: [0-9a-f]*" "$LOGDIR/mount-local.err" | head -n 1)"
  stop_mount local INT

  # mount.log is truncated per mount: the second mount's log must not
  # contain the first mount's endpoint id.
  start_mount local2 "$c" "$d" "$MNTS/local"
  grep -qF "$first_id" "$d/mount.log" && die "local: mount.log accumulated across mounts"
  pass "local: mount.log truncated per mount"
  [[ "$(cat "$MNTS/local/note.txt")" == "local-write" ]] || die "local: write lost across remount"
  pass "local: writes persist across remount"
  stop_mount local2 TERM

  check_no_leaks "$LOGDIR/mount-local.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-local2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$d/mount.log" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}
# --- step 3: write matrix -----------------------------------------------
step3_matrix() {
  step 3 "write matrix"
  local d="$DRIVES/owner" c="$CREDS/owner"

  start_mount matrix "$c" "$d" "$MNTS/matrix"
  set +e
  python3 /mnt/wyrd/tests/alpha-lima-matrix.py "$MNTS/matrix" >"$LOGDIR/matrix.out" 2>&1
  local status=$?
  set -e
  cat "$LOGDIR/matrix.out"
  [[ $status -eq 0 ]] || die "write matrix failed"
  pass "write matrix: all python cases passed"
  stop_mount matrix INT

  check_no_leaks "$LOGDIR/mount-matrix.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/matrix.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# --- step 4: offline member/device ---------------------------------------

step4_member() {
  step 4 "offline member/device"
  local od="$DRIVES/owner" oc="$CREDS/owner"
  local ndr="$DRIVES/newcomer" nc="$CREDS/newcomer"
  mkdir -p "$nc" "$ndr"
  gen_identity "$nc/identity"; gen_passphrase "$nc/passphrase"
  local n_identity n_passphrase
  n_identity="$(cat "$nc/identity")"; n_passphrase="$(cat "$nc/passphrase")"

  # The newcomer dir starts empty (no init): pairing stages member
  # state, and join fills it. Joining an init'd owner home refuses.
  expect_exit 0 step4-pairing \
    with_creds "$nc" device "$ndr" pairing-request "$E2E_ROOT/pairing.txt" >/dev/null
  pass "pairing-request stages material in an empty dir"
  expect_exit 0 step4-pairing-stable \
    with_creds "$nc" device "$ndr" pairing-request "$E2E_ROOT/pairing2.txt" >/dev/null
  cmp -s "$E2E_ROOT/pairing.txt" "$E2E_ROOT/pairing2.txt" \
    || die "pairing re-run changed the key"
  pass "pairing re-run returns the same key"
  local dev key
  dev="$(awk '/^device /{print $2}' "$E2E_ROOT/pairing.txt")"
  key="$(awk '/^encryption-key /{print $2}' "$E2E_ROOT/pairing.txt")"
  [[ "${#dev}" == 64 && "${#key}" == 64 ]] || die "pairing material malformed"

  expect_exit 0 step4-invite \
    with_creds "$oc" member "$od" invite "$dev" "$key" "$E2E_ROOT/invitation" >/dev/null
  [[ -f "$E2E_ROOT/invitation" ]] || die "invite wrote no invitation file"
  pass "invite admits the device and seals an invitation"

  # The destination is claimed before the commit: inviting a second
  # device onto an existing file refuses with no transition authored.
  local nc2="$CREDS/newcomer-b" ndr2="$DRIVES/newcomer-b"
  mkdir -p "$nc2" "$ndr2"
  gen_identity "$nc2/identity"; gen_passphrase "$nc2/passphrase"
  expect_exit 0 step4-pairing-b \
    with_creds "$nc2" device "$ndr2" pairing-request "$E2E_ROOT/pairing-b.txt" >/dev/null
  local dev_b key_b
  dev_b="$(awk '/^device /{print $2}' "$E2E_ROOT/pairing-b.txt")"
  key_b="$(awk '/^encryption-key /{print $2}' "$E2E_ROOT/pairing-b.txt")"
  touch "$E2E_ROOT/taken"
  expect_fail2 step4-invite-taken \
    with_creds "$oc" member "$od" invite "$dev_b" "$key_b" "$E2E_ROOT/taken"
  with_creds "$oc" member "$od" list | grep -q "$dev_b" \
    && die "refused invite still authored a transition"
  pass "invite onto an existing file refuses before the commit"

  # Lose the sealed invitation, recover with a reseal, join from it:
  # the reseal opens identically, with fresh randomness.
  rm "$E2E_ROOT/invitation"
  expect_exit 0 step4-reissue \
    with_creds "$oc" member "$od" reissue-invitation "$dev" "$E2E_ROOT/invitation2" >/dev/null
  [[ -f "$E2E_ROOT/invitation2" ]] || die "reissue wrote no file"
  pass "reissue reseals the admission from durable state"

  expect_exit 0 step4-join \
    with_creds "$nc" device "$ndr" join "$E2E_ROOT/invitation2" >/dev/null
  pass "join accepts the reissued invitation"
  local id_out
  id_out="$(expect_exit 0 step4-id with_creds "$nc" device "$ndr" id)"
  [[ "$id_out" == "device $dev"* ]] || die "joined id mismatch: $id_out"
  pass "joined device reopens with member custody"

  local owner_id
  owner_id="$(with_creds "$oc" device "$od" id | awk '/^device /{print $2}')"
  local list_out
  list_out="$(expect_exit 0 step4-list with_creds "$oc" member "$od" list)"
  echo "$list_out" | grep -q "^owner $owner_id$" || die "list misses the owner"
  echo "$list_out" | grep -q "^member $dev$" || die "list misses the newcomer"
  pass "list shows owner and newcomer at the tip"
  local log_out
  log_out="$(expect_exit 0 step4-log with_creds "$oc" member "$od" log)"
  [[ "$(echo "$log_out" | wc -l)" == 2 ]] || die "log is not genesis+invite: $log_out"
  echo "$log_out" | grep -q "canonical" || die "log misses canonical status"
  pass "log shows genesis and invite, both canonical"
  local held_before
  held_before="$(expect_exit 0 step4-status with_creds "$oc" member "$od" status \
    | sed -n 's/^held secrets: //p')"
  [[ "$held_before" == "1 2" ]] || die "held secrets before rotate: $held_before"
  pass "status shows held secrets 1 2"

  expect_exit 0 step4-rotate with_creds "$oc" member "$od" rotate >/dev/null
  pass "rotate forces a fresh epoch"
  local held_after
  held_after="$(with_creds "$oc" member "$od" status \
    | sed -n 's/^held secrets: //p')"
  [[ "$held_after" == "$held_before 3" ]] || die "held secrets did not grow: $held_after"
  pass "held secrets grow across rotate ($held_after)"

  expect_fail2 step4-reinvite \
    with_creds "$oc" member "$od" invite "$dev" "$key" "$E2E_ROOT/invitation-dup"
  grep -qi "already a member" "$LOGDIR/step4-reinvite.stderr" \
    || die "re-invite did not report AlreadyMember"

  expect_fail2 step4-remove-sole-owner \
    with_creds "$oc" member "$od" remove "$owner_id"
  grep -q "sole owner" "$LOGDIR/step4-remove-sole-owner.stderr" \
    || die "sole-owner remove refusal unexplained"

  local f
  for f in "$LOGDIR"/step4-*.stderr; do
    check_no_leaks "$f" "$(cat "$oc/identity")" "$(cat "$oc/passphrase")" \
      "$n_identity" "$n_passphrase" \
      "$(cat "$nc2/identity")" "$(cat "$nc2/passphrase")"
  done
}
# --- step 5: offline export ----------------------------------------------

step5_export() {
  step 5 "offline export"
  local od="$DRIVES/owner" oc="$CREDS/owner"

  # Export while mounted: the offline egress path reads the drive
  # directly, and the tree must match the live mount exactly. (No
  # divergent heads exist single-device, so no `name@N` siblings.)
  start_mount export "$oc" "$od" "$MNTS/export"

  # Offline commands take the store lock: exporting under a live
  # mount refuses instead of reading a moving drive.
  expect_fail2 step5-locked \
    with_creds "$oc" export "$od" "$E2E_ROOT/export-locked"
  grep -q "another process holds" "$LOGDIR/step5-locked.stderr" \
    || die "locked-store refusal unexplained"
  [[ -e "$E2E_ROOT/export-locked" ]] && die "refused export wrote output"

  # Snapshot the live tree (listing, checksums, modes), then export
  # offline after unmount and compare exactly.
  (cd "$MNTS/export" && find . | sort > "$LOGDIR/tree.list")
  (cd "$MNTS/export" && find . -type f -exec md5sum {} + | sort -k2 > "$LOGDIR/tree.md5")
  (cd "$MNTS/export" && find . -type f -perm -111 | sort > "$LOGDIR/tree.exec")
  stop_mount export INT

  expect_exit 0 step5-export \
    with_creds "$oc" export "$od" "$E2E_ROOT/export1" >/dev/null
  pass "export materializes a plain tree"
  (cd "$E2E_ROOT/export1" && find . | sort) | diff "$LOGDIR/tree.list" - \
    || die "export listing differs from the live mount"
  (cd "$E2E_ROOT/export1" && find . -type f -exec md5sum {} + | sort -k2) \
    | diff "$LOGDIR/tree.md5" - || die "export content differs from the live mount"
  (cd "$E2E_ROOT/export1" && find . -type f -perm -111 | sort) \
    | diff "$LOGDIR/tree.exec" - || die "export modes differ from the live mount"
  pass "export matches the live mount (listing, content, exec bits)"

  # A refused export modifies nothing: snapshot the tree, refuse,
  # compare.
  cp -r "$E2E_ROOT/export1" "$E2E_ROOT/export1-copy"
  expect_fail2 step5-populated \
    with_creds "$oc" export "$od" "$E2E_ROOT/export1"
  diff -r "$E2E_ROOT/export1" "$E2E_ROOT/export1-copy" \
    || die "refused export modified the destination"
  pass "populated destination refused, tree untouched"

  expect_usage2 step5-no-relay \
    with_creds "$oc" export --relay ws://127.0.0.1:1 "$od" "$E2E_ROOT/export2"

  # A failed run leaves no partial tree behind.
  mkdir -p "$E2E_ROOT/ro" && chmod 555 "$E2E_ROOT/ro"
  expect_fail2 step5-unwritable \
    with_creds "$oc" export "$od" "$E2E_ROOT/ro/out"
  [[ -e "$E2E_ROOT/ro/out" ]] && die "failed export left a partial tree"
  pass "failed export leaves no partial tree"
  chmod 755 "$E2E_ROOT/ro"

  local f
  for f in "$LOGDIR"/step5-*.stderr "$LOGDIR"/mount-export.err; do
    check_no_leaks "$f" "$(cat "$oc/identity")" "$(cat "$oc/passphrase")"
  done
}
# converged <file> <want>: file exists with exactly the wanted content.
converged() {
  [[ -f "$1" ]] && [[ "$(cat "$1")" == "$2" ]]
}

# --- step 6: live relay convergence -------------------------------------
# Two mounts, one relay, both directions: the owner's writes appear on
# the member's mount and back. This is the publish path's e2e proof —
# intake, outbox, announcement, fetch — over a real relay process.
step6_relay() {
  step 6 "live relay convergence"
  local od="$DRIVES/owner" oc="$CREDS/owner"
  local ndr="$DRIVES/newcomer" nc="$CREDS/newcomer"
  local relay="ws://127.0.0.1:$RELAY_PORT"

  command -v nostr-rs-relay >/dev/null \
    || die "nostr-rs-relay missing in the guest (provision.sh installs it)"

  # The demand assertions below read the loop's defer/timeout lines, so
  # the mounts run with the core trace on regardless of the outer
  # default (the CLI's own lines are plain stderr, unaffected).
  export E2E_RUST_LOG="${E2E_RUST_LOG:-wyrd_core=debug}"

  # The suite owns the port: a previous --keep run may have stranded a
  # relay, and two relays cannot share the port. Exact-name match only.
  pkill -x nostr-rs-relay 2>/dev/null || true
  sleep 1

  cat > "$E2E_ROOT/relay.toml" <<EOF
[info]
relay_url = "$relay/"
name = "wyrd-e2e"
description = "Lima e2e relay; guest-local, one run."

[network]
address = "127.0.0.1"
port = $RELAY_PORT
EOF
  mkdir -p "$E2E_ROOT/relay-db"

  # start_relay [log-suffix]: the mounts' control plane needs it up;
  # a mid-step restart (the conflict fixture) reuses the same config
  # and database under a suffixed log.
  start_relay() {
    nostr-rs-relay -c "$E2E_ROOT/relay.toml" -d "$E2E_ROOT/relay-db" \
      >"$LOGDIR/relay${1:-}.out" 2>"$LOGDIR/relay${1:-}.err" &
    echo $! > "$E2E_ROOT/relay.pid"
    poll_until 20 bash -c "exec 3<>/dev/tcp/127.0.0.1/$RELAY_PORT" \
      || die "relay never listened on $RELAY_PORT (see relay${1:-}.err)"
  }

  start_relay
  pass "relay listening on $RELAY_PORT"

  start_mount owner-relay "$oc" "$od" "$MNTS/owner-relay" --relay "$relay"
  start_mount member-relay "$nc" "$ndr" "$MNTS/member-relay" --relay "$relay"

  # With a relay given, intake must stay live: the idle warning from
  # step 2 must be absent, and the serving endpoint (whose address the
  # announcements carry) must be bound on both mounts.
  local m
  for m in owner-relay member-relay; do
    grep -q "control-plane intake stays idle" "$LOGDIR/mount-$m.err" \
      && die "$m: idle intake despite --relay"
    grep -q "serving over iroh" "$LOGDIR/mount-$m.err" \
      || die "$m: serving endpoint never bound"
  done
  pass "both relay mounts keep intake live and serve"

  # Owner to member, then member to owner, then owner again: the last
  # leg proves convergence holds across successive writes, not just
  # the first catch-up.
  echo "owner-write-1" > "$MNTS/owner-relay/shared.txt"
  poll_until 90 converged "$MNTS/member-relay/shared.txt" "owner-write-1" \
    || die "member never converged on the owner's write"
  pass "member converges on owner writes via the relay"

  echo "member-write-1" > "$MNTS/member-relay/from-member.txt"
  poll_until 90 converged "$MNTS/owner-relay/from-member.txt" "member-write-1" \
    || die "owner never converged on the member's write"
  pass "owner converges on member writes via the relay"

  echo "owner-write-2" > "$MNTS/owner-relay/shared.txt"
  poll_until 90 converged "$MNTS/member-relay/shared.txt" "owner-write-2" \
    || die "member missed the owner's second write"
  pass "convergence holds across successive writes"

  # --- peer-down demand, bounded failure, re-announcement recovery ---
  # The owner commits a large file; its head (trees and manifests) reaches
  # the member, the bulk content streams after. On loopback the object
  # phase finishes in milliseconds, so throttle loopback IP traffic
  # (the bulk fetch travels over it; FUSE writes are unix sockets and
  # stay instant) until the head is installed, then stop the owner
  # mid-transfer: the member keeps an installed head whose file chunks
  # are remote-only — the exact state a mounted write must demand
  # through. The member appends: the demand cannot be served, so the
  # commit must fail bounded (ETIMEDOUT at the prerequisite deadline),
  # never hang.
  command -v tc >/dev/null || die "tc missing (provision.sh installs iproute2)"
  # Clear a qdisc stranded by a killed run before throttling.
  sudo tc qdisc del dev lo root 2>/dev/null || true
  sudo tc qdisc add dev lo root netem rate 4mbit delay 10ms
  # An idle line before the write anchors the quiesce check below: a
  # pass only reports idle when it short-circuits before publication,
  # so one seen after the write means the owner's publish pass — and
  # with it the serving-mirror flush of the whole closure — finished.
  local idle_before
  idle_before=$(grep -c "sync pass idle" "$LOGDIR/mount-owner-relay.err" || true)
  dd if=/dev/zero of="$MNTS/owner-relay/peer-down.bin" bs=1M count=56 \
    status=none
  poll_until 120 test -e "$MNTS/member-relay/peer-down.bin" \
    || die "member never saw the owner's file (head did not install)"
  # Let the owner quiesce first: its graceful shutdown drains the
  # serving mirror, and stopping it mid-import of a 56MiB closure
  # would measure the mirror, not the shutdown.
  poll_until 120 bash -c "[[ \$(grep -c 'sync pass idle' '$LOGDIR/mount-owner-relay.err') -gt $idle_before ]]" \
    || die "the owner never quiesced (serving-mirror drain stuck?)"
  # Stop the owner with the throttle STILL on, so the member provably
  # cannot pull the rest of the file during the stop window: the
  # owner dies with its serving socket while loopback stays at
  # 4mbit, so the member's remaining chunks stay undelivered. The
  # shutdown's control plane rides the same loopback, but only small
  # messages; the drain that needs the larger budget is the
  # serving-store persist, which is disk, not network.
  # 90s: the owner holds a 56MiB closure, and its exit persists the
  # serving store — bounded, but far past the 15s small-vault budget.
  stop_mount owner-relay INT 90
  sudo tc qdisc del dev lo root 2>/dev/null || true
  pass "owner stopped mid-transfer (member head installed, chunks remote)"

  local started elapsed rc
  started=$(date +%s)
  set +e
  # notrunc is load-bearing: dd truncates by default, the kernel splits
  # the truncate out of the open, and the append-handle guard then
  # refuses the whole open (EOPNOTSUPP) before any byte is written.
  timeout 45 dd if=/dev/zero bs=1 count=1 of="$MNTS/member-relay/peer-down.bin" \
    oflag=append conv=notrunc,fsync status=none 2>"$LOGDIR/step6-peer-down.stderr"
  rc=$?
  set -e
  elapsed=$(( $(date +%s) - started ))
  [[ "$rc" -ne 124 ]] || die "peer-down append hung instead of failing bounded"
  (( elapsed >= 20 && elapsed <= 45 )) \
    || die "peer-down append failed after ${elapsed}s, outside the 30s bound"
  grep -qE "Connection timed out|Input/output error" "$LOGDIR/step6-peer-down.stderr" \
    || die "peer-down append failed without a bounded errno (see step6-peer-down.stderr)"
  grep -q "mutation deferred for authoring content" "$LOGDIR/mount-member-relay.err" \
    || die "the append never demanded its remote base (no defer in the log)"
  grep -q "mutation prerequisite wait expired" "$LOGDIR/mount-member-relay.err" \
    || die "the demand never reached its deadline (no timeout in the log)"
  pass "peer-down demand fails bounded (${elapsed}s, prerequisite deadline)"

  # The member now holds a dead route for the owner. Restarting the
  # owner binds a fresh iroh endpoint; the live loop re-announces under
  # the live route (the route-specific reseal), the member accepts the
  # route update, and a new owner write converges with no manual repair.
  start_mount owner-restarted "$oc" "$od" "$MNTS/owner-restarted" --relay "$relay"
  grep -q "serving over iroh" "$LOGDIR/mount-owner-restarted.err" \
    || die "restarted owner: serving endpoint never bound"
  echo "after-restart" > "$MNTS/owner-restarted/after-restart.txt"
  poll_until 90 converged "$MNTS/member-relay/after-restart.txt" "after-restart" \
    || die "member never converged after the owner's re-announcement"
  pass "re-announcement recovers the route after owner restart"

  stop_mount owner-restarted INT
  stop_mount member-relay TERM
  pass "peer-down pair stopped"

  # The conflict-sibling export leg (the issue's `name@N` acceptance
  # item) is not in the guest contract yet, and the export side of it
  # is pinned by unit tests (wyrd-core export: both versions
  # materialized as name@1/name@2, and a stored name meeting a
  # versioned sibling fails closed). The end-to-end leg needs one of
  # two product capabilities this branch does not claim: a mailbox
  # that reconnects when the relay returns (a relay-outage divergence
  # never converges in-process today), or a barrier that lets both
  # sides author before either sees the other's head (back-to-back
  # writes race and the member converges first on loopback). Tracked
  # as the conflict-divergence follow-up; non-blocking for the review.

  stop_relay
  pass "relay stopped"

  local f
  for f in "$LOGDIR"/step6-*.stderr "$LOGDIR"/mount-owner-relay.err \
          "$LOGDIR"/mount-owner-restarted.err \
          "$LOGDIR"/mount-member-relay.err "$LOGDIR"/relay.out "$LOGDIR"/relay.err \
          "$LOGDIR"/relay-conflict.out "$LOGDIR"/relay-conflict.err \
          ; do
    [[ -f "$f" ]] || continue
    check_no_leaks "$f" "$(cat "$oc/identity")" "$(cat "$oc/passphrase")" \
      "$(cat "$nc/identity")" "$(cat "$nc/passphrase")"
  done
}
main() {
  # Fresh slate every run: steps build on each other within one run, and a
  # previous partial run must never leak state into the next. Unmount
  # first — rm cannot remove a live mountpoint.
  mkdir -p "$MNTS" "$LOGDIR"
  cleanup_mounts
  # Any exit — a failed check included — unmounts, reaps, and stops the
  # relay: a surviving background process inherits this script's
  # stdout, so the host's `limactl shell` would wait for a pipe that
  # never closes and the run would hang instead of failing.
  reap_background() {
    cleanup_mounts
    stop_relay
  }
  trap reap_background EXIT
  # A run killed while step 6 throttled loopback leaves the qdisc
  # behind; clear it so this run starts unthrottled.
  command -v tc >/dev/null && { sudo tc qdisc del dev lo root 2>/dev/null || true; }
  # A stranded relay outlives `wait` in cleanup (it is a background job
  # of this shell) and blocks the next run's bind: reclaim the port.
  if [[ -f "$E2E_ROOT/relay.pid" ]]; then
    kill -KILL "$(cat "$E2E_ROOT/relay.pid")" 2>/dev/null || true
  fi
  rm -rf "$E2E_ROOT"
  mkdir -p "$DRIVES" "$CREDS" "$MNTS" "$LOGDIR"
  local only="${E2E_ONLY_STEP:-}"
  # Comma list (`--step 1,4,6`): steps build on each other, so the run
  # set is the prefix closure of the selection — selecting step N runs
  # 1..N, never a lone dependent step on wiped state. Every entry must
  # name a real step, so `--step 99` fails instead of passing zero
  # checks, and the highest entry decides the prefix.
  local max_step=0
  local entry
  # Split on commas into a quoted array: an unquoted expansion would
  # glob each entry against the working directory first, so `--step
  # '*'` could pathname-expand into a digit-named file and slip past
  # the grammar.
  local -a entries=()
  if [[ -n "$only" ]]; then
    IFS=',' read -r -a entries <<< "$only"
  fi
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[1-6]$ ]] \
      || die "--step: '$entry' is not a step (expected a comma list of 1-6)"
    if (( entry > max_step )); then max_step=$entry; fi
  done
  # An empty or empty-entry selection (`,`, `4,,5`, `,4`) is a
  # mistake, not "all steps": without this it would run zero checks
  # and pass. An absent variable (the wrapper omits it) means all.
  if [[ -n "$only" ]]; then
    # The grammar is a comma list; whitespace is not a separator.
    [[ "$only" != *[[:space:]]* ]] \
      || die "--step: '$only' is not a comma list (got whitespace)"
    [[ "$max_step" -gt 0 ]] \
      || die "--step: '$only' names no step (expected a comma list of 1-6)"
    [[ ",$only," != *,,* ]] \
      || die "--step: '$only' has an empty entry (expected 1-6 entries)"
  fi
  want_step() { [[ -z "$only" ]] || (( $1 <= max_step )); }
  if want_step 1; then step1_init; fi
  if want_step 2; then step2_mount; fi
  if want_step 3; then step3_matrix; fi
  if want_step 4; then step4_member; fi
  if want_step 5; then step5_export; fi
  if want_step 6; then step6_relay; fi
  echo "e2e: $PASS_COUNT checks passed"
}

main "$@"
