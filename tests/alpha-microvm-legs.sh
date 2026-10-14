#!/usr/bin/env bash
# tests/alpha-microvm-legs.sh — per-guest legs for the microVM hardened
# gate, executed over ssh by tests/alpha-microvm.sh (host). Baked into
# every peer guest at /etc/wyrd-tests/; never run directly.
#
# Each leg is a whole mount lifecycle (start, file ops, stop) so pid
# files never cross pid namespaces. legs report via step/pass/die from
# tests/alpha-common.sh; the host counts PASS lines and fails on a
# non-zero ssh exit.
set -euo pipefail

E2E_ENV_FILE="${E2E_ENV_FILE:-/mnt/wyrd-state/e2e-env.sh}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Wrapper-only entry, before alpha-common.sh sources the env file
# (sourcing first would install the published token into this shell
# and make the comparison vacuous). The host orchestrator passes
# the run token on every ssh invocation; anything else dies here.
# shellcheck source=/dev/null
source "$SCRIPT_DIR/e2e-guard.sh"
e2e_require_wrapped "$E2E_ENV_FILE" "sudo ./nix/microvm/run-microvm.sh" \
  || { echo "  FAIL: unwrapped legs invocation refused" >&2; exit 2; }
# shellcheck source=/dev/null
source /etc/wyrd-tests/alpha-common.sh

# Per-guest pid dir: legs run concurrently on guests sharing one
# E2E_ROOT, and same-image mount pids collide across hosts — a
# shared pid dir lets one leg's EXIT trap SIGKILL the other's live
# mount (or an unrelated pid). Done-files stay shared (rendezvous);
# pids must not be. (alpha-common.sh sources the env file itself.)
PIDDIR="$E2E_ROOT/pids/$(hostname -s)"

# Per-probe section timing for the long legs (steps 9, 13, and 15
# today): each mark prints the wall seconds since the previous mark, so the
# breakdown is greppable in the leg log
# (`step<PROBE_STEP> probe <name>=<Ns>`) without changing any probe.
# Marks sit beside the passes they follow; the pass deltas stay the
# check-level view. The step prefix defaults to 9; a leg on another
# step sets a local PROBE_STEP first instead of emitting a false step
# (local: the dispatch runs one leg per process, and a global would
# leak a false step into any later leg in the same shell).
PROBE_STEP="${PROBE_STEP:-9}"
PROBE_MARK=$SECONDS
probe_mark() { # <name>
  printf 'step%s probe %s=%ss\n' "$PROBE_STEP" "$1" "$(( SECONDS - PROBE_MARK ))"
  PROBE_MARK=$SECONDS
}

# leg_converge_owner <drive> <creds> <relay>: mount, write shared.txt,
# wait for the member's reply, stop.
leg_converge_owner() {
  local d="$1" c="$2" relay="$3"
  step 7 "cross-host owner leg"
  start_mount xowner "$c" "$d" "$MNTS/xowner" --relay "$relay"
  echo "owner-write-1" > "$MNTS/xowner/shared.txt"
  poll_until 90 converged "$MNTS/xowner/from-member.txt" "member-write-1" \
    || die "owner never converged on the member's write"
  pass "owner converges on member writes across hosts"
  touch "$E2E_ROOT/owner-done"
  stop_mount xowner INT
  check_no_leaks "$LOGDIR/mount-xowner.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_converge_member <drive> <creds> <relay>: mount, wait for the
# owner's write, reply, stop.
leg_converge_member() {
  local d="$1" c="$2" relay="$3"
  step 7 "cross-host member leg"
  start_mount xmember "$c" "$d" "$MNTS/xmember" --relay "$relay"
  poll_until 90 converged "$MNTS/xmember/shared.txt" "owner-write-1" \
    || die "member never converged on the owner's write"
  pass "member converges on owner writes across hosts"
  echo "member-write-1" > "$MNTS/xmember/from-member.txt"
  # Stay up until the owner reports convergence (it touches
  # owner-done when done): an early exit here would drop the serving
  # route the owner is still fetching over.
  poll_until 120 test -f "$E2E_ROOT/owner-done" \
    || die "owner leg never finished"
  stop_mount xmember TERM
  check_no_leaks "$LOGDIR/mount-xmember.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_converge2_owner <drive> <creds> <relay>: wave 2 of the
# cross-host proof (the embedded consumer converges without
# mounting): write the second wave through the FUSE adapter and
# stay up serving until the member reports its headless
# convergence — the stop must not precede the member's fetch, or
# nothing serves wave-2 bodies. The mount-free capture happens
# after the stop: the keystore is held by the running mount, so
# the offline snapshot reads run on the free drive.
leg_converge2_owner() {
  local d="$1" c="$2" relay="$3"
  step 7 "wave-2 owner leg (FUSE-authored)"
  start_mount xowner-w2 "$c" "$d" "$MNTS/xowner-w2" --relay "$relay"
  echo "wave2-a-bytes" > "$MNTS/xowner-w2/wave2-a.txt"
  mkdir -p "$MNTS/xowner-w2/wave2-dir"
  echo "wave2-b-bytes" > "$MNTS/xowner-w2/wave2-dir/wave2-b.txt"
  echo "owner-write-2" > "$MNTS/xowner-w2/shared.txt"
  pass "wave-2 written through the FUSE adapter"
  touch "$E2E_ROOT/owner-w2-written"
  poll_until 300 test -f "$E2E_ROOT/member-w2-done" \
    || die "member never converged on wave 2"
  stop_mount xowner-w2 INT
  with_creds "$c" snapshot "$d" list >"$E2E_ROOT/wave2-owner-list.txt" \
    || die "owner snapshot list failed"
  pass "owner converged state captured mount-free"
  check_no_leaks "$LOGDIR/mount-xowner-w2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$E2E_ROOT/wave2-owner-list.txt" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_converge2_member <drive> <creds> <relay>: the embedded
# consumer half — converge on wave 2 with headless `sync now` and
# no mount up, then read the converged state mount-free
# (`snapshot list`: heads with their tree hashes). v0 promises no
# headless materialization, so the proof is structural: identical
# live heads mean identical manifests, hence identical bytes by
# CAS. (`snapshot plan` cannot serve here: it refuses a single
# head, and this wave converges to exactly one.) A mount follows
# only to fault one wave-2 file in, tying this wave's heads to
# bytes through the serving route (the step-12 pattern), before
# the done-file releases the owner to stop.
leg_converge2_member() {
  local d="$1" c="$2" relay="$3"
  step 7 "wave-2 member leg (embedded consumer)"
  poll_until 300 test -f "$E2E_ROOT/owner-w2-written" \
    || die "owner never wrote wave 2"
  with_creds "$c" sync "$d" --relay "$relay" now \
    >"$LOGDIR/member-w2-sync.out" 2>"$LOGDIR/member-w2-sync.err" \
    || die "member wave-2 headless sync exited non-zero"
  grep -qE "fetch [0-9]+ manifests, [0-9]+ bodies, [1-9][0-9]* objects" "$LOGDIR/member-w2-sync.out" \
    || die "member wave-2 sync fetched no objects (see member-w2-sync.out)"
  pass "member converges on wave 2 with no mount up"
  with_creds "$c" snapshot "$d" list >"$E2E_ROOT/wave2-member-list.txt" \
    || die "member snapshot list failed"
  pass "member converged state captured mount-free"
  start_mount xmember-w2 "$c" "$d" "$MNTS/xmember-w2" --relay "$relay"
  [[ "$(cat "$MNTS/xmember-w2/wave2-a.txt")" == "wave2-a-bytes" ]] \
    || die "member wave-2 mount lost wave2-a.txt"
  [[ "$(cat "$MNTS/xmember-w2/shared.txt")" == "owner-write-2" ]] \
    || die "member wave-2 mount lost the shared.txt overwrite"
  pass "member faults wave-2 bytes in over the serve route"
  stop_mount xmember-w2 INT
  touch "$E2E_ROOT/member-w2-done"
  check_no_content_ids "$LOGDIR/member-w2-sync.out"
  check_no_leaks "$LOGDIR/member-w2-sync.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/member-w2-sync.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$E2E_ROOT/wave2-member-list.txt" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-xmember-w2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_restarted_owner <drive> <creds> <relay>: mount (endpoint 1),
# write the pre-restart marker, wait for the member to converge on
# it, then stop and mount fresh (endpoint 2): the stop+remount IS
# the production restart (new iroh endpoint over a persisted
# route). Write again; the member must converge without remounting.
leg_restarted_owner() {
  local d="$1" c="$2" relay="$3"
  step 8 "serving restart leg"
  start_mount xowner-r1 "$c" "$d" "$MNTS/xowner-r1" --relay "$relay"
  echo "before-restart" > "$MNTS/xowner-r1/before-restart.txt"
  poll_until 120 test -f "$E2E_ROOT/member-ready" \
    || die "member never converged on the pre-restart write"
  pass "member converges before the restart"
  stop_mount xowner-r1 INT
  check_no_leaks "$LOGDIR/mount-xowner-r1.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  start_mount xowner-r2 "$c" "$d" "$MNTS/xowner-r2" --relay "$relay"
  grep -q "serving over iroh" "$LOGDIR/mount-xowner-r2.err" \
    || die "restarted owner: serving endpoint never bound"
  echo "after-restart" > "$MNTS/xowner-r2/after-restart.txt"
  poll_until 120 test -f "$E2E_ROOT/member-done" \
    || die "member never converged on the restarted owner"
  stop_mount xowner-r2 INT
  check_no_leaks "$LOGDIR/mount-xowner-r2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_restart_member <drive> <creds> <relay>: mount, converge on the
# pre-restart write, then hold that same mount across the owner's
# restart: the post-restart write must arrive over the re-announced
# route with no remount, no manual repair.
leg_restart_member() {
  local d="$1" c="$2" relay="$3"
  step 8 "restart convergence leg"
  start_mount xmember-r "$c" "$d" "$MNTS/xmember-r" --relay "$relay"
  poll_until 120 converged "$MNTS/xmember-r/before-restart.txt" "before-restart" \
    || die "member never converged before the restart"
  pass "member holds the pre-restart route"
  touch "$E2E_ROOT/member-ready"
  poll_until 120 converged "$MNTS/xmember-r/after-restart.txt" "after-restart" \
    || die "member never converged after the owner's re-announcement"
  pass "re-announcement recovers the route across hosts"
  touch "$E2E_ROOT/member-done"
  stop_mount xmember-r TERM
  check_no_leaks "$LOGDIR/mount-xmember-r.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_upgrade_owner <drive> <creds> <relay> <archive>: mount
# (endpoint 1), write the pre-upgrade marker, wait for the member to
# converge on it, then stop and upgrade the serving binary in place
# via `wyrd update` against the host-crafted same-checkout archive
# before mounting fresh (endpoint 2) with the upgraded binary: the
# stop+update+remount IS the production upgrade (new instance over a
# persisted route, re-announced under the live route). Write the
# post-upgrade set; the member must converge without remounting.
# The nix store is read-only, so the update targets a writable copy
# of the binary on the shared state root — the swap siblings live
# beside the copy, and WYRD_BIN is re-exported so every later helper
# uses the upgraded build. (Issue: post-upgrade convergence leg; the
# true cross-version extension reuses these assertions with a v0.2.0
# binary.)
leg_upgrade_owner() {
  local d="$1" c="$2" relay="$3" archive="$4"
  step 8 "post-upgrade serving leg"
  start_mount xowner-u1 "$c" "$d" "$MNTS/xowner-u1" --relay "$relay"
  echo "before-upgrade" > "$MNTS/xowner-u1/before-upgrade.txt"
  poll_until 120 test -f "$E2E_ROOT/member-u-ready" \
    || die "member never converged on the pre-upgrade write"
  pass "member converges before the upgrade"
  stop_mount xowner-u1 INT
  check_no_leaks "$LOGDIR/mount-xowner-u1.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  # Writable copy first: the shared store binary cannot be swapped
  # in place (read-only), and the update siblings must sit beside
  # the target executable on one filesystem.
  local uexe="$E2E_ROOT/wyrd-upgraded/wyrd"
  mkdir -p "$E2E_ROOT/wyrd-upgraded"
  cp "$WYRD_BIN" "$uexe"
  export WYRD_BIN="$uexe"
  with_creds "$c" update "$d" --archive "$archive" \
    >"$LOGDIR/update-owner.out" 2>"$LOGDIR/update-owner.err" \
    || die "owner update transaction failed (see update-owner.err)"
  grep -q "^update done: " "$LOGDIR/update-owner.out" \
    || die "owner update never reported done (see update-owner.out)"
  grep -q '"outcome": "done"' "$uexe.update-verdict" \
    || die "owner update verdict is not done (see wyrd-upgraded/wyrd.update-verdict)"
  pass "owner binary upgrades in place with a done verdict"
  # Transaction rendezvous: the member waits on this before its
  # convergence poll, so a slow update reports as a slow
  # transaction, never as a route failure.
  touch "$E2E_ROOT/owner-u-updated"
  check_no_leaks "$LOGDIR/update-owner.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  start_mount xowner-u2 "$c" "$d" "$MNTS/xowner-u2" --relay "$relay"
  grep -q "serving over iroh" "$LOGDIR/mount-xowner-u2.err" \
    || die "upgraded owner: serving endpoint never bound"
  echo "after-upgrade" > "$MNTS/xowner-u2/after-upgrade.txt"
  # Bulk byte-identity witness: random once, hash published over the
  # shared root — the member proves byte-identical receipt without
  # the suite baking the bytes.
  head -c 1048576 /dev/urandom > "$MNTS/xowner-u2/payload.bin"
  sha256sum "$MNTS/xowner-u2/payload.bin" | cut -d' ' -f1 > "$E2E_ROOT/upgrade-blob.sha256"
  poll_until 120 test -f "$E2E_ROOT/member-u-done" \
    || die "member never converged on the upgraded owner"
  stop_mount xowner-u2 INT
  check_no_leaks "$LOGDIR/mount-xowner-u2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_upgrade_member <drive> <creds> <relay>: mount, converge on the
# pre-upgrade write, then hold that same mount across the owner's
# binary upgrade: the post-upgrade set must arrive over the
# re-announced route with no remount, no manual repair — the old
# routes resend under the live route against the new binary.
leg_upgrade_member() {
  local d="$1" c="$2" relay="$3"
  step 8 "upgrade convergence leg"
  start_mount xmember-u "$c" "$d" "$MNTS/xmember-u" --relay "$relay"
  poll_until 120 converged "$MNTS/xmember-u/before-upgrade.txt" "before-upgrade" \
    || die "member never converged before the upgrade"
  pass "member holds the pre-upgrade route"
  touch "$E2E_ROOT/member-u-ready"
  # The update's verify children are budgeted well above the
  # convergence poll below: wait on the owner's transaction
  # rendezvous first, so only a live route is ever polled.
  poll_until 600 test -f "$E2E_ROOT/owner-u-updated" \
    || die "owner never finished the update transaction"
  poll_until 120 converged "$MNTS/xmember-u/after-upgrade.txt" "after-upgrade" \
    || die "member never converged after the owner's upgrade"
  pass "re-announcement recovers the route from the upgraded binary"
  poll_until 120 test -f "$E2E_ROOT/upgrade-blob.sha256" \
    || die "owner never published the payload hash"
  poll_until 120 blob_converged \
    || die "member payload diverged from the upgraded owner"
  pass "post-upgrade views are byte-identical"
  touch "$E2E_ROOT/member-u-done"
  stop_mount xmember-u TERM
  check_no_leaks "$LOGDIR/mount-xmember-u.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# blob_converged: the mounted payload hashes to the owner-published
# digest. Predicate form for poll_until (exit status only, no output).
blob_converged() {
  [[ -f "$MNTS/xmember-u/payload.bin" ]] || return 1
  [[ "$(sha256sum "$MNTS/xmember-u/payload.bin" | cut -d' ' -f1)" == "$(cat "$E2E_ROOT/upgrade-blob.sha256")" ]]
}

# leg_fetch_owner <drive> <creds> <relay>: mount, publish the cold
# file, then the two stale files the member lists before the route
# dies, then stop: the stop IS the stale-route setup — no VM
# surgery, just an unmounted owner. After the member's dead-route
# probes, remount on a fresh endpoint and write a new file first:
# the new announcement carries the new route (which the member's
# later tree fetch needs) and the head advances singly — the member
# converges it before authoring scratch, so no fork. The member
# must recover the second stale identity over the new route
# without remounting.
leg_fetch_owner() {
  local d="$1" c="$2" relay="$3"
  step 9 "fetch-plane owner leg"
  start_mount xowner-f "$c" "$d" "$MNTS/xowner-f" --relay "$relay"
  probe_mark owner_mount
  echo "cold-bytes" > "$MNTS/xowner-f/cold-2.txt"
  poll_until 120 test -f "$E2E_ROOT/member-cold-done" \
    || die "member never completed the blocking cold open"
  pass "member's single open unblocked on the announcement"
  probe_mark cold_served
  echo "stale-bytes" > "$MNTS/xowner-f/stale-1.txt"
  echo "stale-2-bytes" > "$MNTS/xowner-f/stale-2.txt"
  poll_until 120 test -f "$E2E_ROOT/member-listed-done" \
    || die "member never listed the stale files"
  # Stop before the member probes: the EIO probes below require the
  # route down — a live route would serve fetch-on-open and read rc
  # 0 instead of failing closed. The scratch write that localizes
  # trees for the later delete runs against the fresh endpoint
  # instead; same drive, same lineage, so nothing forks.
  stop_mount xowner-f INT
  touch "$E2E_ROOT/owner-stopped"
  probe_mark stopped
  check_no_leaks "$LOGDIR/mount-xowner-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  poll_until 240 test -f "$E2E_ROOT/member-probed-done" \
    || die "member never finished the dead-route probes"
  pass "owner stayed down while the member probed the dead route"
  probe_mark probed_wait
  # The bitrot block runs three deadline-bounded reads plus its
  # asserts after the probes: stay down until it signals
  # completion, or the remount below heals its later reads
  # mid-block and the fail-closed asserts race the recovery.
  poll_until 500 test -f "$E2E_ROOT/member-bitrot-done" \
    || die "member never finished the bitrot block"
  probe_mark bitrot_wait
  # Recovery setup: remount on a fresh endpoint (new iroh identity
  # over the same drive) and write a new file BEFORE the member
  # authors anything: the member converges this head first, so the
  # scratch and the delete extend the post-restart lineage instead
  # of forking it (the conflict phase forks deliberately later, on a
  # different path). The new announcement also carries the fresh
  # route the member needs for serving. File presence in the member's own view is the
  # self-synchronizing signal — no sleeps. Reading the scratch file
  # later also localizes its bytes: phase 6 exports this drive
  # offline and fails closed on remote-only content.
  start_mount xowner-f2 "$c" "$d" "$MNTS/xowner-f2" --relay "$relay"
  probe_mark owner_remount
  echo "owner-back" > "$MNTS/xowner-f2/owner-back-1.txt"
  touch "$E2E_ROOT/owner-back"
  # The member created its scratch file and deleted stale-1 on the
  # post-restart head; converge both before finishing, so the suite
  # never leaves a forked head behind.
  poll_until 180 test -f "$E2E_ROOT/member-scratch-done" \
    || die "member never created the scratch file"
  poll_until 120 converged "$MNTS/xowner-f2/scratch-del.txt" "scratch" \
    || die "owner never converged the scratch file's bytes"
  pass "owner converges the member's scratch write with bytes"
  probe_mark scratch_converged
  poll_until 240 test -f "$E2E_ROOT/member-fetch-done" \
    || die "member never finished the delete"
  poll_until 120 bash -c "! test -e '$MNTS/xowner-f2/stale-1.txt'" \
    || die "owner never converged the member's offline delete"
  pass "owner converges the delete before finishing"
  probe_mark delete_converged
  # Convergence ack: the member must not shut down until its
  # announcements have arrived here — a fast member would otherwise
  # outrun its own outbox drain and this leg could never converge.
  touch "$E2E_ROOT/owner-converged-done"
  probe_mark converged_ack
  # Ten attempts bound the member's worst case near eleven minutes
  # (10 x (60s attempt + 5s sleep)), so this wait must clear it or
  # the owner's diagnostic masks the member's own.
  poll_until 700 test -f "$E2E_ROOT/member-recovered-done" \
    || die "member never recovered the stale identity"
  stop_mount xowner-f2 INT
  probe_mark recovery_wait
  check_no_leaks "$LOGDIR/mount-xowner-f2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_fetch_member <drive> <creds> <relay>: mount, wait for the cold
# file's announcement via listing, then prove open() blocks for the
# bytes with ONE cat (no retry loop). List both stale files for
# their manifests only, then probe the dead route right after the
# owner stops — before authoring anything, so no local write can
# fetch the probed identities first (fetch-on-open serves a live
# route with rc 0, which is correct serving but the wrong probe).
# The stale-1 probe exercises read-side chunk demand (the manifest
# is already local, so open succeeds and the bounded EIO comes from
# the read) with the errno to prove it; the never-announced path
# fails fast with ENOENT — open blocks for content after announce,
# not for announcements themselves. The recovery identity fails
# bounded here too, so its later success proves revival. Then the
# owner returns on a fresh endpoint: converge its head (and route)
# first, scratch-write to localize the trees the delete needs, and
# delete stale-1 — all on the post-restart lineage, no fork. Close
# with the dedupe proof over the step-8 restart's redelivery.
# Wall-clock envelope (whole guest run shares the 90-minute
# whole-run budget):
# probes ~130s worst case, owner convergence chain concurrent with
# the member's recovery, recovery loop 650s worst case, ack waits
# fail-fast (120s member-side). Typical green run: 4-6 minutes.
# Per-probe `step9 probe <name>=<Ns>` lines in the leg logs break the
# total down (see probe_mark above); the recovery mark also reports
# the attempts used.
# Two matrix items are deliberately NOT e2e-legged here:
# timeout-then-completion (the waiter leaves with
# EIO while the fetch continues (unit-pinned by
# late_completion_caches_for_the_next_waiter in
# crates/wyrd-core/src/want.rs, no e2e leg).
# A third row is half-legged by construction: the stale probe pins
# fail-closed EIO but not "no invalid object committed", which is
# structurally guaranteed (verified ingest admits nothing invalid)
# and unobservable e2e — the member deletes stale-1.txt precisely
# because the export fails closed on remote-only content, so the
# export can never show that identity's absence.
# The recovery probe below is order-dependent, not a regression pin
# for decision 8 (fair share): candidate order is hash order, so a
# run where the live provider sorts first would pass without the
# fix. Read it as an end-to-end recovery smoke; the deterministic
# pin lives in-crate at
# runtime::plan::tests_execution::sliced_run_attempts_live_candidates_behind_a_dead_one,
# which builds the dead-first order explicitly.
leg_fetch_member() {
  local d="$1" c="$2" relay="$3"
  step 9 "fetch-plane member leg"
  # Debug for this mount only, Lima step-6 style: the class
  # assertion below greps a debug-level pass line, but a suite-wide
  # `wyrd_core=debug` would suppress the `wyrd`-target warn line
  # step 2 requires in mount.log (EnvFilter target directives
  # silence unmatched targets below error). Scoped save/restore so
  # later mounts keep the default info level.
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  export E2E_RUST_LOG="wyrd_core=debug"
  start_mount xmember-f "$c" "$d" "$MNTS/xmember-f" --relay "$relay"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  probe_mark cold_mount
  # Announcement first (listing shows the new head), bytes second
  # (the single cat below): this split is what makes the cat a
  # blocking-open proof rather than a find-ready-bytes no-op.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'cold-2.txt'" \
    || die "member never listed the cold file"
  # The create authors its own empty snapshot before the flush
  # commits the bytes (write-path DG-1: CreateFile is its own
  # snapshot), so the name converges ahead of the size: a cat now
  # serves a fully-converged empty file with rc 0, and the mismatch
  # below dies on a transient. Wait for the manifest's size first
  # (11 = "cold-bytes" plus the echo newline); the single cat after
  # still proves open blocks for the chunks.
  poll_until 120 bash -c "[[ \"\$(stat -c %s '$MNTS/xmember-f/cold-2.txt')\" == 11 ]]" \
    || die "member never converged the cold file's size"
  timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2.got" \
    || die "blocking cold open failed (open did not wait for the bytes)"
  [[ "$(cat "$E2E_ROOT/cold-2.got")" == "cold-bytes" ]] \
    || { echo "--- cold-2.got ($(wc -c <"$E2E_ROOT/cold-2.got") bytes) ---"; od -c "$E2E_ROOT/cold-2.got" | head -n 10; die "cold open returned wrong bytes"; }
  pass "single open blocks until the announced bytes arrive"
  probe_mark cold_open
  touch "$E2E_ROOT/member-cold-done"
  # Manifest-only convergence: readdir pulls the manifest chain
  # without opening contents, so the member holds the announcements
  # for both stale files while their chunks are still unfetched.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-1.txt'" \
    || die "member never listed stale-1.txt"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-2.txt'" \
    || die "member never listed stale-2.txt"
  touch "$E2E_ROOT/member-listed-done"
  probe_mark stale_listed
  poll_until 180 test -f "$E2E_ROOT/owner-stopped" \
    || die "owner never stopped for the dead-route probes"
  probe_mark route_down
  # Window start for the class assertion below: only passes logged
  # after the owner stopped can be about the dead-route probes — a
  # whole-log grep would also match pre-window passes.
  probed_from=$(wc -l < "$LOGDIR/mount-xmember-f.err")
  # Dead route, held manifest, nothing authored yet: the bytes are
  # announced but unfetchable, and no local write has had a chance
  # to demand them first. Each read must fail closed and bounded.
  local rc=0
  timeout 60 cat "$MNTS/xmember-f/stale-1.txt" >/dev/null 2>"$E2E_ROOT/stale-1.err" || rc=$?
  [[ "$rc" == 1 ]] || die "stale-manifest read returned rc $rc, want EIO (1)"
  grep -q "Input/output error" "$E2E_ROOT/stale-1.err" \
    || die "stale-manifest read was not EIO: $(cat "$E2E_ROOT/stale-1.err")"
  pass "announced-but-unfetchable read fails closed and bounded"
  probe_mark stale1_eio
  # Never announced at all: resolve fails fast, no 30s wait for an
  # announcement that may never come. The 10s budget (well under the
  # 30s open deadline) is what makes "immediately" real: a regression
  # that blocked the full deadline before ENOENT would die here as
  # rc 124 instead of passing as rc 1.
  rc=0
  timeout 10 cat "$MNTS/xmember-f/never-announced.txt" >/dev/null 2>"$E2E_ROOT/never-announced.err" || rc=$?
  [[ "$rc" == 1 ]] || die "unknown-path open returned rc $rc, want ENOENT (1)"
  grep -q "No such file or directory" "$E2E_ROOT/never-announced.err" \
    || die "unknown-path open was not ENOENT: $(cat "$E2E_ROOT/never-announced.err")"
  pass "unknown-path open fails fast, never hangs for an announcement"
  probe_mark unknown_path
  # The recovery identity must FAIL first: bounded EIO against the
  # dead route, so the later success proves revival rather than a
  # first attempt that never saw trouble. The failure must be FAST
  # (well under the 30s open deadline): a terminal generation
  # completes its waiters with the verdict instead of blocking, so
  # a fast EIO proves the identity went terminal — a deadline EIO
  # would mean the fetch never concluded. The loop allows the
  # verdict to still be forming (three strike runs); once formed,
  # every subsequent read fails fast deterministically.
  rc=0
  fast=0
  attempt=0
  while (( attempt < 3 )); do
    start=$(date +%s)
    timeout 60 cat "$MNTS/xmember-f/stale-2.txt" >/dev/null 2>"$E2E_ROOT/stale-2.err" || rc=$?
    elapsed=$(( $(date +%s) - start ))
    [[ "$rc" == 1 ]] || die "stale-2 read returned rc $rc, want EIO (1)"
    grep -q "Input/output error" "$E2E_ROOT/stale-2.err" \
      || die "stale-2 read was not EIO: $(cat "$E2E_ROOT/stale-2.err")"
    if (( elapsed < 15 )); then
      fast=1
      break
    fi
    attempt=$((attempt + 1))
  done
  [[ "$fast" == 1 ]] \
    || die "stale-2 read never failed fast: the identity never went terminal (all attempts ran to the deadline)"
  pass "second stale identity fails closed, bounded, and fast (terminal verdict, not deadline)"
  probe_mark stale2_verdict
  # Fetch-failure classes outside a debug-attached session
  # (peer-repair child 14): the probes above forced fetch attempts
  # against a gone peer, so a pass line must name peer absence or
  # transport failure non-zero — "peer gone" distinguished from
  # "budget exhausted" in the member's own log. The mount runs at
  # the debug level exported above for exactly this grep.
  tail -n +"$((probed_from + 1))" "$LOGDIR/mount-xmember-f.err" \
    | grep "sync pass published" \
    | grep -qE "missing=[1-9]|transport_errors=[1-9]" \
    || die "member log never named a fetch-failure class for the dead-route probes"
  pass "dead-route probes surface peer absence in the pass log"
  probe_mark failure_class
  touch "$E2E_ROOT/member-probed-done"
  # Bitrot with a live claim (quarantine leg, peer-repair child
  # 12): cold-2.txt is verified local on the member — the blocking
  # open above served its bytes — so corrupting its chunk under the
  # live name models disk bitrot against a held claim. The owner is
  # still stopped, so no refetch can heal yet: the read must fail
  # closed, serve nothing, and name the rejected representation in
  # the mount log for the loop's drain.
  cold_chunk=$(grep -ral "cold-bytes" "$d/objects" 2>/dev/null | head -n 1)
  [[ -n "$cold_chunk" ]] || die "member store holds no cold-bytes chunk to corrupt"
  [[ "$(grep -ral "cold-bytes" "$d/objects" 2>/dev/null | wc -l)" == 1 ]] \
    || die "cold-bytes is not unique in the member store"
  printf 'tampered!!\n' > "$cold_chunk" \
    || die "host-side chunk surgery failed"
  # The reads fail closed at the demand deadline (or on a formed
  # verdict), never fast on the stale view and never with bytes:
  # the first read reports the rejection — starting the backend's
  # repair window — and every read waits out the in-flight repair
  # instead of completing on the projection that still shows the
  # pre-repair state. With the owner stopped no refetch can land,
  # so each attempt must end bounded-EIO having served nothing.
  attempt=0
  while (( attempt < 3 )); do
    rc=0
    timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2-bitrot.got" 2>"$E2E_ROOT/cold-2-bitrot.err" || rc=$?
    [[ "$rc" == 1 ]] || die "bitrotted read returned rc $rc, want EIO (1)"
    grep -q "Input/output error" "$E2E_ROOT/cold-2-bitrot.err" \
      || die "bitrotted read was not EIO"
    [[ ! -s "$E2E_ROOT/cold-2-bitrot.got" ]] \
      || die "bitrotted read served bytes: unverified content reached the mount"
    attempt=$((attempt + 1))
  done
  grep -q "representation rejected" "$LOGDIR/mount-xmember-f.err" \
    || die "mount log never named the rejected representation for quarantine"
  # OD-12-1 A end to end: the bad representation is unlinked, not
  # merely unclaimed. (A failed discard would still heal below —
  # the refetch's insert heals the live name — so only the
  # absence proves removal.)
  [[ ! -e "$cold_chunk" ]] \
    || die "bitrotted chunk file still on disk after the quarantine drain"
  pass "bitrotted read fails closed, serves nothing, names the rejection"
  probe_mark bitrot
  # Rendezvous: the owner remounts only after this block is fully
  # done. Without it the returned owner would heal reads 2-3
  # mid-block (repair-on-demand working as designed) and the
  # fail-closed asserts above would race the recovery they precede.
  touch "$E2E_ROOT/member-bitrot-done"
  # The owner is back on a fresh endpoint with a new route (see
  # owner leg). Converge its head BEFORE authoring: the scratch and
  # the delete below must extend the post-restart lineage, and the
  # announcement carries the route the tree fetch needs.
  poll_until 120 test -f "$E2E_ROOT/owner-back" \
    || die "owner never came back after the dead-route probes"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'owner-back-1.txt'" \
    || die "member never listed the post-restart write"
  pass "member converges on the post-restart head over the new route"
  probe_mark owner_back
  # Repair-on-demand without remount: the same mount that failed
  # closed on the bitrotted chunk now serves verified bytes — the
  # loop discarded the bad representation, unclaimed it, and
  # refetched from the returned owner on this read's demand. No
  # remount, no restart: the mountpoint never went down between
  # the EIO above and this read.
  timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2-healed.got" \
    || die "post-owner read failed: quarantine never healed"
  [[ "$(cat "$E2E_ROOT/cold-2-healed.got")" == "cold-bytes" ]] \
    || die "healed read returned wrong bytes"
  pass "quarantined chunk heals from the returned owner without remount"
  probe_mark heal
  # Out-of-band loss with a live claim (scrub leg, peer-repair
  # child 13): cold-2.txt is verified local on the member again —
  # the heal above served its bytes — so deleting its chunk file
  # outright models post-install loss (a vanished file, never a
  # verification failure) against a held claim. The owner is back,
  # so unlike the bitrot block this read must heal instead of
  # failing: the first read names the lost representation for the
  # scrub drain, waits out the unclaim-and-refetch, and serves the
  # refetched bytes in the same read. No remount, no restart.
  cold_chunk=$(grep -ral "cold-bytes" "$d/objects" 2>/dev/null | head -n 1)
  [[ -n "$cold_chunk" ]] || die "member store holds no cold-bytes chunk to delete"
  [[ "$(grep -ral "cold-bytes" "$d/objects" 2>/dev/null | wc -l)" == 1 ]] \
    || die "cold-bytes is not unique in the member store after the quarantine heal"
  rm "$cold_chunk" \
    || die "host-side chunk deletion failed"
  timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2-relost.got" \
    || die "post-loss read failed: scrub never healed"
  [[ "$(cat "$E2E_ROOT/cold-2-relost.got")" == "cold-bytes" ]] \
    || die "healed-after-loss read returned wrong bytes"
  grep -q "unclaiming and re-demanding" "$LOGDIR/mount-xmember-f.err" \
    || die "mount log never named the lost representation for scrub"
  pass "lost chunk heals from the returned owner without remount"
  probe_mark reloss
  # Scratch write against the live route: creating a file forces
  # the current head's tree object to materialize (reads never
  # fetch tree objects, only manifests and chunks), and the delete
  # below needs that tree local. Completion is the signal —
  # success means the trees are local, so no timing guess.
  echo "scratch" > "$MNTS/xmember-f/scratch-del.txt"
  poll_until 120 converged "$MNTS/xmember-f/scratch-del.txt" "scratch" \
    || die "scratch write never became readable"
  pass "scratch write forces tree materialization over the live route"
  probe_mark scratch
  touch "$E2E_ROOT/member-scratch-done"
  # Delete of stale-1: the scratch write above authored a head
  # whose tree object is local by construction, so this delete
  # needs nothing from the network — same local-first authorship
  # the green suite proved, now deterministic instead of
  # timing-lucky. The owner converges it (see owner leg), so no
  # head fork. stale-2 stays for the recovery probe below.
  timeout 60 rm "$MNTS/xmember-f/stale-1.txt" \
    || die "member cannot author the delete"
  pass "member authors the delete with trees local"
  probe_mark delete
  touch "$E2E_ROOT/member-fetch-done"
  # Recovery without remount: the owner is back on a fresh endpoint
  # with a new route (see owner leg), and this mount never went
  # down. The stale-2 identity failed terminally against the dead
  # route (fast EIO pinned above); each bounded open below re-demands
  # it, so the reviving fetch runs as a new generation — the same
  # read succeeding here proves the verdict was never permanent.
  # The live route must produce a new fetch attempt and the
  # open must eventually succeed. Each attempt is a fresh
  # bounded open (30s): the loop below is the retry, while the
  # fetch continues across attempts. Ten attempts bound the worst
  # case near eleven minutes; the live route should land it in the
  # first few. (The post-restart head converged before the scratch
  # above, so no second converge is needed here.)
  # Localize the post-restart file too: phase 6 exports this drive
  # offline and fails closed on remote-only content, so the export
  # needs every head file local — and reads need chunks only, never
  # tree objects, so this stays a pure fetch-plane assertion.
  poll_until 180 converged "$MNTS/xmember-f/owner-back-1.txt" "owner-back" \
    || die "member never fetched the post-restart bytes"
  pass "post-restart bytes land over the new route"
  probe_mark post_restart
  local attempt=0
  while (( attempt < 10 )); do
    if timeout 60 cat "$MNTS/xmember-f/stale-2.txt" >"$E2E_ROOT/stale-2-recovered.got" 2>/dev/null \
      && [[ "$(cat "$E2E_ROOT/stale-2-recovered.got")" == "stale-2-bytes" ]]; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 5
  done
  [[ "$attempt" -lt 10 ]] \
    || die "stale identity never recovered without remount after $attempt bounded opens"
  pass "failed fetch recovers after re-announcement without remount"
  probe_mark "recovery(attempts=$((attempt + 1)))"
  # Stay up until the owner confirms convergence: shutting down
  # here would outrun the outbox drain and strand the scratch and
  # delete announcements this leg's owner polls wait for. Short
  # budget on purpose: in the normal case the owner acks while this
  # mount is still recovering, so this only ever costs minutes when
  # the owner is genuinely stuck.
  poll_until 120 test -f "$E2E_ROOT/owner-converged-done" \
    || die "owner never converged the scratch and delete"
  touch "$E2E_ROOT/member-recovered-done"
  probe_mark converged_wait
  stop_mount xmember-f TERM
  # Dedupe proof over the step-8 restart's redelivery, read after the
  # mount is down so no concurrent append can slip mid-read. Two
  # preconditions make the check real: the log is non-empty (an
  # empty log would pass trivially and means the member stopped
  # acking), and it grew past the phase-4 snapshot (the restart
  # redelivered, so "no duplicates" is observed, not vacuous).
  # Past the retention bound an evicted id may legitimately
  # re-append after redelivery (seen_store.rs:21-25), so the no-dup
  # half is a below-the-bound invariant; the bound itself is pinned
  # by unit tests at the 512 test bound.
  [[ -s "$d/mailbox.seen" ]] || die "member mailbox.seen empty: member stopped acking"
  [[ -f "$E2E_ROOT/seen-after-restart" ]] || die "phase-4 seen snapshot missing"
  [[ "$(wc -l < "$d/mailbox.seen")" -gt "$(cat "$E2E_ROOT/seen-after-restart")" ]] \
    || die "mailbox.seen did not grow across the restart: no redelivery observed"
  [[ -z "$(sort "$d/mailbox.seen" | uniq -d)" ]] \
    || die "mailbox.seen holds duplicate ids: redelivery double-appended"
  pass "redelivery grows the dedupe log without double-appending"
  # Growth-bound backstop (seen_store.rs:21-25): the durable file
  # never exceeds twice the 65,536 production retention bound,
  # regardless of lifetime history. Asserted in bytes, not lines: the
  # module's promise is a disk bound, and every record is exactly
  # MAX_RECORD_LEN (65) bytes, so 131072 * 65 fails closed on a
  # corrupt long line too. The suite generates ~100 acks, so this
  # pins the invariant in the hardened gate rather than exercising
  # compaction — that stays pinned by unit tests at the 512 test
  # bound. The literal below is a copy of MAX_SEEN_ENTRIES * 2;
  # update it if the production const moves.
  [[ "$(wc -c < "$d/mailbox.seen")" -le 8519680 ]] \
    || die "mailbox.seen exceeds the durable growth bound"
  pass "dedupe log stays within the durable growth bound"
  # Companion that can actually fail: every record is one 64-hex
  # id plus newline (MAX_RECORD_LEN is 65 including the newline), so
  # a longer line is a torn or corrupt record — and the byte ceiling
  # above assumes it. (Use > 64: a torn tail with no newline is
  # exactly 64 bytes, which is legitimate.)
  awk 'length($0) > 64 { exit 1 }' "$d/mailbox.seen" \
    || die "mailbox.seen holds an over-long record"
  pass "dedupe log holds only well-formed records"
  # The fetch surface through the real binary (peer-repair child
  # 14): the mount is down, so a headless `sync now` owns the
  # drive — no concurrent loop, no shared relay identity. Runs
  # after the dedupe proofs because a live run acks mail and would
  # move `mailbox.seen` under them. Exit status is intentionally
  # unasserted (a live run may still find transient work); the
  # shape asserts below hold on any completed run, quiet or not.
  set +e
  # No `timeout` wrapper: `with_creds` is a shell function and
  # `timeout` can only exec binaries, so wrapping it fails with
  # "No such file or directory" and an empty stdout. The run is
  # bounded internally by MAX_SYNC_NOW_PASSES.
  with_creds "$c" sync "$d" --relay "$relay" now \
    >"$E2E_ROOT/sync-now-member.out" 2>"$E2E_ROOT/sync-now-member.err"
  set -e
  grep -qE "\([0-9]+ unfulfilled\)" "$E2E_ROOT/sync-now-member.out" \
    || die "sync now stdout lost the unfulfilled total"
  grep -qE "^deadlines: [0-9]+ discarded under budget pressure$" "$E2E_ROOT/sync-now-member.out" \
    || die "sync now stdout lost the unconditional deadlines line"
  grep -qE "^terminal: [0-9]+ identities exhausted$" "$E2E_ROOT/sync-now-member.out" \
    || die "sync now stdout lost the terminal gauge"
  pass "sync now renders the fetch surface (total, deadlines, terminal)"
  probe_mark dedupe_syncnow
  check_no_content_ids "$E2E_ROOT/sync-now-member.out"
  check_no_leaks "$LOGDIR/mount-xmember-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$E2E_ROOT/sync-now-member.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$E2E_ROOT/sync-now-member.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  probe_mark tail_checks
}

# leg_conflict_owner <drive> <creds> <relay>: mount, drive the rename
# half of the StaleHandle pin (rename the victim after the member
# holds it open), then the partition half: concurrent same-file
# commit under tap-r down, conflict assertions after heal.
# The rename half runs pre-partition (it needs convergence); the
# conflict half runs post-partition-signal (shared-fs rendezvous,
# no relay needed). Observed on odin: partitioned same-path commits
# both succeed locally (single head each); after heal the two heads
# surface as name@N versions with SnapshotId byte-order numbering,
# a further write fails EIO (ConflictedHeads), reads keep serving.
leg_conflict_owner() {
  local d="$1" c="$2" relay="$3"
  step 10 "partition-conflict owner leg"
  # Debug for this mount only, same scoped pattern as the fetch
  # member leg: a silent victim-write failure here cascades into a
  # misleading member-side FAIL two polls later.
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  export E2E_RUST_LOG="wyrd_core=debug"
  start_mount xowner-c "$c" "$d" "$MNTS/xowner-c" --relay "$relay"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  conflict_assert_reachable "$relay"
  echo "victim" > "$MNTS/xowner-c/rename-victim.txt" \
    || die "owner victim write failed"
  poll_until 120 test -f "$E2E_ROOT/conflict-rename-member-ready" \
    || die "member never opened the rename victim"
  mv "$MNTS/xowner-c/rename-victim.txt" "$MNTS/xowner-c/renamed.txt" \
    || die "owner rename failed"
  touch "$E2E_ROOT/conflict-rename-owner-done"
  poll_until 120 test -f "$E2E_ROOT/conflict-rename-member-done" \
    || die "member never finished the stale-handle probe"
  pass "rename committed while the member holds the victim open"
  poll_until 180 test -f "$E2E_ROOT/conflict-partitioned" \
    || die "host never partitioned the relay"
  conflict_assert_partitioned "$relay"
  echo "owner-conflict-1" > "$MNTS/xowner-c/conflict-c.txt"
  touch "$E2E_ROOT/conflict-owner-written"
  poll_until 180 test -f "$E2E_ROOT/conflict-healed" \
    || die "host never healed the relay"
  conflict_assert_converged "$MNTS/xowner-c" owner
  touch "$E2E_ROOT/conflict-owner-done"
  poll_until 240 test -f "$E2E_ROOT/conflict-member-done" \
    || die "member never finished the conflict assertions"
  stop_mount xowner-c INT
  check_no_leaks "$LOGDIR/mount-xowner-c.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_conflict_member <drive> <creds> <relay>: mount, hold the victim
# open across the owner's rename (stale-handle EIO pin), then commit
# the same conflict path from this side of the partition and assert
# the merged conflict identically to the owner.
# Staleness is relative to the converged head: the held fd is opened
# O_RDWR (spelled `exec 3<>`, which is O_RDWR|O_CREAT — the open
# itself commits nothing only because the preceding `converged`
# proved the victim exists, so O_CREAT is a no-op here) and stays
# pinned to the pre-rename generation — reads on it still serve the
# captured identity until release — so the member must converge the
# rename FIRST (renamed.txt reads the victim bytes) and only then
# write via the held fd, which addresses a superseded parent and
# must fail EIO. Either write-time or close-time EIO counts
# (buffered writes may fail at flush, not at write): both are
# asserted, and success at both is a lost-update violation.
leg_conflict_member() {
  local d="$1" c="$2" relay="$3"
  local rc=0 crc=0
  step 10 "partition-conflict member leg"
  # Debug for this mount only, same scoped pattern as the fetch
  # member leg: shows what (if anything) converges while the
  # victim poll runs.
  local old_e2e_log_m="${E2E_RUST_LOG-__unset}"
  export E2E_RUST_LOG="wyrd_core=debug"
  start_mount xmember-c "$c" "$d" "$MNTS/xmember-c" --relay "$relay"
  if [[ "$old_e2e_log_m" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log_m"; fi
  conflict_assert_reachable "$relay"
  poll_until 120 converged "$MNTS/xmember-c/rename-victim.txt" "victim" \
    || die "member never converged the rename victim"
  exec 3<>"$MNTS/xmember-c/rename-victim.txt" \
    || die "member cannot hold the victim handle open"
  touch "$E2E_ROOT/conflict-rename-member-ready"
  poll_until 120 test -f "$E2E_ROOT/conflict-rename-owner-done" \
    || die "owner never committed the rename"
  poll_until 180 converged "$MNTS/xmember-c/renamed.txt" "victim" \
    || die "member never converged the rename"
  echo "stale-write" >&3 2>"$E2E_ROOT/rename-stale.err" || rc=$?
  # Close may be where the EIO surfaces (buffered write accepted,
  # flush refused at commit) — but bash prints a close-flush error
  # without propagating it to $?, so the error TEXT is the gate
  # here, not the close status. A fully silent success at both
  # points is the lost update this leg exists to forbid.
  exec 3>&- 2>>"$E2E_ROOT/rename-stale.err" || crc=$?
  grep -q "Input/output error" "$E2E_ROOT/rename-stale.err" \
    || die "stale-handle write showed no EIO (rc $rc/$crc)"
  pass "rename breaks a held writable handle across hosts (EIO)"
  touch "$E2E_ROOT/conflict-rename-member-done"
  poll_until 180 test -f "$E2E_ROOT/conflict-partitioned" \
    || die "host never partitioned the relay"
  conflict_assert_partitioned "$relay"
  echo "member-conflict-1" > "$MNTS/xmember-c/conflict-c.txt"
  touch "$E2E_ROOT/conflict-member-written"
  poll_until 180 test -f "$E2E_ROOT/conflict-healed" \
    || die "host never healed the relay"
  conflict_assert_converged "$MNTS/xmember-c" member
  touch "$E2E_ROOT/conflict-member-done"
  poll_until 240 test -f "$E2E_ROOT/conflict-owner-done" \
    || die "owner never finished the conflict assertions"
  stop_mount xmember-c TERM
  check_no_leaks "$LOGDIR/mount-xmember-c.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# conflict_assert_partitioned <relay>: guest-side proof the partition
# took — the relay TCP endpoint must be unreachable. Without this a
# failed tap-down would let both writes converge onto one head and
# the leg would die much later at the @1 read with a misleading
# message.
# conflict_relay_hostport <relay>: split ws(s)://host:port/path into
# "$host $port" for /dev/tcp probes.
conflict_relay_hostport() {
  local relay="$1" hostport host port
  hostport="${relay#ws://}"
  hostport="${hostport#wss://}"
  host="${hostport%%:*}"
  port="${hostport##*:}"
  port="${port%%/*}"
  printf '%s %s' "$host" "$port"
}

# conflict_assert_reachable <relay>: positive control for the
# partition probe below — the same /dev/tcp connect must SUCCEED
# while the relay is up, so the later must-fail probe is a real
# two-sided assertion rather than a vacuously passing one (bad
# parse, missing /dev/tcp, or a miswired relay would all fail
# here, loudly, pre-partition).
conflict_assert_reachable() {
  local host port
  read -r host port <<< "$(conflict_relay_hostport "$1")"
  if ! timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
    die "relay $host:$port unreachable pre-partition"
  fi
  pass "relay reachable pre-partition"
}

conflict_assert_partitioned() {
  local host port
  read -r host port <<< "$(conflict_relay_hostport "$1")"
  if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
    die "relay $host:$port reachable while partitioned"
  fi
  pass "partition verified guest-side"
}

# conflict_assert_converged <mnt> <side>: shared post-heal
# assertions for both conflict legs. Same-path commits from both
# sides of the partition surface as name@N versions (deterministic
# SnapshotId byte-order numbering — order pinned nowhere, so the
# version set is compared, identically on both sides), the
# conflicted path presents as a directory, a further write fails
# EIO while reads keep serving, and both versions are fetched
# local: phase 6 exports offline and fails closed on remote-only
# content. <side> (owner/member) namespaces the probe stderr:
# LOGDIR is shared across guests, and one O_TRUNC file would let
# each side's text gate pass on the sibling's attempt.
conflict_assert_converged() {
  local m="$1" side="$2"
  local wrc=0
  # Envelope note: poll_until counts 0.2s sleeps, not wall clock, so
  # with 60s-bounded cats inside the real bound is budget x command
  # time, not 300 seconds. The happy path converges in seconds; the
  # wide budget is pathology cover for a genuinely regressing
  # conflict phase, carried by the raised whole-run cap.
  poll_until 300 bash -c "timeout 60 cat '$m/conflict-c.txt@1' >/dev/null 2>&1 && timeout 60 cat '$m/conflict-c.txt@2' >/dev/null 2>&1" \
    || die "conflict versions never became readable on $m"
  pass "both conflict versions readable"
  [[ -d "$m/conflict-c.txt" ]] \
    || die "conflicted path does not present as a directory on $m"
  pass "conflicted path presents as a directory"
  if ! listing="$(ls "$m")"; then
    die "readdir failed on $m: the mount is unhealthy"
  fi
  [[ "$listing" != *conflict-c.txt@* ]] \
    || die "readdir lists a version-qualified name on $m"
  pass "readdir omits version-qualified names"
  # The re-read must be loud and settle-tolerant. A failing cat
  # inside a bare command substitution killed this leg silently under
  # set -e twice on odin (leg 10, post-heal) with no die line; and a
  # rerun at the same commit went green, with the red runs converging
  # in ~6s post-heal against ~17s green — the single-shot re-read
  # fires milliseconds after the poll while post-heal convergence is
  # still in flight. So each version is captured separately with
  # errexit off (naming its side, exit code, and kernel error text),
  # and the capture plus set comparison retries bounded like the
  # poll. Content mismatches retry too: the set is order-free and
  # heads land incrementally post-heal, so a transient mismatch is
  # settle, not failure — a version that never serves or never
  # matches still dies loudly with the trajectory on the die line.
  # The per-read cats carry the same `timeout 60` as the poll above
  # so the retry budget stays a real wall-clock bound. LOGDIR is
  # shared across guests, so the per-cat stderr files are namespaced
  # by side like the EIO-write probe's below.
  local got want got1 got2 rc1=0 rc2=0 settled=0 attempt=0 last=""
  local errexit=true
  case $- in *e*) ;; *) errexit=false;; esac
  set +e
  while (( attempt < 120 )); do
    attempt=$(( attempt + 1 ))
    got1="$(timeout 60 cat "$m/conflict-c.txt@1" 2>"$LOGDIR/conflict-reread-$side-1.stderr")"; rc1=$?
    got2="$(timeout 60 cat "$m/conflict-c.txt@2" 2>"$LOGDIR/conflict-reread-$side-2.stderr")"; rc2=$?
    if [[ $rc1 -eq 0 && $rc2 -eq 0 ]]; then
      got="$(printf '%s\n' "$got1" "$got2" | sort)"
      want="$(printf '%s\n' "owner-conflict-1" "member-conflict-1" | sort)"
      if [[ "$got" == "$want" ]]; then
        settled=1
        break
      fi
      last="content set mismatch [$got]"
    else
      # Unfailable by construction: the redirects above create both
      # files before the reads run, and `|| true` holds even if the
      # share itself misbehaves — diagnostics must never reintroduce
      # the silent death this block removes.
      last="reads"
      if [[ $rc1 -ne 0 ]]; then
        last="$last @1(rc $rc1: $(cat "$LOGDIR/conflict-reread-$side-1.stderr" 2>/dev/null || true))"
      fi
      if [[ $rc2 -ne 0 ]]; then
        last="$last @2(rc $rc2: $(cat "$LOGDIR/conflict-reread-$side-2.stderr" 2>/dev/null || true))"
      fi
    fi
    sleep 0.5
  done
  if $errexit; then set -e; fi
  [[ $settled -eq 1 ]] \
    || die "conflict versions never settled on $m after $attempt attempts (last: $last)"
  [[ $attempt -gt 1 ]] && echo "  note: conflict re-read settled after $attempt attempts on $m (last: $last)"
  pass "conflict versions read identically (owner + member takes)"
  if test -e "$m/conflict-c.txt@3"; then
    die "third conflict version on $m: more than two heads"
  fi
  pass "no third head"
  # Write refusal: the attempt runs in a child (a FUSE-EIO-at-open
  # on the main shell's own redirection killed the leg silently
  # even behind `||` under set -e). The text is checked first;
  # the exit code then pins the observed behavior — create on a
  # conflicted drive fails at open (rc 1) on odin — rather than
  # merely echoing the text gate.
  bash -c "echo after > '$m/post-conflict.txt'" 2>"$LOGDIR/conflict-eio-write-$side.stderr" || wrc=$?
  grep -q "Input/output error" "$LOGDIR/conflict-eio-write-$side.stderr" \
    || die "conflicted-drive write was not EIO on $m (rc $wrc)"
  [[ "$wrc" == 1 ]] \
    || die "conflicted-drive write exited $wrc, want 1, on $m"
  # Post-write serving probe with the same settle tolerance as the
  # re-read above: a transient read failure right after the refused
  # write retries bounded instead of misreporting "stopped serving
  # reads" for a drive that resumes serving.
  local serving="" src=0 sread=0 sattempt=0
  set +e
  while (( sattempt < 60 )); do
    sattempt=$(( sattempt + 1 ))
    serving="$(timeout 60 cat "$m/conflict-c.txt@1" 2>/dev/null)"; src=$?
    if [[ $src -eq 0 && "$serving" != "" ]]; then
      sread=1
      break
    fi
    sleep 0.5
  done
  if $errexit; then set -e; fi
  [[ $sread -eq 1 ]] \
    || die "conflicted drive stopped serving reads on $m (rc $src after $sattempt attempts)"
  pass "conflicted drive fails writes EIO and still serves reads"
}

# leg_headless_setup <drive> <creds>: mount the fresh single-author
# drive, write the target files, stop. Phase 12 intentionally uses
# a fresh single-author dataset: v0 serving is author-bound and
# does not replicate serving authority for historical snapshots,
# so a deep multi-author closure is only convergent when every
# author has a live route (replication serving is deferred to
# v0.7). Do not "improve" this leg by reusing an existing deep
# drive: every announcement C needs must carry A's live endpoint,
# which holds exactly when A is the sole author.
leg_headless_setup() {
  local d="$1" c="$2"
  step 12 "headless dataset setup"
  start_mount xhfresh "$c" "$d" "$MNTS/xhfresh"
  echo "serve-target-1" > "$MNTS/xhfresh/target-1.txt"
  echo "serve-target-2" > "$MNTS/xhfresh/target-2.txt"
  stop_mount xhfresh INT
  check_no_leaks "$LOGDIR/mount-xhfresh.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  pass "single-author dataset written and unmounted"
  touch "$E2E_ROOT/headless-setup-done"
}

# leg_headless_serve <drive> <creds> <relay>: the serving half of
# the two-headless-peers exchange (issue 22a: the vault process;
# issue 22b: the crash-restart gate). Runs `wyrd vault` in the
# background, waits for the ready line (first routed pass complete,
# endpoint serving), then drives the kill/restart/TERM sequence the
# fetch legs rendezvous on:
#   serve#1 → C fetches → KILL (mid-flight) → serve#2 (mirror
#   rebuilt from the vault) → E fetches against the replacement →
# TERM → host admits D → serve#3 → D fetches pre-kill content →
# TERM, clean exit 0, then outwait the freshness threshold for the
# STALE pin.
# Issue 22c probes sit at the same joints: status against running
# serve#1 (fresh posture without opening the store), status after
# fetch-c (last-pass verdict present), status against serve#2 (new
# instance, no inherited readiness), status after serve#2's TERM
# (durable state back, last posture retained as last-recorded),
# status against serve#3 (its instance), and status 200s after
# serve#3's TERM (STALE under its own instance).
# E is admitted before the leg (alongside C) so its obligations are
# fresh for serve#2's route: E proves the replacement re-announced
# (E reconciles over the new route) AND serves content (pre-kill
# bodies flow from the post-KILL process) — each peer-observed, not
# read off the ready line. D is admitted between serve#2 and serve#3
# on purpose: the re-announcement path reseals pending obligations
# with the live route but never resurrects discharged ones, so D's
# obligations must be fresh for serve#3's route. C proves the
# positive case, E proves the crash-restart case, D proves
# previously announced representations still serve after a kill -9
# and mirror rebuild.
leg_headless_serve() {
  local d="$1" c="$2" relay="$3"
  step 12 "headless serving leg"
  rm -f "$E2E_ROOT/headless-serve-ready" "$E2E_ROOT/headless-fetch-c-done" \
    "$E2E_ROOT/headless-serve2-ready" "$E2E_ROOT/headless-fetch-e-done" \
    "$E2E_ROOT/headless-serve-stopped" "$E2E_ROOT/headless-d-invited" \
    "$E2E_ROOT/headless-serve3-ready" "$E2E_ROOT/headless-fetch-d-done"
  mkdir -p "$PIDDIR"
  # serve#1: the vault announces with its serve route, then keeps
  # syncing. The ready line proves the first routed pass completed,
  # so a fetcher starting now races nothing.
  with_creds "$c" vault "$d" --relay "$relay" \
    >"$LOGDIR/headless-serve-1.out" 2>"$LOGDIR/headless-serve-1.err" &
  echo $! > "$PIDDIR/headless-serve.pid"
  poll_until 300 grep -q "vault ready: serving " "$LOGDIR/headless-serve-1.err" \
    || die "serve#1 never reported ready (see headless-serve-1.err)"
  grep -q "serving over iroh" "$LOGDIR/headless-serve-1.err" \
    || die "serve#1 never bound its endpoint"
  pass "serve#1 reports ready with its route and keeps syncing"
  touch "$E2E_ROOT/headless-serve-ready"
  # 22c: status against the running vault reads the sidecar without
  # opening the store — exit 0, fresh posture, ready named, durable
  # unavailable (never guessed). No last-pass verdict yet: posture
  # publishes on loop events, and only the ready event has fired.
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-1.out" \
    || die "vault status failed against running serve#1 (see headless-status-1.out)"
  grep -q "^process: fresh posture" "$LOGDIR/headless-status-1.out" \
    || die "status missed fresh posture on serve#1"
  grep -q "^process: ready: [0-9][0-9]*$" "$LOGDIR/headless-status-1.out" \
    || die "status missed serve#1's ready stamp"
  grep -q "^process: liveness: unverified" "$LOGDIR/headless-status-1.out" \
    || die "status claimed liveness it cannot see"
  grep -q "^durable: unavailable (drive held by a running process" "$LOGDIR/headless-status-1.out" \
    || die "status guessed durable state under the lock"
  grep "^process: instance: " "$LOGDIR/headless-status-1.out" | head -n 1 > "$E2E_ROOT/headless-serve1-instance"
  pass "status reads fresh ready posture off the running vault without opening the store"
  # C fetches the whole drive headless; only then is the kill
  # mid-flight (residency, not startup).
  poll_until 300 test -f "$E2E_ROOT/headless-fetch-c-done" \
    || die "fetch-c never finished against serve#1"
  pass "fetch-c converged against the serving headless peer"
  # 22c: the verdict needs a published posture event (60s cadence).
  # Ready proves the first pass completed, but only a Posture event
  # carries its counters and verdict into the sidecar — the sidecar
  # mirrors the log stream, and the log stream has no per-pass
  # posture line before the first interval. So wait for the first
  # posture line (poll below), then the verdict is populated under
  # the same instance; "none observed" after that wait would mean
  # the loop wedged without publishing.
  poll_until 300 grep -q "vault posture:" "$LOGDIR/headless-serve-1.err" \
    || die "serve#1 never published a posture event (see headless-serve-1.err)"
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-2.out" \
    || die "vault status failed against running serve#1 late (see headless-status-2.out)"
  grep -Eq "^process: last pass: (ok at|failed \()" "$LOGDIR/headless-status-2.out" \
    || die "status missed serve#1's last-pass verdict"
  diff "$E2E_ROOT/headless-serve1-instance" <(grep "^process: instance: " "$LOGDIR/headless-status-2.out" | head -n 1) \
    || die "serve#1's instance changed without a restart"
  pass "status names the last-pass verdict on the long-running vault"
  local pid
  pid="$(cat "$PIDDIR/headless-serve.pid")"
  kill -KILL "$pid" 2>/dev/null || die "serve#1 pid already gone before KILL"
  set +e; wait "$pid"; local kstatus=$?; set -e
  [[ "$kstatus" == "137" ]] || die "serve#1 KILL exit $kstatus, want 137"
  kill -0 "$pid" 2>/dev/null && die "serve#1 pid survived KILL"
  rm -f "$PIDDIR/headless-serve.pid"
  pass "serve#1 dies on KILL"
  # serve#2: restart the vault over the same drive — the mirror
  # rebuilds from the vault by replay, never by re-deriving bytes.
  # E's obligation is still pending (admitted up front, never
  # discharged: C discharged, D not yet admitted), so serve#2
  # re-announces it with the new route; the ready line proves the
  # endpoint is back up and re-announced. Debug on: the send
  # recipients below are the 22b proof (re-announcement to E under
  # the new route), and info level hides them.
  local old_serve_log="${RUST_LOG-__unset}"
  export RUST_LOG="wyrd_core=debug"
  with_creds "$c" vault "$d" --relay "$relay" \
    >"$LOGDIR/headless-serve-2.out" 2>"$LOGDIR/headless-serve-2.err" &
  echo $! > "$PIDDIR/headless-serve.pid"
  if [[ "$old_serve_log" == "__unset" ]]; then unset RUST_LOG; else export RUST_LOG="$old_serve_log"; fi
  poll_until 300 grep -q "vault ready: serving " "$LOGDIR/headless-serve-2.err" \
    || die "serve#2 never reported ready after KILL (see headless-serve-2.err)"
  pass "serve#2 reports ready after KILL: the mirror rebuilt from the vault"
  touch "$E2E_ROOT/headless-serve2-ready"
  # 22c: the replacement publishes under a new instance from its
  # first write — status must name that instance with its own
  # readiness, never the dead instance's file as its own.
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-3.out" \
    || die "vault status failed against serve#2 (see headless-status-3.out)"
  grep -q "^process: fresh posture" "$LOGDIR/headless-status-3.out" \
    || die "status missed fresh posture on serve#2"
  grep -q "^process: ready: [0-9][0-9]*$" "$LOGDIR/headless-status-3.out" \
    || die "status missed serve#2's ready stamp"
  grep "^process: instance: " "$LOGDIR/headless-status-3.out" | head -n 1 > "$E2E_ROOT/headless-serve2-instance"
  if diff -q "$E2E_ROOT/headless-serve1-instance" "$E2E_ROOT/headless-serve2-instance" >/dev/null; then
    die "serve#2 inherited serve#1's instance"
  fi
  pass "status names the replacement instance with its own readiness"
  # E fetches the whole drive against the replacement: E was
  # admitted before the leg so its obligations are fresh for
  # serve#2's route, and E starts empty so every object it pulls is
  # bulk transfer from the post-KILL process. Re-announcement and
  # content service each peer-observed — the ready line alone is
  # never the proof. Only then is serve#2 stopped.
  poll_until 300 test -f "$E2E_ROOT/headless-fetch-e-done" \
    || die "fetch-e never finished against serve#2"
  pass "fetch-e converged against the KILL replacement: re-announced and serving"
  # TERM while parked: the ordered teardown (mailbox, bulk, serving
  # under the transport bound) must exit 0, proving the shutdown
  # half of the residency contract.
  pid="$(cat "$PIDDIR/headless-serve.pid")"
  kill -TERM "$pid"
  local i status="timeout"
  for ((i = 0; i < 60 * 5; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e; wait "$pid"; status=$?; set -e
      break
    fi
    sleep 0.2
  done
  [[ "$status" == "0" ]] || die "serve#2 TERM shutdown exit $status, want clean 0"
  rm -f "$PIDDIR/headless-serve.pid"
  pass "serve#2 shuts down clean on TERM"
  touch "$E2E_ROOT/headless-serve-stopped"
  # 22c: drive free — durable state renders again beside serve#2's
  # retained last posture (last-recorded, explicitly not live).
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-4.out" \
    || die "vault status failed on the stopped drive (see headless-status-4.out)"
  grep -q "^durable: stopped drive" "$LOGDIR/headless-status-4.out" \
    || die "durable state missing on the stopped drive"
  grep -q "^process: retained posture" "$LOGDIR/headless-status-4.out" \
    || die "serve#2's fresh posture not reclassified as retained on the free drive"
  diff "$E2E_ROOT/headless-serve2-instance" <(grep "^process: instance: " "$LOGDIR/headless-status-4.out" | head -n 1) \
    || die "serve#2's last posture did not survive its shutdown"
  pass "status renders durable state beside the retained last posture"
  # The host admits D while the drive is free; serve#3 announces
  # D's fresh obligations with its own route.
  poll_until 300 test -f "$E2E_ROOT/headless-d-invited" \
    || die "host never admitted D"
  with_creds "$c" vault "$d" --relay "$relay" \
    >"$LOGDIR/headless-serve-3.out" 2>"$LOGDIR/headless-serve-3.err" &
  echo $! > "$PIDDIR/headless-serve.pid"
  poll_until 300 grep -q "vault ready: serving " "$LOGDIR/headless-serve-3.err" \
    || die "serve#3 never reported ready (see headless-serve-3.err)"
  pass "serve#3 reports ready with D's obligations announced"
  touch "$E2E_ROOT/headless-serve3-ready"
  # 22c: serve#3's own instance, for the stale-transition pin below.
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-5.out" \
    || die "vault status failed against serve#3 (see headless-status-5.out)"
  grep -q "^process: fresh posture" "$LOGDIR/headless-status-5.out" \
    || die "status missed fresh posture on serve#3"
  grep "^process: instance: " "$LOGDIR/headless-status-5.out" | head -n 1 > "$E2E_ROOT/headless-serve3-instance"
  pass "status names serve#3's instance while it runs"
  # D fetches content announced before the kill, served after it:
  # the vault-persisted representations outlive the endpoint.
  poll_until 300 test -f "$E2E_ROOT/headless-fetch-d-done" \
    || die "fetch-d never finished against serve#3"
  pass "fetch-d converged on pre-kill content after the restart"
  pid="$(cat "$PIDDIR/headless-serve.pid")"
  kill -TERM "$pid"
  status="timeout"
  for ((i = 0; i < 60 * 5; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e; wait "$pid"; status=$?; set -e
      break
    fi
    sleep 0.2
  done
  [[ "$status" == "0" ]] || die "serve#3 TERM shutdown exit $status, want clean 0"
  rm -f "$PIDDIR/headless-serve.pid"
  pass "serve#3 shuts down clean on TERM"
  # 22c: the fresh-to-stale transition for real — outwait the 180s
  # threshold (slow on purpose: the threshold is the contract, and
  # forging the clock would test nothing). The last publish predates
  # the TERM (teardown runs no passes), so 200s of quiet guarantees
  # an age past the threshold, and serve#3's last posture must read
  # STALE under its own instance.
  sleep 200 || die "sleep past the freshness threshold failed"
  with_creds "$c" vault "$d" status >"$LOGDIR/headless-status-6.out" \
    || die "vault status failed long after serve#3's TERM (see headless-status-6.out)"
  grep -q "^process: STALE posture" "$LOGDIR/headless-status-6.out" \
    || die "posture still fresh past the 180s threshold"
  diff "$E2E_ROOT/headless-serve3-instance" <(grep "^process: instance: " "$LOGDIR/headless-status-6.out" | head -n 1) \
    || die "stale posture lost serve#3's instance"
  pass "posture goes STALE past the threshold under its own instance"
  check_no_leaks "$LOGDIR/headless-serve-1.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-serve-2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-serve-3.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  # The status surface carries serving ids and timestamps only, but
  # it runs against live credentials — same leak bar as the logs.
  check_no_leaks "$LOGDIR/headless-status-1.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-status-2.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-status-3.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-status-4.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-status-5.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-status-6.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_headless_fetch <drive> <creds> <relay> <tag> <ready-file> <done-file>:
# the fetching half: an ordinary headless `sync now` (never --serve)
# against a parked serving peer, then a mount read proves the bytes.
# The device starts empty, so a nonzero object count is bulk transfer
# from the serving peer — the advertised address is the one that
# answers, proved by dialability rather than asserted from logs.
# File content is deliberately NOT asserted via headless export:
# headless reconciliation leaves file chunks `RemoteOnly` by policy
# (structural closure only — trees, manifests, bodies), and v0
# promises no headless materialization. The byte-exact proof comes
# from mounting the fetcher and reading through the projection:
# the read faults the remote-only chunks in over the serving peer's
# announced route, which is the feature under review end to end
# (serve -> route -> fault-in -> verify). This runs while the serve
# side is still parked, before the done-file releases it for KILL.
leg_headless_fetch() {
  local d="$1" c="$2" relay="$3" tag="$4" ready="$5" done="$6"
  step 12 "headless fetch leg ($tag)"
  poll_until 300 test -f "$E2E_ROOT/$ready" \
    || die "serve side never parked for $tag"
  # Debug on: intake verdicts (duplicate vs route-update commit)
  # and fetch dials below say whether a redelivered route was
  # applied or the peer stayed pinned to the dead one — info
  # level hides both. Both crate targets: wyrd_core carries the
  # pass reports, wyrd_sync carries intake verdicts, route
  # publication, bulk dials, and backoff skips. (An EnvFilter with
  # only wyrd_core=debug silences wyrd_sync entirely — that is why
  # the previous instrumented run showed pass reports but no
  # verdicts.)
  local old_fetch_log="${RUST_LOG-__unset}"
  export RUST_LOG="wyrd_core=debug,wyrd_sync=debug"
  with_creds "$c" sync "$d" --relay "$relay" now \
    >"$LOGDIR/headless-fetch-$tag.out" 2>"$LOGDIR/headless-fetch-$tag.err" \
    || die "headless fetch ($tag) exited non-zero"
  if [[ "$old_fetch_log" == "__unset" ]]; then unset RUST_LOG; else export RUST_LOG="$old_fetch_log"; fi
  grep -qE "fetch [0-9]+ manifests, [0-9]+ bodies, [1-9][0-9]* objects" "$LOGDIR/headless-fetch-$tag.out" \
    || die "headless fetch ($tag) fetched no objects (see headless-fetch-$tag.out)"
  pass "headless fetch ($tag) pulls objects over the serve route"
  start_mount "xheadless-$tag" "$c" "$d" "$MNTS/xheadless-$tag" --relay "$relay"
  [[ "$(cat "$MNTS/xheadless-$tag/target-1.txt")" == "serve-target-1" ]] \
    || die "headless mount ($tag) lost target-1.txt"
  [[ "$(cat "$MNTS/xheadless-$tag/target-2.txt")" == "serve-target-2" ]] \
    || die "headless mount ($tag) lost target-2.txt"
  pass "headless mount ($tag) faults the served bytes in over the serve route"
  stop_mount "xheadless-$tag" INT
  touch "$E2E_ROOT/$done"
  check_no_content_ids "$LOGDIR/headless-fetch-$tag.out"
  check_no_leaks "$LOGDIR/headless-fetch-$tag.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/headless-fetch-$tag.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-xheadless-$tag.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_crash_owner <drive> <creds> <relay>: mount, converge an anchor
# write with the witness, then take 40 acknowledged burst writes and
# SIGKILL the mount's own process mid-stream — no graceful shutdown,
# no reopen before the kill. Remount fresh and prove the drive
# reopened clean: the anchor survives byte-identical, every burst
# file present is byte-complete (never torn), and a post-crash write
# converges to the witness.
# Fence record (OD-06-A): the kill lands after the 40th burst write
# is acknowledged (read back through the mount) and before any
# reopen or export can report the commit — the rename/CURRENT
# window (AfterRenameCommit / AfterFsyncCommitDir /
# AfterRenameCurrent). The fence cannot name the exact stage; the
# leg pins the crash-model window, not the stage.
# Bounded-failure assertions: anchor read bounded (120s), post-crash
# convergence bounded (300s member-side via the witness done-file).
# Wall-clock envelope: typical 3-5 min observed green; dominant
# budget products are the burst loop (40 x up to 2 x 46s ~= 61 min)
# and the fixed rendezvous waits (~20 min). Simultaneous exhaustion
# of all budgets is pathology, covered by the whole-run cap — not
# by this envelope.
leg_crash_owner() {
  local d="$1" c="$2" relay="$3"
  step 13 "crash-injection owner leg"
  local PROBE_STEP=13
  start_mount xcrash-o "$c" "$d" "$MNTS/xcrash-o" --relay "$relay"
  # Converge the member's readiness signal first: this fetch settles
  # the sync engine (the closure gate blocks mutations until the
  # fetch completes). Without it the anchor write ETIMEDOUTs —
  # retries alone never drain the gate. Then the anchor write itself
  # gets bounded retries as insurance against a straggler pass.
  poll_until 180 converged "$MNTS/xcrash-o/member-ready.txt" "member-ready" \
    || die "member never published readiness"
  probe_mark ready_converged
  local attempt=0 anchored=0
  while (( attempt < 6 )); do
    attempt=$((attempt + 1))
    local _awrc=1 _agot=""
    timeout -s KILL 35 bash -c "echo 'anchor-v1' > '$MNTS/xcrash-o/anchor.txt'" 2>/dev/null && _awrc=0
    if ((_awrc == 0)); then
      _agot="$(timeout 10 cat "$MNTS/xcrash-o/anchor.txt" 2>/dev/null)"
    fi
    step 13 "  anchor attempt $attempt: write_rc=$_awrc got='${_agot:0:20}'"
    if ((_awrc == 0)) && [[ "$_agot" == "anchor-v1" ]]; then
      anchored=1
      break
    fi
    sleep 2
  done
  [[ "$anchored" == 1 ]] \
    || die "anchor write failed in $attempt attempts (closure never drained)"
  poll_until 120 test -f "$E2E_ROOT/crash-o-steady-ready" \
    || die "witness never converged the anchor write"
  probe_mark "anchor(attempts=$attempt)"
  pass "anchor converged before the burst"
  # Each burst write gets bounded retries: after the anchor the sync
  # engine may still be publishing, and a bare echo to the FUSE mount
  # hangs indefinitely when the mutation queue is blocked. timeout
  # 35 covers the 30s max_mutation_wait; 2 attempts per write, 40
  # writes: worst product ~61 min, observed full loops ~200s with
  # every write landing first try.
  local i=1 bw_attempt bw_ok
  while (( i <= 40 )); do
    bw_attempt=0 bw_ok=0
    while (( bw_attempt < 2 )); do
      bw_attempt=$((bw_attempt + 1))
      # SIGKILL not SIGTERM: a FUSE write stuck in D state ignores
      # SIGTERM and timeout hangs forever waiting for the process.
      # The read-back gets its own timeout for the same reason.
      local _wrc=1 _got=""
      timeout -s KILL 35 bash -c "echo 'burst-$i' > '$MNTS/xcrash-o/burst-$i.txt'" 2>/dev/null && _wrc=0
      if ((_wrc == 0)); then
        _got="$(timeout 10 cat "$MNTS/xcrash-o/burst-$i.txt" 2>/dev/null)"
      fi
      step 13 "  burst[$i] attempt $bw_attempt: write_rc=$_wrc got='${_got:0:20}'"
      if ((_wrc == 0)) && [[ "$_got" == "burst-$i" ]]; then
        bw_ok=1
        break
      fi
      sleep 1
    done
    [[ "$bw_ok" == 1 ]] \
      || die "burst write $i never acknowledged after $bw_attempt attempts"
    i=$((i + 1))
  done
  pass "40 burst writes acknowledged (fence: post-ack, pre-reopen — the rename/CURRENT window)"
  probe_mark burst_done
  local pid kstatus=0
  pid="$(cat "$PIDDIR/mount-xcrash-o.pid")"
  kill -KILL "$pid" 2>/dev/null || die "owner mount pid already gone before KILL"
  set +e; wait "$pid"; kstatus=$?; set -e
  [[ "$kstatus" == "137" ]] || die "owner KILL exit $kstatus, want 137"
  kill -0 "$pid" 2>/dev/null && die "owner mount pid survived KILL"
  rm -f "$PIDDIR/mount-xcrash-o.pid"
  fusermount3 -uz "$MNTS/xcrash-o" 2>/dev/null || true
  probe_mark killed
  pass "owner mount died on KILL"
  start_mount xcrash-o2 "$c" "$d" "$MNTS/xcrash-o2" --relay "$relay"
  [[ "$(timeout 120 cat "$MNTS/xcrash-o2/anchor.txt")" == "anchor-v1" ]] \
    || die "anchor lost across the KILL"
  pass "anchor survives the KILL byte-identical"
  # Fail-closed burst inventory: every burst file the reopen shows
  # must carry its full acknowledged bytes — a torn survivor is the
  # partial-accept this leg exists to forbid. Absent is fine (never
  # committed); partial is not.
  local f torn=0 n=0 i got
  for (( i = 1; i <= 40; i++ )); do
    f="$MNTS/xcrash-o2/burst-$i.txt"
    [[ -e "$f" ]] || continue
    n=$((n + 1))
    got="$(timeout 60 cat "$f" 2>/dev/null)" \
      || die "burst survivor $i unreadable after remount (rc $?)"
    [[ "$got" == "burst-$i" ]] || torn=$((torn + 1))
  done
  [[ "$torn" == 0 ]] || die "$torn burst survivors are torn after the KILL"
  probe_mark reopen_verified
  pass "burst survivors ($n files) are byte-complete, never torn"
  timeout 35 bash -c "echo 'after-crash' > '$MNTS/xcrash-o2/after-crash.txt'" 2>/dev/null \
    || die "post-crash write failed after remount"
  touch "$E2E_ROOT/crash-o-back"
  poll_until 180 test -f "$E2E_ROOT/crash-o-member-done" \
    || die "witness never converged the post-crash head"
  probe_mark postcrash_converged
  stop_mount xcrash-o2 INT
  check_no_leaks "$LOGDIR/mount-xcrash-o.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-xcrash-o2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_steady_member <drive> <creds> <relay>: the witness half of the
# owner crash: converge the anchor (proving pre-crash convergence),
# then converge the post-crash head after the owner returns — both
# bounded, so a stuck recovery dies loudly instead of hanging the
# phase. Holds its mount across the owner's death: no remount, no
# repair on this side.
leg_steady_member() {
  local d="$1" c="$2" relay="$3"
  step 13 "crash witness member leg"
  local PROBE_STEP=13
  start_mount xsteady-m "$c" "$d" "$MNTS/xsteady-m" --relay "$relay"
  # Publish readiness before waiting for the anchor: the owner
  # converges this first, which triggers the fetch that settles its
  # sync engine. Without it the owner's first mutation hits the
  # closure gate and ETIMEDOUTs (observed: retries alone never
  # drain the gate).
  timeout 35 bash -c "echo 'member-ready' > '$MNTS/xsteady-m/member-ready.txt'" 2>/dev/null \
    || die "witness readiness write failed"
  poll_until 180 converged "$MNTS/xsteady-m/anchor.txt" "anchor-v1" \
    || die "witness never converged the anchor write"
  pass "witness converges the anchor before the crash"
  probe_mark anchor_witnessed
  touch "$E2E_ROOT/crash-o-steady-ready"
  # 300s: instrumentation shows 40 burst writes take ~200s (some
  # hit 21s when the sync engine is mid-publish), plus KILL + remount
  # + verify ~30s. The old 120s expired at burst[18].
  poll_until 300 test -f "$E2E_ROOT/crash-o-back" \
    || die "owner never came back after the KILL"
  probe_mark owner_back
  poll_until 180 converged "$MNTS/xsteady-m/after-crash.txt" "after-crash" \
    || die "witness never converged the post-crash head"
  probe_mark head_converged
  pass "post-crash head converges without remount"
  touch "$E2E_ROOT/crash-o-member-done"
  stop_mount xsteady-m TERM
  check_no_leaks "$LOGDIR/mount-xsteady-m.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_crash_member <drive> <creds> <relay>: mount, take the cold
# announcement in hand WITHOUT fetching its body (the want is
# admitted but unfetched — durable state, not memory), then write an
# obligation the partitioned relay cannot drain and SIGKILL the
# mount's own process. After the host heals, remount fresh: the
# obligation must still converge to the witness (never lost with
# the dead process) and the cold want must re-demand from durable
# state and serve.
# Fence record (OD-06-A): the kill lands after the obligation write
# is acknowledged and while the relay partition makes drain
# impossible — the pending-outbox window. The drive joined fresh
# (manifest-only), so a scratch commit over the live relay localizes
# the head tree first: without it the obligation write would wait on
# remote base-closure content and fail TimedOut instead of pending.
# Single-writer discipline holds throughout: the witness authors
# nothing while partitioned, so no fork can mask a lost obligation.
# Bounded-failure assertions: cold serve bounded (300s), witness
# convergence bounded host-side. Wall-clock envelope: typical 3-4
# min observed green; dominant budget products are the scratch
# retries (6 x ~67s), cold converges (300s x2), and partition/heal
# rendezvous (~10 min). Simultaneous exhaustion is pathology,
# covered by the whole-run cap — not by this envelope.
leg_crash_member() {
  local d="$1" c="$2" relay="$3"
  step 13 "crash-injection member leg"
  local PROBE_STEP=13
  # Debug for this mount only, Lima step-6 style (see leg_fetch_member):
  # the scratch commit below is under investigation — if it outwaits
  # its deadline again, the daemon log must show what the commit
  # waited on. Scoped save/restore so later mounts keep info level.
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  export E2E_RUST_LOG="wyrd_core=debug"
  start_mount xcrash-m "$c" "$d" "$MNTS/xcrash-m" --relay "$relay"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  poll_until 120 bash -c "ls '$MNTS/xcrash-m' | grep -qx 'cold-u.txt'" \
    || die "member never listed the cold file"
  probe_mark cold_listed
  touch "$E2E_ROOT/crash-m-listed"
  # Body-path gate BEFORE any authorship: a held mutation gets 30s
  # (max_mutation_wait) before it fails TimedOut, and this drive
  # joined fresh — its loop is still settling while the endpoint
  # warms. Converging the cold bytes through patient read-side
  # demand first proves the iroh body path is live and the loop is
  # settled, so the scratch commit's tree fetch below races nothing
  # cold. Without this the scratch itself outwaits the deadline.
  poll_until 300 converged "$MNTS/xcrash-m/cold-u.txt" "cold-bytes-u" \
    || die "member never converged the cold bytes before authoring"
  pass "cold bytes flow before the member authors"
  probe_mark cold_converged
  # Tree localization BEFORE the partition, with bounded retries:
  # this drive joined fresh and its initial closure drains slowly
  # (observed: single objects per pass while pending_heads=1), so a
  # first-minute commit can outwait the 30s max_mutation_wait and
  # fail TimedOut even with the body path proven. Each attempt is
  # terminal (a timed-out mutation commits nothing), so retrying the
  # same bytes is safe; the first success proves the head tree local.
  # Six attempts bound the worst case near six minutes; the
  # closure drains in about one, so green runs pass on an early
  # retry. (Product note, out of G5 scope: fresh-join authorship in
  # the first ~minute routinely outwaits the deadline — fail-closed
  # and fast, but worth knowing.)
  local attempt=0 localized=0
  while (( attempt < 6 )); do
    attempt=$((attempt + 1))
    if timeout 60 bash -c "echo 'scratch-m' > '$MNTS/xcrash-m/scratch-m.txt'" 2>/dev/null \
      && [[ "$(cat "$MNTS/xcrash-m/scratch-m.txt")" == "scratch-m" ]]; then
      localized=1
      break
    fi
    sleep 2
  done
  [[ "$localized" == 1 ]] \
    || die "scratch never committed in $attempt attempts: the head tree never localized"
  pass "scratch commit localizes the head tree over the live relay (attempt $attempt)"
  probe_mark "scratch(attempts=$attempt)"
  touch "$E2E_ROOT/crash-m-ready"
  poll_until 180 test -f "$E2E_ROOT/crash-m-partitioned" \
    || die "host never partitioned the relay"
  conflict_assert_partitioned "$relay"
  # Bounded retries like the scratch above: trees are local now, so
  # the first attempt should take — the loop is insurance against a
  # straggler pass, not a second localization. Two attempts bound
  # ~150s, inside the host's 180s killed wait below.
  local oattempt=0 obligated=0
  while (( oattempt < 2 )); do
    oattempt=$((oattempt + 1))
    if timeout 60 bash -c "echo 'obligation-v1' > '$MNTS/xcrash-m/obligation.txt'" 2>/dev/null \
      && [[ "$(timeout 10 cat "$MNTS/xcrash-m/obligation.txt" 2>/dev/null)" == "obligation-v1" ]]; then
      obligated=1
      break
    fi
    sleep 2
  done
  [[ "$obligated" == 1 ]] \
    || die "obligation never acknowledged in $oattempt attempts under partition"
  pass "obligation acknowledged while the relay is down (fence: pending-outbox window)"
  probe_mark "obligation(attempts=$oattempt)"
  local pid kstatus=0
  pid="$(cat "$PIDDIR/mount-xcrash-m.pid")"
  kill -KILL "$pid" 2>/dev/null || die "member mount pid already gone before KILL"
  set +e; wait "$pid"; kstatus=$?; set -e
  [[ "$kstatus" == "137" ]] || die "member KILL exit $kstatus, want 137"
  kill -0 "$pid" 2>/dev/null && die "member mount pid survived KILL"
  rm -f "$PIDDIR/mount-xcrash-m.pid"
  fusermount3 -uz "$MNTS/xcrash-m" 2>/dev/null || true
  touch "$E2E_ROOT/crash-m-killed"
  probe_mark killed
  pass "member mount died on KILL with the obligation pending"
  poll_until 180 test -f "$E2E_ROOT/crash-m-healed" \
    || die "host never healed the relay"
  start_mount xcrash-m2 "$c" "$d" "$MNTS/xcrash-m2" --relay "$relay"
  # The want re-demands from durable state: the pre-kill listing
  # admitted it, the kill took only the process, and the post-heal
  # read serves the bytes over the live route with no remount dance
  # beyond the fresh mount itself.
  poll_until 300 converged "$MNTS/xcrash-m2/cold-u.txt" "cold-bytes-u" \
    || die "cold want never re-demanded after the KILL"
  pass "admitted want survives the KILL and serves after heal"
  probe_mark cold_redemanded
  touch "$E2E_ROOT/crash-m-done"
  poll_until 300 test -f "$E2E_ROOT/crash-m-witness-done" \
    || die "witness never converged the obligation"
  probe_mark obligation_witnessed
  stop_mount xcrash-m2 TERM
  check_no_leaks "$LOGDIR/mount-xcrash-m.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-xcrash-m2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_steady_owner <drive> <creds> <relay>: the witness half of the
# member crash: publish the cold file, then stay read-only while the
# relay is partitioned (single-writer discipline — any owner write
# under partition would fork the drive and mask the assertion).
# After heal, converge the member's obligation bytes bounded: the
# replay arriving here is the proof the KILL lost nothing.
leg_steady_owner() {
  local d="$1" c="$2" relay="$3"
  step 13 "crash witness owner leg"
  local PROBE_STEP=13
  start_mount xsteady-o "$c" "$d" "$MNTS/xsteady-o" --relay "$relay"
  timeout 35 bash -c "echo 'cold-bytes-u' > '$MNTS/xsteady-o/cold-u.txt'" 2>/dev/null \
    || die "cold announcement write failed"
  poll_until 120 test -f "$E2E_ROOT/crash-m-listed" \
    || die "member never listed the cold file"
  pass "cold announcement published before the partition"
  probe_mark announced
  poll_until 180 converged "$MNTS/xsteady-o/obligation.txt" "obligation-v1" \
    || die "member obligation never replayed after the KILL"
  probe_mark obligation_replayed
  pass "killed member's obligation replays after heal"
  touch "$E2E_ROOT/crash-m-witness-done"
  poll_until 120 test -f "$E2E_ROOT/crash-m-done" \
    || die "member leg never finished"
  probe_mark member_done
  stop_mount xsteady-o INT
  check_no_leaks "$LOGDIR/mount-xsteady-o.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_exhaustion <drive> <creds>: fill the drive's filesystem with
# a filler file (leaving 256 MiB headroom — never the whole disk),
# then write 32 MiB random files through an OFFLINE mount until one
# fails. The failing write must fail closed with ENOSPC (rc 1,
# "No space left on device"): the store maps a full disk to
# StoreFailure::StorageFull, which reaches the mount as ENOSPC
# (wyrd-format fs_store, wyrd-daemon fuse backend). Each file stays
# under the 64 MiB per-handle write budget, so the ENOSPC is the
# disk's, not the budget's; random bytes defeat chunk sharing, so
# every file really consumes its 32 MiB.
# Bounded-failure assertions: the failing write is wrapped in
# `timeout` (a hang is the bug, not a slow pass); the pre-fill file
# stays readable under exhaustion; the drive accepts writes again
# once the filler is gone. The harness exports the drive afterwards
# (in-guest: the container is invisible host-side) and asserts every
# fill file present is exactly 32 MiB (byte-complete) or absent —
# never torn.
# Wall-clock envelope: typical 4-5 min observed green (full pass
# ~185s with ENOSPC breaking early); dominant budget product is the
# fill loop (24 x 120s ~= 48 min if every fill hung to timeout yet
# succeeded — unreachable in practice since ENOSPC breaks the loop
# by fill ~9). Simultaneous exhaustion is pathology, covered by the
# whole-run cap — not by this envelope.
leg_exhaustion() {
  local d="$1" c="$2"
  step 14 "resource-exhaustion leg"
  command -v fallocate >/dev/null \
    || die "fallocate missing in the guest: the filler needs block preallocation"
  local avail_kb filler_bytes
  avail_kb="$(df -k --output=avail "$d" | tail -n 1 | tr -d ' ')"
  [[ "$avail_kb" -ge 2097152 ]] \
    || die "only ${avail_kb} KiB free under $d: the exhaustion leg needs 2 GiB headroom to fail loudly, not vacuously"
  # The filler must live INSIDE the drive dir: it is the only path
  # visible inside the container ($d/.. is the shared host dir, and
  # filling there fills odin, not the test fs). A stray file in the
  # drive dir is fine — nothing references it, and it is removed
  # before recovery and export below.
  # Leave 256 MiB breathing room: the filler takes the rest, and the
  # drive's own writes eat the remainder until something refuses.
  # That something may be the disk or the daemon's 256 MiB write
  # budget (budgets.rs: ENOSPC past the aggregate) — both reach the
  # mount as fail-closed ENOSPC, and the recovery retries below
  # cover either. The attribution check after the failing fill
  # records which refused (write-path.md "ENOSPC attribution").
  filler_bytes=$(( (avail_kb - 262144) * 1024 ))
  rm -f "$d/../exhaustion-filler.bin" "$d/exhaustion-filler.bin"
  fallocate -l "$filler_bytes" "$d/exhaustion-filler.bin" \
    || die "filler preallocation failed"
  pass "filesystem filled, 256 MiB headroom left"
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  # wyrd_daemon=debug for the backend's ENOSPC attribution lines
  # (layer + stage per refusal): the failing fill's refused layer —
  # disk or daemon budget — lives there, which wyrd_core=debug does
  # not cover.
  export E2E_RUST_LOG="wyrd_core=debug,wyrd_daemon=debug"
  start_mount xexh "$c" "$d" "$MNTS/xexh"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  echo "pre-fill" > "$MNTS/xexh/small.txt" \
    || die "pre-fill anchor write failed"
  [[ "$(cat "$MNTS/xexh/small.txt")" == "pre-fill" ]] \
    || die "pre-fill anchor never committed"
  pass "pre-fill anchor committed before exhaustion"
  local i=0 rc=0 failed=0 exh_log_from
  exh_log_from=$(wc -l < "$LOGDIR/mount-xexh.err")
  while (( i < 24 )); do
    i=$((i + 1))
    rc=0
    timeout 120 bash -c "head -c 33554432 /dev/urandom > '$MNTS/xexh/fill-$i.bin'" \
      2>"$E2E_ROOT/fill-$i.stderr" || rc=$?
    if (( rc != 0 )); then
      [[ "$rc" == 1 ]] || die "fill-$i exited $rc, want ENOSPC (1)"
      grep -q "No space left on device" "$E2E_ROOT/fill-$i.stderr" \
        || die "fill-$i was not ENOSPC: $(cat "$E2E_ROOT/fill-$i.stderr")"
      failed=1
      break
    fi
  done
  [[ "$failed" == 1 ]] \
    || die "24 x 32 MiB fills never exhausted the disk: the leg would pass without ever seeing ENOSPC"
  echo "$i" > "$E2E_ROOT/exh-failed-fill" \
    || die "could not record the failing fill index"
  pass "write fails closed with ENOSPC after $i fills"
  # Attribution: the failing fill must name its refusing layer in the
  # mount log. Which layer refused is load-dependent — disk or daemon
  # budget — so assert a refusal line exists and record which, rather
  # than predicting it.
  tail -n +"$((exh_log_from + 1))" "$LOGDIR/mount-xexh.err" | grep -q 'layer="' \
    || die "no ENOSPC attribution in mount-xexh.err past line $exh_log_from"
  local refusal
  refusal="$(tail -n +"$((exh_log_from + 1))" "$LOGDIR/mount-xexh.err" | grep -o 'layer="[a-z-]*"' | sort -u | tr '\n' ' ')"
  pass "failing fill attributed to $refusal"
  # Readable under exhaustion: the failure must not take the drive's
  # read path down with it.
  [[ "$(timeout 60 cat "$MNTS/xexh/small.txt")" == "pre-fill" ]] \
    || die "pre-fill anchor unreadable under exhaustion"
  pass "drive stays readable while full"
  rm -f "$d/../exhaustion-filler.bin" "$d/exhaustion-filler.bin" \
    || die "filler removal failed"
  # Bounded retries, not a single shot: freeing disk space does not
  # drain the daemon's write buffers, so if the budget (not the
  # disk) capped the fills, the first recovery write still sees
  # ENOSPC. Each attempt is terminal for its own bytes; a later one
  # lands once the engine publishes the backlog. Worst case ~6
  # minutes; the engine typically drains in under one.
  local r_attempt=0 recovered=0
  while (( r_attempt < 10 )); do
    r_attempt=$((r_attempt + 1))
    if timeout 30 bash -c "echo 'recovered' > '$MNTS/xexh/recovery.txt'" 2>/dev/null \
      && [[ "$(timeout 10 cat "$MNTS/xexh/recovery.txt" 2>/dev/null)" == "recovered" ]]; then
      recovered=1
      break
    fi
    sleep 5
  done
  [[ "$recovered" == 1 ]] \
    || die "drive never accepted writes after the filler was removed ($r_attempt attempts)"
  [[ "$(cat "$MNTS/xexh/recovery.txt")" == "recovered" ]] \
    || die "drive never accepted writes after the filler was removed"
  pass "drive accepts writes again once space returns"
  stop_mount xexh INT
  check_no_leaks "$LOGDIR/mount-xexh.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_uparent_owner <drive> <creds> <relay>: publish two chained
# snapshots (up-1, then up-2 strictly on top — the read-back between
# them proves S1 committed before S2 authors, so S2's parent IS S1)
# and stop gracefully while the member still lacks both bodies. The
# graceful stop is the point: no crash is needed, only an
# announcement whose body never arrives. Remount after the member's
# probes and publish a heal-signal write; the member converging it
# proves the stall healed.
leg_uparent_owner() {
  local d="$1" c="$2" relay="$3"
  step 15 "unknown-parent owner leg"
  local PROBE_STEP=15
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  # wyrd_daemon=debug for the FUSE backend's per-opcode lines
  # (errno, latency_us, queue_depth): the hung open's dispatch
  # story lives there, which wyrd_core=debug does not cover.
  export E2E_RUST_LOG="wyrd_core=debug,wyrd_daemon=debug"
  start_mount xup-o "$c" "$d" "$MNTS/xup-o" --relay "$relay"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  timeout 35 bash -c "echo 'up-1-bytes' > '$MNTS/xup-o/up-1.txt'" 2>/dev/null \
    || die "up-1 write failed"
  [[ "$(timeout 60 cat "$MNTS/xup-o/up-1.txt" 2>/dev/null)" == "up-1-bytes" ]] \
    || die "up-1 never committed"
  timeout 35 bash -c "echo 'up-2-bytes' > '$MNTS/xup-o/up-2.txt'" 2>/dev/null \
    || die "up-2 write failed"
  [[ "$(timeout 60 cat "$MNTS/xup-o/up-2.txt" 2>/dev/null)" == "up-2-bytes" ]] \
    || die "up-2 never committed on top of up-1"
  pass "chained snapshots published (up-2 strictly on up-1)"
  probe_mark published
  # Wait for the member to converge both announcements BEFORE
  # stopping: announcements leave via the async outbox, and after
  # 13b's forty-snapshot history the publish pipeline drains slowly
  # (two local writes took 34s). Stopping first risks stranding
  # up-2's announcement unsent in a dead outbox — while the remount
  # that would deliver it waits for member-probed, which waits for
  # the listing: a circular wait, not a timeout. The member's
  # listing IS the publication confirmation, so the stop below can
  # only happen with both announcements relay-visible. The 300s
  # covers both sequential listing polls (120s each) with margin.
  poll_until 300 test -f "$E2E_ROOT/uparent-announced" \
    || die "member never converged the announcements"
  stop_mount xup-o INT
  check_no_leaks "$LOGDIR/mount-xup-o.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  probe_mark owner_stopped
  touch "$E2E_ROOT/uparent-owner-gone"
  poll_until 300 test -f "$E2E_ROOT/uparent-member-probed" \
    || die "member never finished the unknown-parent probes"
  probe_mark member_probed
  start_mount xup-o2 "$c" "$d" "$MNTS/xup-o2" --relay "$relay"
  timeout 35 bash -c "echo 'up-3-bytes' > '$MNTS/xup-o2/up-3.txt'" 2>/dev/null \
    || die "up-3 write failed"
  touch "$E2E_ROOT/uparent-owner-back"
  probe_mark owner_back
  poll_until 300 test -f "$E2E_ROOT/uparent-member-healed" \
    || die "member never healed after the bodies arrived"
  probe_mark member_healed
  stop_mount xup-o2 INT
  check_no_leaks "$LOGDIR/mount-xup-o2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_uparent_member <drive> <creds> <relay>: with the owner down,
# list both announcements off the relay (manifests need no bodies),
# then prove withheld bodies fail EIO bounded from fetch-on-open.md:
# the child's and the parent's reads each hang on the unservable
# body until the 30s open deadline fires EIO — never a silent hang,
# never partial bytes. Both snapshots are live here (both manifests
# converged, so neither parent is missing from the DAG and neither
# classifies UnknownParent — that verdict needs a missing parent
# manifest and stays pinned at contract level in sync_contracts).
# The EIO pair is the whole proof: bodies were really withheld, the
# mount is alive, and the deadline — not hope — bounds every wait.
# After the owner returns, all three files serve: the stall heals.
# Wall-clock envelope: typical 3-4 min observed green; dominant
# budget products are the four 300s heal/return converges plus
# listing and rendezvous polls (~30 min). Simultaneous exhaustion
# is pathology, covered by the whole-run cap — not by this
# envelope.
leg_uparent_member() {
  local d="$1" c="$2" relay="$3"
  local rc=0
  step 15 "unknown-parent member leg"
  local PROBE_STEP=15
  local old_e2e_log="${E2E_RUST_LOG-__unset}"
  # wyrd_daemon=debug for the FUSE backend's per-opcode lines
  # (errno, latency_us, queue_depth): the hung open's dispatch
  # story lives there, which wyrd_core=debug does not cover.
  export E2E_RUST_LOG="wyrd_core=debug,wyrd_daemon=debug"
  start_mount xup-m "$c" "$d" "$MNTS/xup-m" --relay "$relay"
  if [[ "$old_e2e_log" == "__unset" ]]; then unset E2E_RUST_LOG; else export E2E_RUST_LOG="$old_e2e_log"; fi
  poll_until 120 bash -c "ls '$MNTS/xup-m' | grep -qx 'up-1.txt'" \
    || die "member never listed up-1"
  poll_until 120 bash -c "ls '$MNTS/xup-m' | grep -qx 'up-2.txt'" \
    || die "member never listed up-2"
  pass "both announcements listed; owner holds until this signal"
  probe_mark announced
  # Signal BEFORE waiting for the stop: the owner must not stop
  # until both announcements are relay-visible (see the owner leg).
  # Race-free: fetch is strictly demand-driven (fetch-on-open.md —
  # the loop never prefetches), and nothing opens either file before
  # the probes below, so no body can be cached before the owner is
  # down; the EIO control below still holds unconditionally.
  touch "$E2E_ROOT/uparent-announced"
  poll_until 180 test -f "$E2E_ROOT/uparent-owner-gone" \
    || die "owner never stopped before the probes"
  probe_mark owner_gone
  # Control first, on pristine state: a never-announced name is
  # ENOENT instantly, proving the mount is alive and resolving names
  # — so the EIOs below mean unfetchable bodies, not a dead mount.
  rc=0
  timeout 10 cat "$MNTS/xup-m/up-9.txt" >"$E2E_ROOT/up-9.got" 2>"$E2E_ROOT/up-9.err" || rc=$?
  [[ "$rc" == 1 ]] || die "unannounced-name open returned rc $rc, want ENOENT (1)"
  grep -q "No such file or directory" "$E2E_ROOT/up-9.err" \
    || die "unannounced-name open was not ENOENT: $(cat "$E2E_ROOT/up-9.err")"
  [[ ! -s "$E2E_ROOT/up-9.got" ]] \
    || die "unannounced-name read captured bytes it must not have"
  pass "unannounced names are ENOENT, instantly (control)"
  probe_mark control_enoent
  # The child: live head (its manifest converged, and so did its
  # parent's — neither classifies UnknownParent), body unfetchable
  # with the owner down. The open resolves; the read waits on the
  # body until the 30s open deadline fires EIO. The 60s budget
  # covers the deadline with margin; rc 124 means the wait
  # outlasted even that.
  rc=0
  timeout 60 cat "$MNTS/xup-m/up-2.txt" >"$E2E_ROOT/up-2.got" 2>"$E2E_ROOT/up-2.err" || rc=$?
  if [[ "$rc" != 1 ]]; then
    echo "--- up-2 probe failure evidence: projected view (timeout 10) ---"
    timeout 10 ls -laR "$MNTS/xup-m" 2>&1 | head -n 40 || true
    echo "--- drive + mount df ---"
    df -k "$MNTS/xup-m" "$d" 2>&1 || true
    die "withheld-child read returned rc $rc, want EIO (1); body captured: $(wc -c <"$E2E_ROOT/up-2.got") bytes, err: $(cat "$E2E_ROOT/up-2.err")"
  fi
  grep -q "Input/output error" "$E2E_ROOT/up-2.err" \
    || die "withheld-child read was not EIO: $(cat "$E2E_ROOT/up-2.err")"
  [[ ! -s "$E2E_ROOT/up-2.got" ]] \
    || die "withheld-child read captured bytes it must not have"
  pass "withheld child body fails EIO bounded"
  probe_mark child_eio
  # The parent, same shape: announced with its manifest, body
  # unfetchable with the owner down. Same EIO at the same deadline.
  rc=0
  timeout 60 cat "$MNTS/xup-m/up-1.txt" >"$E2E_ROOT/up-1.got" 2>"$E2E_ROOT/up-1.err" || rc=$?
  if [[ "$rc" != 1 ]]; then
    echo "--- up-1 probe failure evidence: projected view (timeout 10) ---"
    timeout 10 ls -laR "$MNTS/xup-m" 2>&1 | head -n 40 || true
    echo "--- drive + mount df ---"
    df -k "$MNTS/xup-m" "$d" 2>&1 || true
    die "withheld-body read returned rc $rc, want EIO (1); body captured: $(wc -c <"$E2E_ROOT/up-1.got") bytes, err: $(cat "$E2E_ROOT/up-1.err")"
  fi
  grep -q "Input/output error" "$E2E_ROOT/up-1.err" \
    || die "withheld-body read was not EIO: $(cat "$E2E_ROOT/up-1.err")"
  [[ ! -s "$E2E_ROOT/up-1.got" ]] \
    || die "withheld-body read captured bytes it must not have"
  pass "withheld parent body fails EIO bounded (control)"
  probe_mark parent_eio
  touch "$E2E_ROOT/uparent-member-probed"
  poll_until 300 test -f "$E2E_ROOT/uparent-owner-back" \
    || die "owner never returned after the probes"
  probe_mark owner_back
  poll_until 300 converged "$MNTS/xup-m/up-1.txt" "up-1-bytes" \
    || die "up-1 never healed once the body arrived"
  poll_until 300 converged "$MNTS/xup-m/up-2.txt" "up-2-bytes" \
    || die "up-2 never healed once the body arrived"
  pass "withheld bodies heal without remount"
  probe_mark healed
  poll_until 300 converged "$MNTS/xup-m/up-3.txt" "up-3-bytes" \
    || die "member never converged the post-return write"
  probe_mark postreturn_converged
  pass "post-return head converges"
  touch "$E2E_ROOT/uparent-member-healed"
  stop_mount xup-m TERM
  check_no_leaks "$LOGDIR/mount-xup-m.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

case "${1:-}" in
  converge-owner) leg_converge_owner "$2" "$3" "$4" ;;
  converge-member) leg_converge_member "$2" "$3" "$4" ;;
  converge2-owner) leg_converge2_owner "$2" "$3" "$4" ;;
  converge2-member) leg_converge2_member "$2" "$3" "$4" ;;
  restarted-owner) leg_restarted_owner "$2" "$3" "$4" ;;
  restart-member) leg_restart_member "$2" "$3" "$4" ;;
  upgrade-owner) leg_upgrade_owner "$2" "$3" "$4" "$5" ;;
  upgrade-member) leg_upgrade_member "$2" "$3" "$4" ;;
  fetch-owner) leg_fetch_owner "$2" "$3" "$4" ;;
  fetch-member) leg_fetch_member "$2" "$3" "$4" ;;
  conflict-owner) leg_conflict_owner "$2" "$3" "$4" ;;
  conflict-member) leg_conflict_member "$2" "$3" "$4" ;;
  crash-owner) leg_crash_owner "$2" "$3" "$4" ;;
  steady-member) leg_steady_member "$2" "$3" "$4" ;;
  crash-member) leg_crash_member "$2" "$3" "$4" ;;
  steady-owner) leg_steady_owner "$2" "$3" "$4" ;;
  exhaustion) leg_exhaustion "$2" "$3" ;;
  uparent-owner) leg_uparent_owner "$2" "$3" "$4" ;;
  uparent-member) leg_uparent_member "$2" "$3" "$4" ;;
  headless-serve) leg_headless_serve "$2" "$3" "$4" ;;
  headless-fetch) leg_headless_fetch "$2" "$3" "$4" "$5" "$6" "$7" ;;
  headless-setup) leg_headless_setup "$2" "$3" ;;
  *) echo "usage: $0 converge-owner|converge-member|converge2-owner|converge2-member|restarted-owner|restart-member|upgrade-member|fetch-owner|fetch-member|conflict-owner|conflict-member|crash-owner|steady-member|crash-member|steady-owner|exhaustion|uparent-owner|uparent-member|headless-serve <drive> <creds> <relay> | upgrade-owner <drive> <creds> <relay> <archive> | headless-fetch <drive> <creds> <relay> <tag> <ready-file> <done-file> | headless-setup <drive> <creds>" >&2; exit 2 ;;
esac
e2e_timing_report
echo "legs: $PASS_COUNT checks passed"
