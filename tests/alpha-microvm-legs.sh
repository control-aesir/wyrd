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
# shellcheck source=/dev/null
source /etc/wyrd-tests/alpha-common.sh

# Per-guest pid dir: legs run concurrently on guests sharing one
# E2E_ROOT, and same-image mount pids collide across hosts — a
# shared pid dir lets one leg's EXIT trap SIGKILL the other's live
# mount (or an unrelated pid). Done-files stay shared (rendezvous);
# pids must not be. (alpha-common.sh sources the env file itself.)
PIDDIR="$E2E_ROOT/pids/$(hostname -s)"

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
  echo "cold-bytes" > "$MNTS/xowner-f/cold-2.txt"
  poll_until 120 test -f "$E2E_ROOT/member-cold-done" \
    || die "member never completed the blocking cold open"
  pass "member's single open unblocked on the announcement"
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
  check_no_leaks "$LOGDIR/mount-xowner-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  touch "$E2E_ROOT/owner-stopped"
  poll_until 240 test -f "$E2E_ROOT/member-probed-done" \
    || die "member never finished the dead-route probes"
  pass "owner stayed down while the member probed the dead route"
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
  poll_until 240 test -f "$E2E_ROOT/member-fetch-done" \
    || die "member never finished the delete"
  poll_until 120 bash -c "! test -e '$MNTS/xowner-f2/stale-1.txt'" \
    || die "owner never converged the member's offline delete"
  pass "owner converges the delete before finishing"
  # Convergence ack: the member must not shut down until its
  # announcements have arrived here — a fast member would otherwise
  # outrun its own outbox drain and this leg could never converge.
  touch "$E2E_ROOT/owner-converged-done"
  # Ten attempts bound the member's worst case near eleven minutes
  # (10 x (60s attempt + 5s sleep)), so this wait must clear it or
  # the owner's diagnostic masks the member's own.
  poll_until 700 test -f "$E2E_ROOT/member-recovered-done" \
    || die "member never recovered the stale identity"
  stop_mount xowner-f2 INT
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
  start_mount xmember-f "$c" "$d" "$MNTS/xmember-f" --relay "$relay"
  # Announcement first (listing shows the new head), bytes second
  # (the single cat below): this split is what makes the cat a
  # blocking-open proof rather than a find-ready-bytes no-op.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'cold-2.txt'" \
    || die "member never listed the cold file"
  timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2.got" \
    || die "blocking cold open failed (open did not wait for the bytes)"
  [[ "$(cat "$E2E_ROOT/cold-2.got")" == "cold-bytes" ]] \
    || die "cold open returned wrong bytes"
  pass "single open blocks until the announced bytes arrive"
  touch "$E2E_ROOT/member-cold-done"
  # Manifest-only convergence: readdir pulls the manifest chain
  # without opening contents, so the member holds the announcements
  # for both stale files while their chunks are still unfetched.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-1.txt'" \
    || die "member never listed stale-1.txt"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-2.txt'" \
    || die "member never listed stale-2.txt"
  touch "$E2E_ROOT/member-listed-done"
  poll_until 180 test -f "$E2E_ROOT/owner-stopped" \
    || die "owner never stopped for the dead-route probes"
  # Dead route, held manifest, nothing authored yet: the bytes are
  # announced but unfetchable, and no local write has had a chance
  # to demand them first. Each read must fail closed and bounded.
  local rc=0
  timeout 60 cat "$MNTS/xmember-f/stale-1.txt" >/dev/null 2>"$E2E_ROOT/stale-1.err" || rc=$?
  [[ "$rc" == 1 ]] || die "stale-manifest read returned rc $rc, want EIO (1)"
  grep -q "Input/output error" "$E2E_ROOT/stale-1.err" \
    || die "stale-manifest read was not EIO: $(cat "$E2E_ROOT/stale-1.err")"
  pass "announced-but-unfetchable read fails closed and bounded"
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
  # The owner is back on a fresh endpoint with a new route (see
  # owner leg). Converge its head BEFORE authoring: the scratch and
  # the delete below must extend the post-restart lineage, and the
  # announcement carries the route the tree fetch needs.
  poll_until 120 test -f "$E2E_ROOT/owner-back" \
    || die "owner never came back after the dead-route probes"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'owner-back-1.txt'" \
    || die "member never listed the post-restart write"
  pass "member converges on the post-restart head over the new route"
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
  # Scratch write against the live route: creating a file forces
  # the current head's tree object to materialize (reads never
  # fetch tree objects, only manifests and chunks), and the delete
  # below needs that tree local. Completion is the signal —
  # success means the trees are local, so no timing guess.
  echo "scratch" > "$MNTS/xmember-f/scratch-del.txt"
  poll_until 120 converged "$MNTS/xmember-f/scratch-del.txt" "scratch" \
    || die "scratch write never became readable"
  pass "scratch write forces tree materialization over the live route"
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
  # Stay up until the owner confirms convergence: shutting down
  # here would outrun the outbox drain and strand the scratch and
  # delete announcements this leg's owner polls wait for. Short
  # budget on purpose: in the normal case the owner acks while this
  # mount is still recovering, so this only ever costs minutes when
  # the owner is genuinely stuck.
  poll_until 120 test -f "$E2E_ROOT/owner-converged-done" \
    || die "owner never converged the scratch and delete"
  touch "$E2E_ROOT/member-recovered-done"
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
  check_no_leaks "$LOGDIR/mount-xmember-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
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
  start_mount xowner-c "$c" "$d" "$MNTS/xowner-c" --relay "$relay"
  conflict_assert_reachable "$relay"
  echo "victim" > "$MNTS/xowner-c/rename-victim.txt"
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
  start_mount xmember-c "$c" "$d" "$MNTS/xmember-c" --relay "$relay"
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

case "${1:-}" in
  converge-owner) leg_converge_owner "$2" "$3" "$4" ;;
  converge-member) leg_converge_member "$2" "$3" "$4" ;;
  restarted-owner) leg_restarted_owner "$2" "$3" "$4" ;;
  restart-member) leg_restart_member "$2" "$3" "$4" ;;
  fetch-owner) leg_fetch_owner "$2" "$3" "$4" ;;
  fetch-member) leg_fetch_member "$2" "$3" "$4" ;;
  conflict-owner) leg_conflict_owner "$2" "$3" "$4" ;;
  conflict-member) leg_conflict_member "$2" "$3" "$4" ;;
  *) echo "usage: $0 converge-owner|converge-member|restarted-owner|restart-member|fetch-owner|fetch-member|conflict-owner|conflict-member <drive> <creds> <relay>" >&2; exit 2 ;;
esac
echo "legs: $PASS_COUNT checks passed"
