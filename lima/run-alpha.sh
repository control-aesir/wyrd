#!/usr/bin/env bash
# lima/run-alpha.sh — host half of the Lima e2e run. All intelligence lives
# in the guest script (tests/alpha-lima.sh); this only moves the binary
# into the guest and starts it.
#
# Usage: ./lima/run-alpha.sh [--keep] [--re-share] [--step N[,N...]]
#   --keep   leave the instance running afterwards for debugging
#   --re-share
#            the guest share is stamped with the checkout path at instance
#            creation; after switching worktrees it serves the old checkout
#            (or a deleted one). With --re-share the wrapper re-points the
#            instance at this checkout and restarts it instead of refusing.
#            Without it a stale share is a hard stop (see below).
#   --step   run guest-script steps 1..N (comma lists allowed; the run
#            is the prefix closure, since steps build on each other)
#
# Prerequisites on the host: nix (with the linux-builder for the
# guest-arch binary), limactl, and realpath. The guest needs no toolchain.
set -euo pipefail

KEEP=0
RESHARE=0
ONLY_STEP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --re-share) RESHARE=1; shift ;;
    --step)
      # An explicit but empty value is a mistake, not "all steps".
      [[ -n "${2:-}" ]] || { echo "error: --step needs at least one step" >&2; exit 2; }
      ONLY_STEP="$2"
      shift 2
      ;;
    *) echo "error: unknown flag $1" >&2; exit 2 ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel)"
ROOT_REAL="$(realpath "$ROOT")"
INSTANCE="wyrd-alpha"
SHARE=/tmp/lima
mkdir -p "$SHARE"

if ! limactl list 2>/dev/null | grep -q "^$INSTANCE[[:space:]].*Running"; then
  if limactl list 2>/dev/null | grep -q "^$INSTANCE[[:space:]]"; then
    echo "==> starting existing instance $INSTANCE"
    limactl start "$INSTANCE"
  else
    echo "==> creating instance $INSTANCE"
    # The yaml carries a placeholder checkout path; stamp the real one.
    # (limactl --set could do this, but a rendered file is easier to
    # debug.) The replacement is sed-escaped: a checkout path with
    # `&`, `|`, or `\` must land literally.
    ROOT_SED="${ROOT//\\/\\\\}"
    ROOT_SED="${ROOT_SED//|/\\|}"
    ROOT_SED="${ROOT_SED//&/\\&}"
    sed "s|/path/to/wyrd-checkout|$ROOT_SED|" "$ROOT/lima/wyrd-alpha.yaml" \
      > "$SHARE/wyrd-alpha.rendered.yaml"
    limactl start --name="$INSTANCE" "$SHARE/wyrd-alpha.rendered.yaml"
  fi
fi

# The guest share is stamped with the checkout path at creation time, so a
# run from a different worktree would silently test the wrong code (or fail
# obscurely off a deleted checkout). Refuse before building anything. The
# comparison is host-side: the instance yaml records the checkout the share
# serves, and path equality is strictly stronger than a HEAD probe (two
# checkouts at the same commit are still different shares); both the raw and
# the resolved checkout path match, so a symlinked checkout is not a false
# refusal. A guest liveness check confirms something shaped like this
# checkout is actually mounted; the guest needs no toolchain for either
# half. A wrong path and an unmounted share fail differently on purpose: the
# remedies are different (re-point versus restart the VM).
LIMA_YAML="${LIMA_HOME:-$HOME/.lima}/$INSTANCE/lima.yaml"
# Read ($1=read, prints the recorded path, empty on any failure) or rewrite
# ($1=write) the /mnt/wyrd mount location. One matcher for both: the read
# already proves the file parses and names the mount, so a write after a
# successful read cannot miss. Quote-agnostic and index-guarded: limactl
# owns this file's serialization, not us. ensure_ascii=False keeps the
# write byte-identical to what the read returns for non-ASCII paths.
mount_location() {
  # Reads stay silent (empty record is a normal mismatch input); writes fail
  # loudly (a traceback under set -e aborts before the start below).
  local err=/dev/stderr
  if [[ "$1" == read ]]; then err=/dev/null; fi
  WYRD_MODE="$1" WYRD_YAML="$LIMA_YAML" WYRD_ROOT="$ROOT" python3 - <<'EOF' 2>"$err" || [[ "$1" == read ]]
import json, os, shutil
path = os.environ["WYRD_YAML"]
lines = open(path, encoding="utf-8").read().split("\n")
for i, line in enumerate(lines):
    if not line.strip().startswith("- location:"):
        continue
    if i + 1 >= len(lines):
        continue
    nxt = lines[i + 1].replace('"', "").replace("'", "")
    if "mountPoint:" in nxt and "/mnt/wyrd" in nxt:
        break
else:
    raise SystemExit("no /mnt/wyrd mount found in " + path)
if os.environ["WYRD_MODE"] == "read":
    print(line.split(":", 1)[1].strip().strip("\"'"))
else:
    indent = line[: line.index("- location:")]
    lines[i] = indent + "- location: " + json.dumps(os.environ["WYRD_ROOT"], ensure_ascii=False)
    # Unlink first: a previous read-only backup must not block this one;
    # unlinking needs directory permission, which the operator has.
    for stale in (path + ".bak", path + ".tmp"):
        if os.path.exists(stale):
            os.unlink(stale)
    shutil.copyfile(path, path + ".bak")
    open(path + ".tmp", "w", encoding="utf-8").write("\n".join(lines))
    shutil.copymode(path, path + ".tmp")
    os.replace(path + ".tmp", path)
EOF
}
# A sentry file, not git: the guest must show a mounted checkout, and the
# recorded path above says which one.
share_mounted() {
  (cd / && limactl shell "$INSTANCE" -- test -f /mnt/wyrd/lima/run-alpha.sh 2>/dev/null)
}
# The 9p share may lag the READY state by a moment after a start; retry
# briefly before calling a freshly started instance unmounted.
wait_mounted() {
  local attempt
  for attempt in 1 2 3 4 5; do
    share_mounted && return 0
    [[ $attempt -lt 5 ]] && sleep 3
  done
  return 1
}
recorded_ok() {
  [[ "$RECORDED" == "$ROOT" || "$RECORDED" == "$ROOT_REAL" ]]
}
RECORDED="$(mount_location read)"
if ! recorded_ok || ! share_mounted; then
  if [[ $RESHARE -eq 1 ]] && ! recorded_ok; then
    # Validate before announcing or stopping: an empty record means
    # unreadable yaml or no match (not just a wrong path), so refuse with
    # the VM still running.
    [[ -n "$RECORDED" ]] || { echo "error: cannot re-share: no readable /mnt/wyrd mount in $LIMA_YAML" >&2; exit 2; }
    echo "==> guest share points elsewhere (recorded $RECORDED, checkout $ROOT); re-pointing $INSTANCE"
    # Back up the operator's config, then rewrite atomically. Only the
    # /mnt/wyrd mount moves; image locations and the scratch share stay.
    # A write failure here leaves the instance stopped; the next run
    # restarts it (see the start block above).
    limactl stop "$INSTANCE"
    mount_location write
    limactl start "$INSTANCE"
    RECORDED="$(mount_location read)"
  fi
  if ! recorded_ok; then
    echo "error: guest share points elsewhere (recorded ${RECORDED:-unreadable}, checkout $ROOT)" >&2
    echo "  recreate the instance, or rerun with --re-share to re-point it at this checkout" >&2
    exit 2
  elif ! wait_mounted; then
    echo "error: guest share is not mounted (recorded $RECORDED matches this checkout, but /mnt/wyrd is not serving it)" >&2
    echo "  restart the instance (limactl stop/start) or recreate it" >&2
    exit 2
  fi
fi

# The guest copies each run's logs to $SHARE/logs/<timestamp>; prune
# to the five newest before this run adds its own, so per-run
# forensics stay available without the shared host dir growing
# without bound. Names sort by intent already (%Y%m%d-%H%M%S), so
# order by name, not mtime. This sits below the verification above so a
# refused run performs no build and prunes no logs (the mkdir and the
# instance start above still run: both are idempotent, and the start is
# required to verify at all).
if [[ -d "$SHARE/logs" ]]; then
  # Only directories rank: a stray file must neither consume a keep
  # slot nor be deleted.
  rank=0
  while IFS= read -r old; do
    rank=$((rank + 1))
    [[ $rank -gt 5 ]] || continue
    rm -rf "$SHARE/logs/$old"
  done < <(for f in "$SHARE/logs/"*/; do
    [[ -d "$f" ]] || continue
    basename "$f"
  done 2>/dev/null | sort -r) || true
fi

# The guest image follows the host architecture (the yaml carries both),
# so the binary must match it: arm64 hosts take the aarch64-linux
# package, Intel hosts the x86_64-linux one.
case "$(uname -m)" in
  arm64|aarch64) LINUX_SYSTEM="aarch64-linux" ;;
  x86_64|amd64) LINUX_SYSTEM="x86_64-linux" ;;
  *) echo "error: unsupported host architecture $(uname -m)" >&2; exit 2 ;;
esac

echo "==> building the $LINUX_SYSTEM wyrd binary on the host"
OUT="$(nix build "$ROOT#packages.$LINUX_SYSTEM.wyrd" --no-link --print-out-paths 2>/dev/null | tail -n 1)"
WYRD_BIN="$OUT/bin/wyrd"
echo "    $WYRD_BIN"

echo "==> exporting the runtime closure for the guest"
readarray -t CLOSURE < <(nix-store -qR "$OUT")
nix-store --export "${CLOSURE[@]}" > "$SHARE/wyrd-closure.nar"
REV="$(python3 -c "import json; print(json.load(open('$ROOT/flake.lock'))['nodes']['nixpkgs']['locked']['rev'])")"
# Shell-quoted, never interpolated raw: a checkout path or a step/log
# filter with shell metacharacters must not become source.
{
  echo "# Generated by lima/run-alpha.sh; sourced by the guest scripts."
  printf 'WYRD_BIN=%q\n' "$WYRD_BIN"
  printf 'NIXPKGS_REV=%q\n' "$REV"
  printf 'RELAY_PORT=%q\n' "18761"
  # Omitted entirely when unset: the guest reads an absent variable as
  # "all steps", and an empty value there would be ambiguous with the
  # malformed list the guest must refuse.
  [[ -z "$ONLY_STEP" ]] || printf 'E2E_ONLY_STEP=%q\n' "$ONLY_STEP"
  printf 'E2E_RUST_LOG=%q\n' "${E2E_RUST_LOG:-}"
} > "$SHARE/e2e-env.sh"

echo "==> provisioning the guest (idempotent)"
# Run from a host directory that exists in the guest: limactl adopts
# the caller's cwd as the guest workdir, and the caller's checkout
# path is not visible in the guest, so leaving it in place only
# produces "cd: no such file" noise on every shell call.
(cd / && limactl shell "$INSTANCE" -- bash /mnt/wyrd/lima/provision.sh)

echo "==> running the guest contract"
set +e
(cd / && limactl shell "$INSTANCE" -- bash /mnt/wyrd/tests/alpha-lima.sh)
STATUS=$?
set -e

echo "==> logs collected under $SHARE/logs/"
if [[ $KEEP -eq 0 ]]; then
  echo "==> stopping $INSTANCE (--keep to leave it running)"
  limactl stop "$INSTANCE"
fi
exit "$STATUS"
