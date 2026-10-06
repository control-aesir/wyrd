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
# guest-arch binary) and limactl. The guest needs no toolchain.
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
# checkouts at the same commit are still different shares). A guest liveness
# check confirms something shaped like this checkout is actually mounted;
# the guest needs no toolchain for either half.
LIMA_YAML="${LIMA_HOME:-$HOME/.lima}/$INSTANCE/lima.yaml"
# Print the checkout path the instance yaml records for /mnt/wyrd (empty
# on any failure: missing file, no match). The matcher is quote-agnostic
# and index-guarded: limactl owns this file's serialization, not us.
recorded_location() {
  WYRD_YAML="$1" python3 - <<'EOF' 2>/dev/null || true
import os
path = os.environ["WYRD_YAML"]
lines = open(path).read().split("\n")
for i, line in enumerate(lines):
    if not line.strip().startswith("- location:"):
        continue
    if i + 1 >= len(lines):
        break
    nxt = lines[i + 1].replace('"', "").replace("'", "")
    if "mountPoint:" in nxt and "/mnt/wyrd" in nxt:
        print(line.split(":", 1)[1].strip().strip("\"'"))
        break
EOF
}
# A sentry file, not git: the guest must show a mounted checkout, and the
# recorded path above says which one.
share_mounted() {
  (cd / && limactl shell "$INSTANCE" -- test -f /mnt/wyrd/lima/run-alpha.sh 2>/dev/null)
}
RECORDED="$(recorded_location "$LIMA_YAML")"
if [[ "$RECORDED" != "$ROOT" ]] || ! share_mounted; then
  if [[ $RESHARE -eq 1 ]]; then
    echo "==> guest share is stale (recorded ${RECORDED:-unreadable}, checkout $ROOT); re-pointing $INSTANCE"
    # Validate before stopping: the read above already proved the file
    # parses and names a /mnt/wyrd mount, so the rewrite below cannot miss.
    # Back up the operator's config, then rewrite atomically. Only the
    # /mnt/wyrd mount moves; image locations and the scratch share stay.
    [[ -n "$RECORDED" ]] || { echo "error: cannot re-share: no /mnt/wyrd mount in $LIMA_YAML" >&2; exit 2; }
    limactl stop "$INSTANCE"
    WYRD_YAML="$LIMA_YAML" WYRD_ROOT="$ROOT" python3 - <<'EOF'
import json, os, shutil
path = os.environ["WYRD_YAML"]
root = os.environ["WYRD_ROOT"]
lines = open(path).read().split("\n")
for i, line in enumerate(lines):
    if not line.strip().startswith("- location:"):
        continue
    if i + 1 >= len(lines):
        break
    nxt = lines[i + 1].replace('"', "").replace("'", "")
    if "mountPoint:" in nxt and "/mnt/wyrd" in nxt:
        indent = line[: line.index("- location:")]
        lines[i] = indent + "- location: " + json.dumps(root)
        break
else:
    raise SystemExit("no /mnt/wyrd mount found in " + path)
shutil.copy(path, path + ".bak")
tmp = path + ".tmp"
open(tmp, "w").write("\n".join(lines))
os.replace(tmp, path)
EOF
    limactl start "$INSTANCE"
    RECORDED="$(recorded_location "$LIMA_YAML")"
  fi
  if [[ "$RECORDED" != "$ROOT" ]] || ! share_mounted; then
    echo "error: guest share is stale (recorded ${RECORDED:-unreadable}, checkout $ROOT)" >&2
    echo "  recreate the instance, or rerun with --re-share to re-point it at this checkout" >&2
    exit 2
  fi
fi

# The guest copies each run's logs to $SHARE/logs/<timestamp>; prune
# to the five newest before this run adds its own, so per-run
# forensics stay available without the shared host dir growing
# without bound. Names sort by intent already (%Y%m%d-%H%M%S), so
# order by name, not mtime. This sits below the verification above so a
# refused run leaves host state untouched.
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
