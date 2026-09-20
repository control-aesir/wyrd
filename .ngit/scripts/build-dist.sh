#!/usr/bin/env bash
# Build every wyrd distribution tarball this machine can produce.
#
# Usage: build-dist.sh <version> [--strict] [--ref <git-ref>] [--verify] [system...]
#
# With no system arguments, host capability is detected and exactly the
# buildable combos are built: the native system always, x86_64-darwin via
# Rosetta on Apple Silicon (iff nix accepts the platform), and foreign
# Linux systems via remote builders. Explicit systems skip detection (and
# fail loudly when not buildable). `--strict` (what releases use)
# requires all four combos from release.yaml instead, since ngit rejects
# partial platform coverage on the main channel. `--ref` pins the input
# worktree to a git ref instead of the default `v<version>` tag (CI uses
# HEAD); `--verify` unpacks each built tarball and runs its binary.
# Input is always a detached worktree, never the working copy, so a
# dirty tree cannot bake into a release tarball.
set -euo pipefail

VERSION="${1:?usage: build-dist.sh <version> [--strict] [--ref <git-ref>] [--verify] [system...] (e.g. 0.1.0-alpha.1 --strict)}"
shift
STRICT=false
REF=""
VERIFY=false
WANTED=()
while [ $# -gt 0 ]; do
  case "$1" in
    --strict) STRICT=true ;;
    --ref)
      shift
      REF="${1:?--ref needs a git ref}"
      ;;
    --verify) VERIFY=true ;;
    aarch64-darwin|x86_64-darwin|aarch64-linux|x86_64-linux) WANTED+=("$1") ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
  shift
done

PIN="${REF:-v$VERSION}"
git rev-parse --verify --quiet "$PIN" >/dev/null \
  || { echo "ref $PIN does not exist" >&2; exit 1; }
ROOT=$(git rev-parse --show-toplevel)
EXPORT=$(mktemp -d)
trap 'cd "$ROOT"; git worktree remove --force "$EXPORT" >/dev/null 2>&1 || rm -rf "$EXPORT"' EXIT
git worktree add --detach "$EXPORT" "$PIN" >/dev/null
mkdir -p "$ROOT/dist"

NIX=(nix --extra-experimental-features 'nix-command flakes')
NATIVE=$(nix --extra-experimental-features 'nix-command flakes' eval --impure --raw --expr 'builtins.currentSystem' 2>/dev/null)

# Remote-builder systems: second column of each machines file
# (comma-separated), comments skipped.
builder_systems() {
  # shellcheck disable=SC2013
  nix show-config 2>/dev/null | sed -n 's/^builders = //p' | tr ' ' '\n' | while read -r TOKEN; do
    case "$TOKEN" in
      @*) awk '$1 !~ /^#/ {print $2}' "${TOKEN#@}" 2>/dev/null ;;
    esac
  done | tr ',' ' '
}
BUILDERS=$(builder_systems)

# Whether a combo can build here: natively, via Rosetta (Intel macOS
# binaries on Apple Silicon, iff nix accepts the platform), or via a
# remote builder advertising the system.
capable() {
  [ "$1" = "$NATIVE" ] && return 0
  case "$1" in
    x86_64-darwin)
      [ "$(uname -s)" = Darwin ] || return 1
      [ "${NATIVE%%-*}" = aarch64 ] || return 1
      arch -x86_64 /usr/bin/true 2>/dev/null || return 1
      nix show-config 2>/dev/null | grep -q 'x86_64-darwin' || return 1
      return 0
      ;;
    *-linux)
      echo "$BUILDERS" | grep -qw "$1" || return 1
      return 0
      ;;
    *) return 1 ;;
  esac
}

QUEUE=()
SKIPPED=()
if [ -z "${WANTED[*]:-}" ]; then
  for SYSTEM in aarch64-darwin x86_64-darwin aarch64-linux x86_64-linux; do
    if capable "$SYSTEM"; then
      QUEUE+=("$SYSTEM")
    else
      SKIPPED+=("$SYSTEM (not buildable here)")
    fi
  done
else
  for SYSTEM in ${WANTED[@]+"${WANTED[@]}"}; do
    if capable "$SYSTEM"; then
      QUEUE+=("$SYSTEM")
    else
      echo "requested $SYSTEM is not buildable here" >&2
      exit 1
    fi
  done
fi
[ -n "${QUEUE[*]:-}" ] || {
  echo "nothing buildable here" >&2
  exit 1
}

BUILT=()
for SYSTEM in ${QUEUE[@]+"${QUEUE[@]}"}; do
  echo "building $SYSTEM from $PIN..."
  "${NIX[@]}" build "$EXPORT#packages.$SYSTEM.wyrd-dist" --out-link "$EXPORT/dist-$SYSTEM"
  cp "$EXPORT/dist-$SYSTEM" "$ROOT/dist/$(basename "$(readlink "$EXPORT/dist-$SYSTEM")")"
  BUILT+=("$SYSTEM")
done

if [ "$VERIFY" = true ]; then
  for SYSTEM in ${BUILT[@]+"${BUILT[@]}"}; do
    FILE="$ROOT/dist/$(basename "$(readlink "$EXPORT/dist-$SYSTEM")")"
    CHECK=$(mktemp -d)
    tar -xzf "$FILE" -C "$CHECK"
    BIN="$CHECK"/*/bin/wyrd
    test -x "$BIN" || {
      echo "$FILE: no executable bin/wyrd" >&2
      exit 1
    }
    "$BIN" --version
    rm -rf "$CHECK"
  done
fi

echo "built: ${BUILT[*]}"
[ -n "${SKIPPED[*]:-}" ] && echo "skipped: ${SKIPPED[*]}"

# Release gate: --strict requires every archive release.yaml names,
# since ngit rejects partial platform coverage on main.
if [ "$STRICT" = true ]; then
  for ARTIFACT in "$ROOT/dist/wyrd-$VERSION-macos-aarch64.tar.gz" "$ROOT/dist/wyrd-$VERSION-macos-x86_64.tar.gz" "$ROOT/dist/wyrd-$VERSION-linux-aarch64.tar.gz" "$ROOT/dist/wyrd-$VERSION-linux-x86_64.tar.gz"; do
    [ -f "$ARTIFACT" ] || {
      echo "missing expected artifact $ARTIFACT" >&2
      exit 1
    }
  done
fi

echo "dist/:"
ls "$ROOT/dist"
