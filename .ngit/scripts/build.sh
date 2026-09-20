#!/usr/bin/env bash
# Build every wyrd distribution tarball this machine can produce.
#
# Usage: build.sh <version> [--strict] [--ref <git-ref>] [--verify] [system...]
#
# With no system arguments, host capability is detected and exactly the
# buildable combos are built: the native system always, x86_64-darwin via
# Rosetta on Apple Silicon (iff nix accepts the platform), and foreign
# Linux systems via remote builders. Explicit systems skip detection (and
# fail loudly when not buildable). `--strict` (what releases use)
# requires all four combos from release.yaml instead, since ngit rejects
# partial platform coverage on the main channel. `--ref` pins the input
# worktree to a git ref instead of the default `v<version>` tag (CI uses
# HEAD); `--verify` unpacks each built tarball and runs its binary
# (binaries whose linked system libraries are absent get a structure check
# and a warning instead: a missing macFUSE is an environment gap, not a
# broken binary).
# Input is always a detached worktree, never the working copy, so a
# dirty tree cannot bake into a release tarball.
set -euo pipefail

VERSION="${1:?usage: build.sh <version> [--strict] [--ref <git-ref>] [--verify] [system...] (e.g. 0.1.0-alpha.1 --strict)}"
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
# Probes stay loud: a detection failure must say which probe failed (a mute
# CI log cost us a release-day diagnosis once). nix's own stderr is the
# diagnostic, so it is never suppressed here.
NATIVE=$(nix --extra-experimental-features 'nix-command flakes' eval --impure --raw --expr 'builtins.currentSystem') || {
  echo "build.sh: cannot detect the current system (nix eval failed)" >&2
  exit 1
}

# Remote-builder systems: second column of each machines file
# (comma-separated), comments skipped. A show-config failure warns instead
# of silently disabling every remote leg.
builder_systems() {
  local config
  config=$(nix show-config 2>&1) || {
    echo "build.sh: 'nix show-config' failed, treating remote builders as absent:" >&2
    echo "$config" >&2
    return 0
  }
  # shellcheck disable=SC2013
  printf '%s\n' "$config" | sed -n 's/^builders = //p' | tr ' ' '\n' | while read -r TOKEN; do
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
  # Forced: nix outputs are read-only, so a re-run over an existing dist/
  # must replace, not fail (BSD cp cannot overwrite read-only files).
  cp -f "$EXPORT/dist-$SYSTEM" "$ROOT/dist/$(basename "$(readlink "$EXPORT/dist-$SYSTEM")")"
  BUILT+=("$SYSTEM")
done

if [ "$VERIFY" = true ]; then
  for SYSTEM in ${BUILT[@]+"${BUILT[@]}"}; do
    FILE="$ROOT/dist/$(basename "$(readlink "$EXPORT/dist-$SYSTEM")")"
    # Only foreign-OS binaries cannot run here (cross-arch macOS
    # binaries still run under Rosetta); verifying those is CI's job
    # on their native runners.
    case "$FILE" in
      *macos-*) [ "$(uname -s)" = Darwin ] || continue ;;
      *linux-*) [ "$(uname -s)" = Linux ] || continue ;;
    esac
    CHECK=$(mktemp -d)
    tar -xzf "$FILE" -C "$CHECK"
    # Glob must expand in command position: assignments store the
    # literal pattern, so capture it through echo instead.
    BIN=$(echo "$CHECK"/*/bin/wyrd)
    test -f "$BIN" && test -x "$BIN" || {
      echo "$FILE: no executable bin/wyrd" >&2
      exit 1
    }
    # Execution needs the binary's system libraries: a macOS binary without
    # macFUSE installed dies in dyld (exit 134), which is an environment gap,
    # not a broken binary. Check linkage after the structure check above and
    # run only when every linked library is present.
    if [ "$(uname -s)" = Darwin ]; then
      # Read every linkage line: stopping early would SIGPIPE otool and trip
      # pipefail, so the loop consumes all input and remembers the first gap.
      MISSING_LIB=""
      while read -r lib; do
        if [ ! -e "$lib" ] && [ -z "$MISSING_LIB" ]; then MISSING_LIB="$lib"; fi
      # shellcheck disable=SC2016: awk program, not shell expansion.
      done < <(otool -L "$BIN" | awk '$1 ~ /\.dylib/ {print $1}')
      if [ -n "$MISSING_LIB" ]; then
        echo "warning: $FILE not executed (missing system library $MISSING_LIB); structure checked only" >&2
        rm -rf "$CHECK"
        continue
      fi
    fi
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
