#!/usr/bin/env bash
# lima/provision.sh — runs inside the guest, idempotent. Imports the
# host-built wyrd closure and installs the script tools from the pinned
# nixpkgs (binary cache substitutes; nothing compiles).
set -euo pipefail

# shellcheck source=/dev/null
source /tmp/lima/e2e-env.sh

if [[ ! -x "$WYRD_BIN" ]]; then
  echo "provision: importing wyrd closure into the guest store"
  sudo nix-store --import < /tmp/lima/wyrd-closure.nar
fi
"$WYRD_BIN" --version

need() { command -v "$1" >/dev/null 2>&1; }
FLAKE="github:NixOS/nixpkgs/$NIXPKGS_REV"
need python3 || nix profile add "$FLAKE#python3Minimal"
need jq || nix profile add "$FLAKE#jq"
need nostr-rs-relay || nix profile add "$FLAKE#nostr-rs-relay"
# iproute2's tc: step 6 throttles loopback IP traffic to widen the
# owner-mid-transfer window (see tests/alpha-lima.sh).
need tc || nix profile add "$FLAKE#iproute2"

[[ -r /dev/fuse && -w /dev/fuse ]] || { echo "provision: /dev/fuse is not usable" >&2; exit 1; }
command -v fusermount3 >/dev/null || { echo "provision: fusermount3 missing" >&2; exit 1; }
echo "provision: ready"
