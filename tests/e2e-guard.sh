#!/usr/bin/env bash
# tests/e2e-guard.sh — wrapper-only entry enforcement for the e2e
# gates. Sourced (never executed) by the suite scripts both wrappers
# drive; it refuses direct invocation unless the caller carries the
# run token the wrapper minted. Pure bash, no harness, no side
# effects — safe to source anywhere, including --teardown-style
# modes that never run a suite.
#
# Why: a tests/alpha-microvm.sh invocation was once found running
# directly on the shared KVM host, bypassing
# nix/microvm/run-microvm.sh and therefore its flock. The lock
# serializes only callers that acquire it, so the direct run could
# mutate (or tear down) the shared VM fleet underneath a wrapped
# run. "Please remember to use the wrapper" is now this check.
#
# Mechanism: each wrapper mints a random per-run token, publishes it
# in the run's env file (which every suite script already sources),
# and hands it to its direct child in the environment. The guard
# compares the caller-supplied token against the published one. A
# matching token proves the process was launched by the wrapper that
# owns this run's state — an accidental direct invocation carries no
# token and dies here, before touching any fleet. Reading the token
# out of the env file and exporting it by hand is the explicit
# ownership token for deliberate debugging (or set
# WYRD_E2E_UNWRAPPED=1, which warns and proceeds).
#
# The env file is parsed, never sourced: sourcing it first would
# install the published token into this shell and make the comparison
# vacuous. Call e2e_require_wrapped BEFORE sourcing alpha-common.sh
# (which sources the env file itself).
#
# With WYRD_E2E_LOCK set (the microVM orchestrator: the wrapper
# passes its fixed host-global lock path), the wrapper's flock must
# additionally be held right now. A non-blocking acquire that
# succeeds means no wrapper is alive, so a stale token file from a
# dead or kept run cannot authorize a new suite. Lima sets no lock;
# the token alone guards its single-user instance.
e2e_require_wrapped() { # <env-file> <wrapper-command>
  local env_file="$1" wrapper="$2" published="" caller="${WYRD_E2E_TOKEN:-}"
  if [[ "${WYRD_E2E_UNWRAPPED:-}" == 1 ]]; then
    echo "warning: running unwrapped ($wrapper bypassed deliberately)" >&2
    return 0
  fi
  [[ -n "$caller" ]] || {
    echo "error: refuse direct execution: no run token in the environment" >&2
    echo "run through the wrapper instead: $wrapper" >&2
    echo "(deliberate debugging only: WYRD_E2E_UNWRAPPED=1)" >&2
    return 1
  }
  [[ -f "$env_file" ]] || {
    echo "error: refuse direct execution: no published token at $env_file" >&2
    echo "run through the wrapper instead: $wrapper" >&2
    return 1
  }
  # Parsed, never sourced (see header): the token is minted hex, so
  # %q emits it bare, but cut on the first '=' either way.
  published="$(grep -E '^WYRD_E2E_TOKEN=' "$env_file" | cut -d= -f2- | tail -n 1)"
  [[ -n "$published" && "$caller" == "$published" ]] || {
    echo "error: refuse direct execution: run token does not match $env_file" >&2
    echo "run through the wrapper instead: $wrapper" >&2
    return 1
  }
  if [[ -n "${WYRD_E2E_LOCK:-}" ]]; then
    command -v flock >/dev/null || {
      echo "error: cannot verify the wrapper lock (flock missing)" >&2
      return 1
    }
    # A successful non-blocking acquire means NOBODY holds the lock:
    # the wrapper is gone and this token is stale. Failure means a
    # wrapper is alive and holding it — the only authorized state.
    if flock -n "$WYRD_E2E_LOCK" true 2>/dev/null; then
      echo "error: refuse direct execution: no wrapper holds $WYRD_E2E_LOCK" >&2
      echo "run through the wrapper instead: $wrapper" >&2
      return 1
    fi
  fi
  return 0
}
