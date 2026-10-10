#!/usr/bin/env bash
# tests/step-grammar.sh — the shared --step comma-list grammar, sourced
# (never executed) by the harnesses that accept step selections. The rule is
# one everywhere: a comma list of integers in [lo,hi], no whitespace, no
# empty entries. Ranges differ per harness (Lima steps 1-6, microVM phases
# 1-12), so the range is a parameter and the callers name it in their own
# error text.
#
# step_max <lo> <hi> <selection>: print the highest entry. Exit 0 with the
# max on stdout, or 1 with nothing on stdout, when the selection is
# malformed. Callers own the verdict: harnesses die, wrappers exit 2. The
# selection is never echoed, and every expansion here is quoted, so a value
# like '*' cannot pathname-expand against the working directory first.
#
# Leading zeros canonicalize (`01` means 1): the entries are compared
# arithmetically in base 10 (the `10#` prefix keeps `08` from parsing as
# octal), so `01` and `1` are the same step. The previous per-harness
# regexes refused `01`; accepting it is a deliberate loosening, pinned by
# tests/test-step-grammar.sh. Shared by the Lima harness, the microVM
# runner, and the host orchestrator: one rule everywhere.
step_max() {
  local lo="$1" hi="$2" only="$3"
  local -a entries=()
  local entry max=0
  [[ "$only" != *[[:space:]]* ]] || return 1
  [[ ",$only," != *,,* ]] || return 1
  IFS=',' read -r -a entries <<< "$only"
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[0-9]+$ ]] || return 1
    (( 10#$entry >= lo && 10#$entry <= hi )) || return 1
    if (( 10#$entry > max )); then max=$((10#$entry)); fi
  done
  (( max > 0 )) || return 1
  printf '%s\n' "$max"
}
