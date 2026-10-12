// Offline tests for the ngit-workflow plugin's pure logic. Run:
//   devenv shell -- deno test --no-check --import-map=.opencode/plugin-tests/import-map.json .opencode/plugin-tests/
//
// --no-check: the "@opencode-ai/plugin" import resolves to the local stub,
// which carries runtime shape only. Full typechecking of the plugin file
// happens under opencode (bun install provides the real SDK).
// No jsr/npm imports: plain Deno.test asserts, runnable with no network.

import {
  buildLabelArgv,
  parseJsonDocument,
  validateTriage,
  verifyLabels,
  type TriageInput,
} from "../plugins/ngit-workflow.ts"

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assert failed: ${msg}`)
}

const GOOD: TriageInput = {
  id: "nevent1qqsqp8pknwk97099xgpeut2s7pkh7k87knl9s587znlkaf40tcr0tqqpz9mhxue69uhkwunpwdczuap49eehgd8jk0c",
  type: "chore",
  priority: "P3",
  milestone: "release:v0.3.0-alpha",
}

Deno.test("valid triage passes with no errors", () => {
  assert(validateTriage(GOOD).length === 0, JSON.stringify(validateTriage(GOOD)))
})

Deno.test("backlog milestone is accepted", () => {
  assert(
    validateTriage({ ...GOOD, milestone: "release:backlog" }).length === 0,
    "backlog must be a valid milestone",
  )
})

Deno.test("unknown type, priority, and milestone are each rejected", () => {
  const errors = validateTriage({ id: GOOD.id, type: "docs", priority: "P9", milestone: "release:v9" })
  assert(errors.length === 3, `expected 3 errors, got ${JSON.stringify(errors)}`)
  assert(errors.some((e) => e.includes("bug, enhancement, chore")), "type error names the closed set")
  assert(errors.some((e) => e.includes("P0")), "priority error names the closed set")
  assert(errors.some((e) => e.includes("release:backlog")), "milestone error names the closed set")
})

Deno.test("lowercase priority is rejected (case is preserved, never normalized)", () => {
  const errors = validateTriage({ ...GOOD, priority: "p3" })
  assert(errors.length === 1, "p3 must fail: triage labels preserve case via ngit issue label")
})

Deno.test("empty and shell-metachar ids are rejected before any ngit call", () => {
  for (const id of ["", "abc def", "nevent1abc;rm -rf", "nevent1abc$(x)", "#zzzz"]) {
    const errors = validateTriage({ ...GOOD, id })
    assert(errors.length > 0 && errors[0].startsWith("id must be"), `id ${JSON.stringify(id)} must fail`)
  }
})

Deno.test("hex and #prefix ids are accepted", () => {
  assert(validateTriage({ ...GOOD, id: "009c369bac5f3ca532039e2d50f06d7f58feb4fe5850fe14ff6ea6af5e06f580" }).length === 0, "hex")
  assert(validateTriage({ ...GOOD, id: "#009c369b" }).length === 0, "#prefix")
})

Deno.test("label argv carries all three categories in one call", () => {
  assert(
    JSON.stringify(buildLabelArgv(GOOD)) ===
      JSON.stringify([
        "issue", "label", GOOD.id,
        "--label", "chore",
        "--label", "P3",
        "--label", "release:v0.3.0-alpha",
        "--json",
      ]),
    "exact argv",
  )
})

Deno.test("parseJsonDocument accepts a document, refuses noise", () => {
  const good = parseJsonDocument('{"action":"labeled"}\n')
  assert(good.ok && typeof good.value === "object", "valid JSON passes")
  assert(!parseJsonDocument("").ok, "empty fails")
  assert(!parseJsonDocument("Published 1 event to 4 relays").ok, "relay chatter fails loudly")
})

Deno.test("verifyLabels confirms the triaged set, reports gaps", () => {
  assert(
    verifyLabels({ labels: ["chore", "P3", "release:v0.3.0-alpha", "extra"] }, GOOD).length === 0,
    "superset verifies",
  )
  const missing = verifyLabels({ labels: ["chore"] }, GOOD)
  assert(
    missing.length === 2 && missing.some((m) => m.includes("P3")),
    `gaps reported: ${JSON.stringify(missing)}`,
  )
  assert(verifyLabels({}, GOOD).length === 1, "missing labels array fails loudly")
})
