// Offline tests for the ngit-triage pure logic (../lib/ngit-triage.ts).
// Run: devenv shell -- deno test --allow-read .opencode/plugin-tests/
// Plain Deno.test asserts, no jsr/npm imports: runnable with no network
// (--allow-read covers the CONTRIBUTING.md parity test only).
// The lib module imports nothing, so no stubs or import maps are needed;
// full typechecking of the plugin entry happens under opencode's bun
// install, which provides the real SDK.

import {
  buildLabelArgv,
  categoryOf,
  MILESTONES,
  parseJsonDocument,
  planTriageCall,
  staleLabels,
  validateTriage,
  verifyLabels,
  type TriageInput,
} from "../lib/ngit-triage.ts"

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

Deno.test("staleLabels finds displaced closed-set labels, ignores the rest", () => {
  assert(
    JSON.stringify(staleLabels(["bug", "P2", "release:v0.2.0-alpha"], GOOD)) ===
      JSON.stringify(["bug", "P2", "release:v0.2.0-alpha"]),
    "all three displaced",
  )
  assert(
    JSON.stringify(staleLabels(["chore", "P3", "release:v0.3.0-alpha"], GOOD)) === JSON.stringify([]),
    "identical set has no stale labels",
  )
  assert(
    JSON.stringify(staleLabels(["release:alpha", "chore", "P3", "release:v0.3.0-alpha"], GOOD)) ===
      JSON.stringify([]),
    "labels outside the closed sets are not this tool's jurisdiction",
  )
})

Deno.test("planTriageCall builds the removal-carrying argv from a stacked view", () => {
  const planned = planTriageCall({ labels: ["bug", "P3", "release:v0.2.0-alpha"] }, GOOD)
  assert(
    "argv" in planned &&
      JSON.stringify(planned.argv) ===
        JSON.stringify([
          "issue", "label", GOOD.id,
          "--label", "chore",
          "--label", "P3",
          "--label", "release:v0.3.0-alpha",
          "--remove-label", "bug",
          "--remove-label", "release:v0.2.0-alpha",
          "--json",
        ]) &&
      JSON.stringify(planned.removed) === JSON.stringify(["bug", "release:v0.2.0-alpha"]),
    JSON.stringify(planned),
  )
})

Deno.test("planTriageCall refuses views it cannot establish removals from", () => {
  for (const view of [{}, { labels: "chore" }, { labels: null }, null]) {
    const planned = planTriageCall(view, GOOD)
    assert(
      "errors" in planned && planned.errors.some((e) => e.includes("refusing a blind write")),
      `view ${JSON.stringify(view)} must refuse: ${JSON.stringify(planned)}`,
    )
  }
})

Deno.test("parseJsonDocument accepts a document, refuses noise", () => {
  const good = parseJsonDocument('{"action":"labeled"}\n')
  assert(good.ok && typeof good.value === "object", "valid JSON passes")
  assert(!parseJsonDocument("").ok, "empty fails")
  assert(!parseJsonDocument("Published 1 event to 4 relays").ok, "relay chatter fails loudly")
})

Deno.test("verifyLabels confirms the exact set, reports gaps and surplus", () => {
  assert(
    verifyLabels({ labels: ["chore", "P3", "release:v0.3.0-alpha"] }, GOOD).length === 0,
    "exact set verifies",
  )
  assert(
    verifyLabels({ labels: ["chore", "P3", "release:v0.3.0-alpha", "release:alpha"] }, GOOD).length === 0,
    "unknown labels outside the closed sets are ignored",
  )
  const stacked = verifyLabels({ labels: ["chore", "P3", "release:v0.3.0-alpha", "release:v0.2.0-alpha"] }, GOOD)
  assert(
    stacked.length === 1 && stacked[0].includes("release:v0.2.0-alpha") && stacked[0].includes("stacks"),
    `stacked milestone must fail: ${JSON.stringify(stacked)}`,
  )
  const missing = verifyLabels({ labels: ["chore"] }, GOOD)
  assert(
    missing.length === 2 && missing.some((m) => m.includes("P3")),
    `gaps reported: ${JSON.stringify(missing)}`,
  )
  assert(
    JSON.stringify(verifyLabels({ labels: [] }, GOOD).sort()) ===
      JSON.stringify([
        "verified view is missing label chore",
        "verified view is missing label P3",
        "verified view is missing label release:v0.3.0-alpha",
      ].sort()),
    "empty array reports three missing, nothing else",
  )
  assert(verifyLabels({}, GOOD).length === 1, "missing labels array fails loudly")
})

Deno.test("categoryOf classifies closed sets, rejects outsiders", () => {
  assert(categoryOf("bug") === "type", "bug is type")
  assert(categoryOf("P1") === "priority", "P1 is priority")
  assert(categoryOf("release:backlog") === "milestone", "backlog is milestone")
  assert(categoryOf("release:alpha") === null, "retired scheme entry is outside")
  assert(categoryOf("docs") === null, "scope word is outside")
})

Deno.test("MILESTONES matches the CONTRIBUTING.md milestone list", async () => {
  const doc = await Deno.readTextFile(new URL("../../CONTRIBUTING.md", import.meta.url))
  const section = doc.split("The current milestone labels are:")[1].split("Do not stack")[0]
  const found = [...section.matchAll(/`(release:(?!\*)[^`]+)`/g)].map((m) => m[1]).sort()
  assert(
    JSON.stringify(found) === JSON.stringify([...MILESTONES].sort()),
    `drift between code and docs: ${JSON.stringify(found)}`,
  )
})
