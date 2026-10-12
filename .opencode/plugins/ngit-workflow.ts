// .opencode/plugins/ngit-workflow.ts — typed façade over the ngit CLI.
//
// Spike scope: issue triage only. The tool applies exactly one type, one
// priority, and one release milestone in a single call and verifies the
// result, so agents stop re-deriving label ceremony (and closed sets) from
// `--help` output. Creation-time labels are unrepresentable: the tool takes
// no creation path, only triage of an existing issue.
//
// Design rules for this file:
// - Thin exec layer, pure logic. Everything testable without opencode or a
//   relay lives in the exported pure functions below; the tool definition
//   only wires them to `$` (Bun shell) and the tool schema. Tests import
//   the pure functions via .opencode/plugin-tests/ (that directory is NOT
//   scanned for plugins; only .opencode/plugins/ is).
// - Wrap, don't reimplement. ngit remains the client; this file parses its
//   `--json` stdout and enforces repo policy (closed label sets) on top.
// - Refuse loudly. Validation failures return `{ok: false}` without calling
//   ngit at all; ngit failures are reported with stdout/stderr, never
//   retried here.

import { type Plugin, tool } from "@opencode-ai/plugin"

export const TYPES = ["bug", "enhancement", "chore"] as const

export const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"] as const

// Closed milestone set. Source of truth is CONTRIBUTING.md ("The current
// milestone labels are"); update both together. Shipped alphas stay listed
// because their labels remain on history.
export const MILESTONES = [
  "release:v0.1.0-alpha",
  "release:v0.2.0-alpha",
  "release:v0.3.0-alpha",
  "release:v0.4",
  "release:v0.5",
  "release:v0.6",
  "release:v0.7",
  "release:v0.8",
  "release:v0.9.0-beta",
  "release:v1.0",
  "release:backlog",
] as const

export interface TriageInput {
  /** Issue nevent, hex id, or unique hex prefix. Never retype: capture it. */
  id: string
  type: string
  priority: string
  milestone: string
}

// IDs are interpolated into a shell command (escaped), so reject anything
// outside the shapes ngit accepts: bech32, hex, or #hex-prefix.
const ID_PATTERN = /^(nevent1[02-9ac-hj-np-z]+|#?[0-9a-fA-F]{8,64})$/

export function validateTriage(input: TriageInput): string[] {
  const errors: string[] = []
  if (!ID_PATTERN.test(input.id ?? "")) {
    errors.push(`id must be an nevent, hex id, or #hex-prefix (got ${JSON.stringify(input.id)})`)
  }
  if (!(TYPES as readonly string[]).includes(input.type)) {
    errors.push(`type must be one of ${TYPES.join(", ")} (got ${JSON.stringify(input.type)})`)
  }
  if (!(PRIORITIES as readonly string[]).includes(input.priority)) {
    errors.push(`priority must be one of ${PRIORITIES.join(", ")} (got ${JSON.stringify(input.priority)})`)
  }
  if (!(MILESTONES as readonly string[]).includes(input.milestone)) {
    errors.push(`milestone must be one of ${MILESTONES.join(", ")} (got ${JSON.stringify(input.milestone)})`)
  }
  return errors
}

// argv for `ngit issue label`, before shell escaping. One call carries all
// three categories: a triage is all-or-nothing, never a partial label set.
export function buildLabelArgv(input: TriageInput): string[] {
  return [
    "issue",
    "label",
    input.id,
    "--label",
    input.type,
    "--label",
    input.priority,
    "--label",
    input.milestone,
    "--json",
  ]
}

export function parseJsonDocument(stdout: string): { ok: boolean; value?: unknown; error?: string } {
  const trimmed = stdout.trim()
  if (!trimmed) return { ok: false, error: "ngit printed no JSON document on stdout" }
  try {
    return { ok: true, value: JSON.parse(trimmed) }
  } catch {
    return { ok: false, error: `ngit stdout is not a JSON document: ${trimmed.slice(0, 120)}` }
  }
}

// Confirm the verified view carries exactly the triaged set.
export function verifyLabels(view: unknown, input: TriageInput): string[] {
  const labels: unknown =
    typeof view === "object" && view !== null && "labels" in view
      ? (view as { labels: unknown }).labels
      : undefined
  if (!Array.isArray(labels)) return ["verified view carries no labels array"]
  const missing = [input.type, input.priority, input.milestone].filter(
    (want) => !labels.includes(want),
  )
  return missing.map((want) => `verified view is missing label ${want}`)
}

export const server: Plugin = async ({ $ }) => {
  return {
    tool: {
      ngit_issue_triage: tool({
        description:
          "Triage an ngit issue: apply exactly one type (bug|enhancement|chore), one priority (P0-P4), and one release milestone in a single call, then verify. Rejects unknown labels without calling ngit. Use instead of raw `ngit issue label` calls.",
        args: {
          id: tool.schema.string().describe("Issue nevent, hex id, or #hex-prefix"),
          type: tool.schema.string().describe("One of: bug, enhancement, chore"),
          priority: tool.schema.string().describe("One of: P0, P1, P2, P3, P4"),
          milestone: tool.schema
            .string()
            .describe("One release:* label, e.g. release:v0.3.0-alpha or release:backlog"),
        },
        async execute(args) {
          const input: TriageInput = {
            id: args.id,
            type: args.type,
            priority: args.priority,
            milestone: args.milestone,
          }
          const errors = validateTriage(input)
          if (errors.length > 0) {
            return JSON.stringify({ ok: false, errors })
          }
          const argv = buildLabelArgv(input)
          const escaped = argv.map((a) => $.escape(a)).join(" ")
          let labelOut: string
          try {
            labelOut = await $`ngit ${{ raw: escaped }}`.text()
          } catch (err) {
            return JSON.stringify({ ok: false, errors: [`ngit issue label failed: ${String(err)}`] })
          }
          const parsed = parseJsonDocument(labelOut)
          if (!parsed.ok) {
            return JSON.stringify({ ok: false, errors: [parsed.error] })
          }
          let viewOut: string
          try {
            const viewArgv = ["issue", "view", input.id, "--json", "--offline"]
            const viewEscaped = viewArgv.map((a) => $.escape(a)).join(" ")
            viewOut = await $`ngit ${{ raw: viewEscaped }}`.text()
          } catch (err) {
            return JSON.stringify({ ok: false, errors: [`verification view failed: ${String(err)}`] })
          }
          const viewParsed = parseJsonDocument(viewOut)
          if (!viewParsed.ok) {
            return JSON.stringify({ ok: false, errors: [viewParsed.error] })
          }
          const missing = verifyLabels(viewParsed.value, input)
          if (missing.length > 0) {
            return JSON.stringify({ ok: false, errors: missing })
          }
          return JSON.stringify({
            ok: true,
            id: input.id,
            labels: [input.type, input.priority, input.milestone],
          })
        },
      }),
    },
  }
}

export default server
