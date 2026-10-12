// .opencode/lib/ngit-triage.ts — pure issue-triage logic for the
// ngit-workflow plugin. Deliberately NOT under .opencode/plugins/:
// opencode loads every module there as a plugin and treats each export
// as a plugin factory, so helper exports (especially the const arrays)
// would abort loading with "Plugin export is not a function". This
// module is imported by the entry without re-exporting anything, and
// imported directly by the offline deno tests.

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
