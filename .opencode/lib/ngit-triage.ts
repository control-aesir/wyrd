// .opencode/lib/ngit-triage.ts: pure issue-triage logic for the
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

export type Category = "type" | "priority" | "milestone"

const CATEGORY_SETS: Record<Category, readonly string[]> = {
  type: TYPES,
  priority: PRIORITIES,
  milestone: MILESTONES,
}

function wanted(input: TriageInput): Record<Category, string> {
  return { type: input.type, priority: input.priority, milestone: input.milestone }
}

// Which closed category a label belongs to, if any. Labels outside the
// closed sets (stale scheme entries, local experiments) are not this
// tool's jurisdiction: never removed, never flagged.
export function categoryOf(label: string): Category | null {
  for (const category of Object.keys(CATEGORY_SETS) as Category[]) {
    if (CATEGORY_SETS[category].includes(label)) return category
  }
  return null
}

// Current labels in the closed sets that the new triage displaces. Passed
// as --remove-label in the same call, so re-triage cannot stack a stale
// release:* (or stale type/priority) next to the new one.
export function staleLabels(current: string[], input: TriageInput): string[] {
  const want = wanted(input)
  return current.filter((label) => {
    const category = categoryOf(label)
    return category !== null && label !== want[category]
  })
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
// three categories plus any displaced labels as --remove-label: a triage is
// all-or-nothing, never a partial label set and never a stacked one.
export function buildLabelArgv(input: TriageInput, removals: string[] = []): string[] {
  const argv = [
    "issue",
    "label",
    input.id,
    "--label",
    input.type,
    "--label",
    input.priority,
    "--label",
    input.milestone,
  ]
  for (const stale of removals) argv.push("--remove-label", stale)
  argv.push("--json")
  return argv
}

// Decide the single label call from an already-parsed current view. Returns
// errors (never a call) when the view cannot establish what the triage
// would displace: a view this tool cannot parse is a triage it must not
// write. Success returns the argv and the labels it displaces, so the
// reported result and the --remove-label set are one array, not two
// derivations that can drift. Gives the refusal paths a lib-level test seam.
export function planTriageCall(view: unknown, input: TriageInput): { argv: string[]; removed: string[] } | { errors: string[] } {
  const labels: unknown =
    typeof view === "object" && view !== null && "labels" in view
      ? (view as { labels: unknown }).labels
      : undefined
  if (!Array.isArray(labels)) {
    return {
      errors: [
        "current-labels view carries no usable labels array, refusing a blind write: run git fetch origin to refresh the local cache, then triage again",
      ],
    }
  }
  const current = labels.filter((l): l is string => typeof l === "string")
  const removed = staleLabels(current, input)
  return { argv: buildLabelArgv(input, removed), removed }
}

export type JsonDocument = { ok: true; value: unknown } | { ok: false; error: string }

// The reported success shape, built here (not in the plugin entry) so the
// offline suite pins exactly what a triage claims: the file the loader
// executes stays a thin façade over tested code.
export function triageSuccessResult(input: TriageInput, removed: string[]): {
  ok: true
  applied: true
  id: string
  labels: string[]
  removed: string[]
} {
  return {
    ok: true,
    applied: true,
    id: input.id,
    labels: [input.type, input.priority, input.milestone],
    removed,
  }
}

export function parseJsonDocument(stdout: string): JsonDocument {
  const trimmed = stdout.trim()
  if (!trimmed) return { ok: false, error: "ngit printed no JSON document on stdout" }
  try {
    return { ok: true, value: JSON.parse(trimmed) }
  } catch {
    return { ok: false, error: `ngit stdout is not a JSON document: ${trimmed.slice(0, 120)}` }
  }
}

// Confirm the verified view carries exactly the triaged set: every wanted
// label present, no displaced label left behind. A stacked view (two
// release:* labels, two types) is an error even when nothing is missing,
// because ngit label events are additive and ok:true must mean the end
// state is exactly one label per category.
export function verifyLabels(view: unknown, input: TriageInput): string[] {
  const labels: unknown =
    typeof view === "object" && view !== null && "labels" in view
      ? (view as { labels: unknown }).labels
      : undefined
  if (!Array.isArray(labels)) return ["verified view carries no labels array"]
  const want = wanted(input)
  const errors: string[] = []
  for (const category of Object.keys(want) as Category[]) {
    if (!labels.includes(want[category])) {
      errors.push(`verified view is missing label ${want[category]}`)
    }
    for (const label of labels) {
      if (typeof label === "string" && categoryOf(label) === category && label !== want[category]) {
        errors.push(`verified view stacks stale label ${label} next to ${want[category]}`)
      }
    }
  }
  return errors
}
