// .opencode/plugins/ngit-workflow.ts: typed façade over the ngit CLI.
//
// Spike scope: issue triage only. The tool applies exactly one type, one
// priority, and one release milestone in a single call and verifies the
// result, so agents stop re-deriving label ceremony (and closed sets) from
// `--help` output. Creation-time labels are unrepresentable: the tool takes
// no creation path, only triage of an existing issue.
//
// Loader contract (opencode ≥1.16, verified against the failure it reports):
// the loader treats EVERY export of this module as a plugin factory and
// aborts the whole module with "Plugin export is not a function" on the
// first non-function export. So this entry exports exactly one value (the
// plugin function as default) and nothing else. Pure logic lives in
// ../lib/ngit-triage.ts (imported, never re-exported); `export type`
// declarations are fine (erased before the loader sees them). Do not add
// exported consts, arrays, or helpers here, however testable they look:
// the deno tests import them from ../lib/ instead.

import { type Plugin, tool } from "@opencode-ai/plugin"
import {
  buildLabelArgv,
  parseJsonDocument,
  staleLabels,
  validateTriage,
  verifyLabels,
} from "../lib/ngit-triage.js"
import type { TriageInput } from "../lib/ngit-triage.js"

export default (async ({ $ }) => {
  return {
    tool: {
      ngit_issue_triage: tool({
        description:
          "Triage an ngit issue: apply exactly one type (bug|enhancement|chore), one priority (P0-P4), and one release milestone in a single call, removing displaced labels in the same call, then verify the end state. Rejects unknown labels without calling ngit. Use instead of raw `ngit issue label` calls.",
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
            return JSON.stringify({ ok: false, applied: false, errors })
          }
          const run = async (argv: string[]): Promise<string> => {
            const escaped = argv.map((a) => $.escape(a)).join(" ")
            return await $`ngit ${{ raw: escaped }}`.text()
          }
          // Read current labels first: ngit label events are additive, so
          // the call below must also remove what the new triage displaces.
          // A view this tool cannot read is a triage it must not write.
          let currentOut: string
          try {
            currentOut = await run(["issue", "view", input.id, "--json", "--offline"])
          } catch (err) {
            return JSON.stringify({
              ok: false,
              applied: false,
              errors: [`current-labels view failed, refusing a blind write: ${String(err)}`],
            })
          }
          const currentParsed = parseJsonDocument(currentOut)
          if (!currentParsed.ok) {
            return JSON.stringify({ ok: false, applied: false, errors: [currentParsed.error] })
          }
          const currentView = currentParsed.value as { labels?: unknown }
          const currentLabels = Array.isArray(currentView.labels)
            ? currentView.labels.filter((l): l is string => typeof l === "string")
            : []
          const removals = staleLabels(currentLabels, input)
          let labelOut: string
          try {
            labelOut = await run(buildLabelArgv(input, removals))
          } catch (err) {
            return JSON.stringify({ ok: false, applied: false, errors: [`ngit issue label failed: ${String(err)}`] })
          }
          const parsed = parseJsonDocument(labelOut)
          if (!parsed.ok) {
            // The call may have landed while stdout carried relay chatter
            // instead of the JSON document: applied, but unverifiable here.
            // Resubmitting would stack a duplicate, so the signal is split.
            return JSON.stringify({ ok: false, applied: true, errors: [`label applied but unverifiable: ${parsed.error}`] })
          }
          let viewOut: string
          try {
            viewOut = await run(["issue", "view", input.id, "--json", "--offline"])
          } catch (err) {
            return JSON.stringify({ ok: false, applied: true, errors: [`verification view failed: ${String(err)}`] })
          }
          const viewParsed = parseJsonDocument(viewOut)
          if (!viewParsed.ok) {
            return JSON.stringify({ ok: false, applied: true, errors: [viewParsed.error] })
          }
          const gaps = verifyLabels(viewParsed.value, input)
          if (gaps.length > 0) {
            return JSON.stringify({ ok: false, applied: true, errors: gaps })
          }
          return JSON.stringify({
            ok: true,
            applied: true,
            id: input.id,
            labels: [input.type, input.priority, input.milestone],
            removed: removals,
          })
        },
      }),
    },
  }
}) satisfies Plugin
