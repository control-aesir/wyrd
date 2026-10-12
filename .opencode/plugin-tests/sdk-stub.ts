// Test-only stub for "@opencode-ai/plugin", wired via import-map.json so
// `deno test` runs the plugin's pure logic fully offline. It provides just
// enough runtime shape for the module top level to execute: `tool()` must
// run at import time (tool definitions are built on import) and
// `tool.schema.string()` must return something. The pure functions under
// test never touch either. Full typechecking happens under opencode's own
// bun install; tests run with --no-check (see header of triage_test.ts).
export function tool<T>(input: T): T {
  return input
}

// oxlint-disable-next-line no-explicit-any
(tool as any).schema = {
  string: () => ({
    describe: () => ({ _stub: "string" }),
  }),
}
