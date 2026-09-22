// page/check.ts — pin marketing claims to their backing docs sections.
//
// The page stays hand-written and docs stay the source of truth for facts.
// This checker links the two: each slot in page/map.json cites the docs
// sections that back it, and map.lock.json pins those sections by hash.
// When a cited section drifts, the check fails and a human re-reads the
// slot before re-pinning. Copy rules (mustContain/forbids) catch the
// present-tense-overclaim class of bug; they never rewrite copy.
//
// Verify:  deno run --allow-read page/check.ts
// Re-pin:   deno run --allow-read --allow-write page/check.ts --update

interface Back {
  file: string;
  heading: string;
}
interface Slot {
  slot: string;
  backs: Back[];
  mustContain: string[];
  forbids: string[];
}
interface MapFile {
  version: number;
  page: string;
  lock: string;
  slots: Slot[];
}
interface LockFile {
  version: number;
  hashes: Record<string, string>;
}

const root = decodeURIComponent(new URL("../", import.meta.url).pathname);
const read = (rel: string): Promise<string> => Deno.readTextFile(root + rel);

// Extract a markdown section by exact heading line. Ends at the next
// heading of equal or higher level, or end of file.
function section(text: string, heading: string): string | null {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.trim() === heading.trim());
  if (start < 0) return null;
  const level = heading.match(/^#+/)![0].length;
  const end = lines.findIndex(
    (l, n) => n > start && new RegExp(`^#{1,${level}}\\s`).test(l.trim()),
  );
  return lines
    .slice(start, end < 0 ? undefined : end)
    .map((l) => l.replace(/[ \t]+$/, ""))
    .join("\n")
    .replace(/^\n+|\n+$/g, "");
}

async function sha256(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function slotBody(page: string, name: string): string | null {
  const m = page.match(
    new RegExp(`<!-- slot:${name} -->\\n([\\s\\S]*?)\\n?\\s*<!-- /slot:${name} -->`),
  );
  return m ? m[1] : null;
}

const map: MapFile = JSON.parse(await read("page/map.json"));
const page = await read(map.page);
const update = Deno.args.includes("--update");
let lock: LockFile = { version: 1, hashes: {} };
if (!update) {
  try {
    lock = JSON.parse(await read(map.lock));
  } catch {
    console.error(`missing ${map.lock}; run with --update to pin after review`);
    Deno.exit(1);
  }
}

const failures: string[] = [];
for (const s of map.slots) {
  const body = slotBody(page, s.slot);
  if (body === null) {
    failures.push(`slot markers missing for "${s.slot}" in ${map.page}`);
    continue;
  }
  for (const want of s.mustContain) {
    if (!body.includes(want)) failures.push(`"${s.slot}" no longer says ${JSON.stringify(want)}`);
  }
  for (const ban of s.forbids) {
    if (body.toLowerCase().includes(ban.toLowerCase())) {
      failures.push(`"${s.slot}" contains forbidden phrase ${JSON.stringify(ban)}`);
    }
  }
  for (let n = 0; n < s.backs.length; n++) {
    const back = s.backs[n];
    const doc = await read(back.file).catch(() => null);
    if (doc === null) {
      failures.push(`backing file missing: ${back.file} (slot "${s.slot}")`);
      continue;
    }
    const text = section(doc, back.heading);
    if (text === null) {
      failures.push(`heading ${JSON.stringify(back.heading)} not found in ${back.file}`);
      continue;
    }
    const key = `${s.slot}#${n}`;
    const hash = await sha256(text);
    if (update) {
      lock.hashes[key] = hash;
    } else if (lock.hashes[key] !== hash) {
      failures.push(
        `drift: ${back.file} ${JSON.stringify(back.heading)} changed under slot "${s.slot}" — re-read the slot, then re-pin with --update`,
      );
    }
  }
}

if (update) {
  await Deno.writeTextFile(root + map.lock, JSON.stringify(lock, null, 2) + "\n");
  console.log(`pinned ${Object.keys(lock.hashes).length} backing sections to ${map.lock}`);
  Deno.exit(0);
}
if (failures.length > 0) {
  for (const f of failures) console.error(`page-check: ${f}`);
  Deno.exit(1);
}
console.log(`page-check: ${map.slots.length} slots pinned, copy rules hold`);
