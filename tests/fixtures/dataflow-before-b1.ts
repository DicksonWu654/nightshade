import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, unlink, writeFile } from "node:fs/promises";

/** Load an isolated copy of the built interpreter with only its join import
 * rebound to the frozen prior implementation. Relative production imports
 * still resolve beside the original module; no production module or global
 * switch is mutated, and internal isolated views inherit the oracle join. */
export async function dataflowBeforeB1(): Promise<typeof import("../../src/dataflow/index.js")> {
  const original = new URL("../../src/dataflow/index.js", import.meta.url);
  const oracle = new URL("./common-constraints-before-b1.js", import.meta.url);
  const temporary = new URL(`./.before-b1-${randomUUID()}.mjs`, original);
  const source = await readFile(original, "utf8");
  const target = 'from "./common-constraints.js"';
  assert.equal(source.split(target).length, 2, "expected exactly one join import");
  await writeFile(temporary, source.replace(target, `from ${JSON.stringify(oracle.href)}`), { flag: "wx" });
  try { return await import(temporary.href) as typeof import("../../src/dataflow/index.js"); }
  finally { await unlink(temporary); }
}
