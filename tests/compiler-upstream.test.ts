import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths } from "./helpers.js";
import { AnalysisError } from "../src/model.js";

const revision = "b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad";
const upstream = process.env.COMPACT_SOURCE_TEST;
const compiler = process.env.COMPACTC_TEST;
const fixtures = ["commas/commas", "commas/more_commas", "commas/test", "multiconst/multiconst", "return/examples", "assert/example_one", "types/examples"];
const knownGaps: Record<string, string> = { "multiconst/multiconst": "loop-budget" };

for (const fixture of fixtures) test(`upstream language conformance: ${fixture}`, { skip: !upstream || !compiler ? "Requires pinned COMPACT_SOURCE_TEST and COMPACTC_TEST" : false }, () => {
  const checkout = resolve(upstream!);
  const head = spawnSync("git", ["-C", checkout, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 10000 });
  assert.equal(head.status, 0, head.stderr);
  assert.equal(head.stdout.trim(), revision);
  const relative = `examples/${fixture}.compact`;
  const pristine = spawnSync("git", ["-C", checkout, "show", `${revision}:${relative}`], { encoding: "utf8", timeout: 10000 });
  assert.equal(pristine.status, 0, pristine.stderr);
  const path = resolve(checkout, relative);
  assert.equal(readFileSync(path, "utf8"), pristine.stdout, "Qualification inputs must be unmodified upstream sources");
  const accepted = validateWithCompiler(compiler!, path, []);
  assert.equal(accepted.valid, true, accepted.error);
  if (knownGaps[fixture]) {
    assert.throws(() => new Program(path), (error: unknown) => error instanceof AnalysisError && error.diagnostic.code === knownGaps[fixture]);
    return;
  }
  const program = new Program(path);
  assert.ok(program.entries.length > 0);
  const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
  const instructions = new Dataflow(program).analyze();
  if (fixture === "types/examples") {
    // Native storage methods now resolve; the unchanged source next exposes
    // the bounded sequence-layout limit during analysis, not a front-end error.
    for (const facts of [reference, instructions]) {
      assert.equal(facts.diagnostics[0]?.code, "sequence-budget");
      assert.ok(facts.completedEntries.length < program.entries.length);
    }
    return;
  }
  assert.deepEqual(instructions.diagnostics, []);
  assert.deepEqual(reference.diagnostics, []);
  assert.deepEqual(instructions.completedEntries, program.entries);
  assert.deepEqual(semanticPaths(instructions), semanticPaths(reference));
});
