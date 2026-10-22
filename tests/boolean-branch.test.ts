import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { sourceObservations } from "../src/analysis/source-observations.js";
import { redundantBooleanBranch as rule } from "../src/detectors/informational.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function checked(source: string, negated: boolean[], inspect?: (program: Program) => void): void {
  withFiles({ "main.compact": "import CompactStandardLibrary;\n" + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), sourceFacts = sourceObservations(program);
    assert.equal(sourceFacts.complete, true);
    assert.deepEqual(sourceFacts.observations.filter(item => item.kind === rule.id).map(item => item.metadata.negated), negated);
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.equal(scan.findings.length, negated.length);
    for (const finding of scan.findings) {
      assert.equal(finding.severity, "info"); assert.equal(finding.confidence, "high");
      assert.equal(finding.metadata.measuredCost, "not-claimed");
    }
    inspect?.(program);
  });
}

test("opposite literal-only Boolean returns report both polarities", () => checked(`
export circuit direct(flag: Boolean): Boolean {
  if (disclose(flag)) { return true; } else { return false; }
}
export circuit inverse(flag: Boolean): Boolean {
  if (disclose(flag)) { { return disclose(false as Boolean); } } else { return true; }
}`, [false, true]));

test("corrected direct returns and branches with other work stay quiet", () => checked(`
ledger count: Counter;
export circuit direct(flag: Boolean): Boolean { return disclose(flag); }
export circuit inverse(flag: Boolean): Boolean { return !disclose(flag); }
export circuit effects(flag: Boolean): Boolean {
  if (disclose(flag)) { count.increment(1); return true; } else { return false; }
}
export circuit guarded(flag: Boolean): Boolean {
  if (disclose(flag)) { assert(flag,"guard"); return true; } else { return false; }
}
export circuit same(flag: Boolean): Boolean {
  if (disclose(flag)) { return true; } else { return true; }
}
export circuit sequence(flag: Boolean): Boolean {
  if (disclose(flag)) { return (count.increment(1), true); } else { return false; }
}
export circuit tail(flag: Boolean): Boolean { if (disclose(flag)) { return true; } return false; }
`, []));

test("known conditions, dead branches and comparisons returning a computed result are excluded", () => checked(`
export circuit fixed(): Boolean { if (true) { return true; } else { return false; } }
export circuit rejected(flag: Boolean): Boolean {
  assert(false,"reject"); if (disclose(flag)) { return true; } else { return false; }
}
export circuit computed(flag: Boolean): Boolean {
  if (disclose(flag)) { return disclose(flag); } else { return false; }
}`, []));

test("physical generic claims intersect and root-local private checker APIs remain lintable", () => checked(`
circuit checker<#N>(flag: Boolean): Boolean {
  if (N == 0 || disclose(flag)) { return true; } else { return false; }
}
circuit privateChecker(flag: Boolean): Boolean {
  if (disclose(flag)) { return true; } else { return false; }
}
export circuit first(flag: Boolean): Boolean { return checker<0>(flag); }
export circuit second(flag: Boolean): Boolean { return checker<1>(flag); }
`, [false]));

test("condition effects and constraints survive in both engines and cache modes", () => checked(`
ledger count: Counter;
circuit checked(flag: Boolean): Boolean { assert(flag,"required"); count.increment(1); return disclose(flag); }
export circuit entry(flag: Boolean): Boolean {
  if (checked(flag)) { return true; } else { return false; }
}`, [false], program => {
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.equal(rule.run(facts).length, 1);
    const effects = { assertions: facts.assertionReaches, writes: facts.paths.map(path => path.writes) };
    baseline ??= effects; assert.deepEqual(effects, baseline);
    assert.ok(facts.assertionReaches.length > 0); assert.ok(facts.paths.some(path => path.writes.length > 0));
  }
}));

test("branch-shape work exhaustion cannot certify an empty source result", () => checked(`
export circuit entry(flag: Boolean): Boolean { if (disclose(flag)) { return true; } else { return false; } }
`, [false], program => {
  const full = sourceObservations(program);
  assert.deepEqual(sourceObservations(program, full.work), full);
  const exhausted = sourceObservations(program, full.work - 1);
  assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
}));
