import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, resolvePolicies, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { observePublicScalar } from "../src/analysis/public-scalar-observation.js";
import { observeRules } from "../src/analysis/rule-observations.js";
import { publicScalarFindings, publishedDigestGeneratorScalarReview as rule } from "../src/detectors/public-scalar.js";
import { PUBLIC_SCALAR_TARGETS, publicScalarScope } from "../src/semantic/public-scalar-targets.js";
import { withFiles } from "./helpers.js";

const positive = readFileSync("tests/corpus/synthetic-regressions/privacy16/account-key-domain/positive.compact", "utf8");
test("labelled no-entrypoint scans do not reserve unused scalar entry observations", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; pure circuit helper(): Field { return 1 as Field; }" }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const observation = observePublicScalar(program, rule, { maxSteps: 1, maxValues: 1 });
    assert.deepEqual(observation.diagnostics, []); assert.deepEqual(observation.coverage, []);
    assert.equal(observation.work.metrics.steps, 0); assert.equal(observation.work.metrics.abstractValues, 0);
    const report = scanFile(file, { detectors: [rule.id], maxSteps: 1, maxValues: 1 });
    assert.equal(report.status, "complete"); assert.deepEqual(report.coverage.noEntrypointRoots, [file]);
    assert.ok(report.diagnostics.some(issue => issue.code === "no-entrypoints-analyzed"));
  });
});
function flow(program: Program, engine: "instructions" | "expressions", cached: boolean, steps = 40000, values = 50000) {
  return new Dataflow(program, steps, 256, values, engine, cached, cached, "equivalent-states", false, true,
    "witness", false, false, false, true, false, false, true, false, false, false, PUBLIC_SCALAR_TARGETS);
}
function fixture(run: (program: Program) => void, text = positive) {
  withFiles({ "main.compact": text }, directory => run(new Program(resolve(directory, "main.compact"), [], undefined, undefined, 2, "0.34.0")));
}

for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
  test(`production preparation and matcher aggregation equals direct carried deltas ${engine}/${cached}`, () => fixture(program => {
    let captured: AnalysisFacts | undefined, sourceMetrics: AnalysisFacts["metrics"] | undefined;
    const observed = observePublicScalar(program, { ...rule, run(facts) {
      captured = facts; sourceMetrics = { ...facts.metrics }; return rule.run(facts);
    } }, {}, new Set(program.entries), { engine, cached });
    assert.deepEqual(observed.diagnostics, []); assert.equal(observed.findings.length, 1);
    const evidence = captured!.publicScalarEvidence!;
    assert.ok(captured!.metrics.steps > sourceMetrics!.steps);
    assert.ok(captured!.metrics.abstractValues > sourceMetrics!.abstractValues);
    const prepSteps = 40000 - evidence.maxSteps, prepValues = 50000 - evidence.maxValues;
    assert.ok(prepSteps > 0); assert.ok(prepValues > 0);
    assert.equal(observed.work.metrics.steps, captured!.metrics.steps + prepSteps);
    assert.equal(observed.work.metrics.abstractValues, captured!.metrics.abstractValues + prepValues);
    const direct = flow(program, engine, cached, evidence.maxSteps, evidence.maxValues).analyzeSubset(program.entries);
    assert.deepEqual(direct.metrics, sourceMetrics);
    assert.deepEqual(rule.run(direct), observed.findings);
    assert.deepEqual(direct.metrics, captured!.metrics);
    assert.equal(direct.publicScalarEvidence!.entrySteps.get(program.entries[0]), direct.metrics.steps);
    const ordinary = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
    assert.equal(ordinary.publicScalarEvidence, undefined);
    assert.deepEqual(publicScalarFindings(ordinary), []); assert.ok(ordinary.diagnostics.some(issue => issue.code === "public-scalar-evidence"));
  }));

  test(`matching exhaustion retains exact spent work and values without reanalysis ${engine}/${cached}`, () => fixture(program => {
    for (const kind of ["steps", "values"] as const) {
      const facts = flow(program, engine, cached).analyze(); const before = { ...facts.metrics };
      if (kind === "steps") facts.publicScalarEvidence!.maxSteps = facts.publicScalarEvidence!.entrySteps.get(program.entries[0])! + 1;
      else facts.publicScalarEvidence!.maxValues = before.abstractValues + 1;
      assert.deepEqual(publicScalarFindings(facts, 200000), []);
      assert.ok(facts.diagnostics.some(issue => issue.code === "public-scalar-budget"));
      assert.ok(facts.metrics.steps > before.steps || facts.metrics.abstractValues > before.abstractValues);
      assert.equal(facts.metrics.sources, before.sources); assert.equal(facts.metrics.paths, before.paths);
      if (kind === "steps") assert.ok(facts.metrics.steps > facts.publicScalarEvidence!.maxSteps);
      else assert.ok(facts.metrics.abstractValues > facts.publicScalarEvidence!.maxValues);
      const spent = { ...facts.metrics };
      assert.deepEqual(rule.run(facts), []); assert.deepEqual(facts.metrics, spent, "Exhausted native facts are refused without matching retries");
    }
  }));
}

test("production low limits include preparation and exhausted matcher metrics", () => fixture(program => {
  const measured = observePublicScalar(program, rule, {}, new Set(program.entries));
  assert.deepEqual(measured.diagnostics, []);
  for (const options of [{ maxSteps: 1 }, { maxValues: 1 }, { maxSteps: measured.work.metrics.steps - 1 }, { maxValues: measured.work.metrics.abstractValues - 1 }]) {
    const observed = observePublicScalar(program, rule, options, new Set(program.entries));
    assert.deepEqual(observed.findings, []); assert.ok(observed.diagnostics.some(issue => issue.code.includes("budget")));
    assert.ok(observed.work.metrics.steps > 0 || observed.work.metrics.abstractValues > 0);
    if (options.maxSteps !== undefined) assert.ok(observed.work.metrics.steps > options.maxSteps);
    if (options.maxValues !== undefined) assert.ok(observed.work.metrics.abstractValues > options.maxValues);
  }
  const routed = observeRules(program, [rule], resolvePolicies(program, {}), {}, new Set(program.entries));
  assert.deepEqual(routed.findings, measured.findings); assert.deepEqual(routed.work[0].metrics, measured.work.metrics);
}));

test("baseline refusal, missing carrier and metered canonical scope never provide clean applicable facts", () => fixture(program => {
  const incomplete = observePublicScalar(program, rule, {}, new Set());
  assert.deepEqual(incomplete.findings, []); assert.ok(incomplete.diagnostics.some(issue => issue.code === "public-scalar-evidence"));
  const facts = flow(program, "instructions", true).analyze(); delete facts.publicScalarEvidence;
  assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.some(issue => issue.code === "public-scalar-evidence"));
  let steps = 0, values = 0;
  const scope = publicScalarScope(program, program.entries[0], 20000, (work, retain) => { steps += work; values += retain; return steps <= 1 && values <= 8; });
  assert.equal(scope.complete, false); assert.equal(scope.unavailable, "budget"); assert.ok(steps > 0 && values > 0);
}));

test("per-entry source spent steps survive resets and late writes invalidate point identity", () => fixture(program => {
  const facts = flow(program, "instructions", true).analyze();
  assert.equal(facts.publicScalarEvidence!.entrySteps.size, 2);
  assert.equal([...facts.publicScalarEvidence!.entrySteps.values()].reduce((sum, value) => sum + value, 0), facts.metrics.steps);
  const findings = rule.run(facts); assert.equal(findings.length, 1);
  assert.equal(findings[0].metadata.entry, "register");
  assert.equal([...facts.publicScalarEvidence!.entrySteps.values()].reduce((sum, value) => sum + value, 0), facts.metrics.steps);
}, positive + positive.slice(positive.indexOf("export circuit register")).replace("register", "overwritten").replace("encryptionPublicKey = disclose(derivePk(secret));", "encryptionPublicKey = disclose(derivePk(secret)); encryptionPublicKey = default<JubjubPoint>;")));

test("multi-entry inventory value refusal retains every unavailable coverage row", () => fixture(program => {
  const observed = observePublicScalar(program, rule, { maxValues: 1 }, new Set(program.entries));
  assert.deepEqual(observed.findings, []);
  assert.equal(observed.coverage.length, program.entries.length);
  assert.deepEqual(observed.coverage.map(row => row.entry), program.entries);
  assert.ok(observed.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable" && row.diagnosticCodes.includes("public-scalar-budget")));
  assert.equal(observed.diagnostics.length, program.entries.length);
  assert.ok(observed.work.metrics.abstractValues > 1);
}, positive + "\nexport circuit idle(): Field { return 0 as Field; }"));

test("scope retention charges every pending call edge including a repeated target", () => fixture(program => {
  let steps = 0, values = 0;
  const scope = publicScalarScope(program, program.entries[0], 20000, (work, retain) => { steps += work; values += retain; return true; });
  assert.equal(scope.complete, true); assert.equal(scope.applicable, false);
  // Four unique visited circuits and four pushed edges; shared is visited once
  // but its second incoming edge must retain a pending slot too.
  assert.equal(values, 5 + 4 * 2 + 4 * 2);
  assert.equal(steps, scope.work);
}, `pure circuit shared(): Field { return 1 as Field; }
pure circuit first(): Field { return shared(); }
pure circuit second(): Field { return shared(); }
export circuit entry(): Field { return first() + second(); }`));

test("direct initial retention refusal carries original limits and never reruns matching", () => fixture(program => {
  const facts = flow(program, "instructions", true, 40000, 1).analyze();
  assert.ok(facts.publicScalarEvidence); assert.equal(facts.publicScalarEvidence.maxValues, 1);
  assert.equal(facts.publicScalarEvidence.entrySteps.size, program.entries.length);
  assert.deepEqual(facts.completedEntries, []);
  const spent = { ...facts.metrics };
  assert.deepEqual(rule.run(facts), []); assert.deepEqual(facts.metrics, spent);
  assert.deepEqual(rule.run(facts), []); assert.deepEqual(facts.metrics, spent);
}));
