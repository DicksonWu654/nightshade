import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import type { Finding } from "../src/detectors/types.js";
import type { Span } from "../src/model.js";
import { eitherPayloadMismatch as rule } from "../src/detectors/either-payload.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const fixtureDirectory = resolve("tests/corpus/synthetic-regressions/state16");
const fileFor = (variant: string) => resolve(fixtureDirectory, `either-payload-mismatch-case-6-${variant}.compact`);
const selectedSource = (location: Span): string => readFileSync(location.file).subarray(location.start, location.end).toString("utf8");
function expectedRelationship(findings: Finding[], positive: boolean): void {
  assert.equal(findings.length, positive ? 1 : 0);
  if (!positive) return;
  const finding = findings[0];
  assert.equal(selectedSource(finding.location), "owner.left");
  assert.deepEqual(finding.callPath, ["setAndAct", "assertOnlyOwner"]);
  assert.equal(finding.metadata.entry, "setAndAct");
  assert.equal(finding.metadata.arm, "left");
  assert.equal(finding.metadata.isLeft, false);
  const effects = finding.metadata.effects as { through: string; location: Span }[];
  assert.ok(effects.some(effect => effect.through === "predicate" && selectedSource(effect.location) === "authorizedActions.increment(1)"),
    "the inactive stored owner payload gates the composed action's consequence");
}
function observed(program: Program, engine: "instructions" | "expressions", cached: boolean) {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
    "all", false, false, false, true, false, true).analyze();
}

// These are one-invocation source relationships. No historical deployment,
// authenticated ContractAddress caller, or inter-transaction propagation is modeled.
for (const variant of ["positive", "corrected", "lookalike"] as const) {
  test(`composed owned Either owner ${variant} agrees across engine/cache and supervised selection`, async () => {
    const file = fileFor(variant), positive = variant === "positive";
    if (process.env.COMPACTC_TEST) {
      const compilation = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compilation.valid, true, compilation.error);
    }
    const program = new Program(file);
    let baseline: Finding[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observed(program, engine, cached);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      expectedRelationship(findings, positive);
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    for (const options of [{}, { detectors: [rule.id] }]) {
      const direct = scanFile(file, options);
      const supervised = await scanFileIsolated(file, options, { timeoutMs: 60000, heapMiB: 512 });
      for (const report of [direct, supervised]) {
        assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
        assert.deepEqual(report.diagnostics, []);
        const findings = report.findings.filter(finding => finding.detectorId === rule.id);
        expectedRelationship(findings, positive);
        assert.deepEqual(findings, baseline);
      }
      assert.deepEqual(supervised.findings, direct.findings);
    }
  });
}

test("separate owner setter and authorization entries do not compose storage tags across invocations", () => {
  const source = readFileSync(fileFor("positive"), "utf8")
    .replace(/^(?:export )?circuit setOwner\(/m, "export circuit setOwner(")
    .replace(/^(?:export )?circuit assertOnlyOwner\(\): \[\]/m, "export circuit assertOnlyOwner(): []")
    .replace(/export circuit setAndAct[\s\S]*$/, "");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compilation = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compilation.valid, true, compilation.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observed(program, engine, cached);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(rule.run(facts), []);
      assert.deepEqual(facts.diagnostics, []);
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings, []);
  });
});

test("validating a right payload without selecting its tag cannot prove a composed owner mismatch", () => {
  const source = readFileSync(fileFor("positive"), "utf8")
    .replace(/^  assert\(!candidate\.is_left,[^\n]*\n/m, "");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compilation = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compilation.valid, true, compilation.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observed(program, engine, cached);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(rule.run(facts), []);
      assert.deepEqual(facts.diagnostics, []);
    }
  });
});

test("missing receiver evidence and exhausted composed analysis remain diagnostic", () => {
  const file = fileFor("positive"), facts = new Dataflow(new Program(file)).analyze();
  assert.equal(facts.diagnostics.length, 0);
  assert.deepEqual(rule.run(facts), []);
  assert.ok(facts.diagnostics.some(issue => issue.code === "either-evidence-unavailable"));
  const report = scanFile(file, { detectors: [rule.id], maxValues: 3 });
  assert.equal(report.status, "incomplete");
  assert.ok(report.diagnostics.some(issue => /budget/.test(issue.code)), JSON.stringify(report.diagnostics));
});
