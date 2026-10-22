import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { genericWitnessAbiFindings, genericWitnessMaybeAbi } from "../src/detectors/generic-witness-abi.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const id = genericWitnessMaybeAbi.id;
const prefix = `import CompactStandardLibrary;
witness lookup<T>(key: Bytes<4>): Maybe<T>;
export circuit getNumber(key: Bytes<4>): Maybe<Uint<64>> { return disclose(lookup<Uint<64>>(key)); }
export circuit getBytes(key: Bytes<4>): Maybe<Bytes<32>> { return disclose(lookup<Bytes<32>>(key)); }`;

function compile(file: string, compiler = process.env.COMPACTC_TEST, version = "0.34.0") {
  if (!compiler) return;
  const result = validateWithCompiler(compiler, file, [], 30000, 2, version as "0.34.0" | "0.35.0");
  assert.equal(result.valid, true, result.error);
}

test("generic witness ABI findings agree across engines/caches without path requirements", () => withFiles({ "main.compact": prefix }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const program = new Program(file), variants = [];
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    const findings = genericWitnessAbiFindings(facts);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].location.line, 2);
    assert.deepEqual(findings[0].metadata.entries, program.entries);
    assert.equal(findings[0].metadata.hostFailure, "not-proven");
    assert.equal(findings[0].callPath.length, 0);
    assert.equal(findings[0].trace.length, 2);
    variants.push(findings);
  }
  for (const findings of variants) assert.deepEqual(findings, variants[0]);
}));

test("three incompatible specializations group once by canonical witness template", () => withFiles({ "main.compact": prefix + `
export circuit getWide(key: Bytes<4>): Maybe<Uint<128>> { return disclose(lookup<Uint<128>>(key)); }` }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const report = scanFile(file, { detectors: [id] });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.equal(report.findings.length, 1);
  assert.equal((report.findings[0].metadata.specializations as unknown[]).length, 3);
  assert.equal((report.findings[0].metadata.conflictingPairs as unknown[]).length, 2);
  assert.equal(report.findings[0].trace.length, 3);
  assert.deepEqual(report.coverage.rules!.map(row => row.status), ["complete", "complete", "complete"]);
}));

test("budget exhaustion withholds all ABI findings and is rule-scoped", () => withFiles({ "main.compact": prefix }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const facts = new Dataflow(new Program(file)).analyze();
  assert.equal(genericWitnessAbiFindings(facts).length, 1);
  assert.deepEqual(genericWitnessAbiFindings(facts, 0), []);
  assert.equal(facts.diagnostics.length, 2);
  assert.ok(facts.diagnostics.every(issue => issue.code === "generic-witness-abi-unavailable"
    && issue.scope?.kind === "rule" && issue.scope.detectorId === id));
  genericWitnessAbiFindings(facts, 0);
  assert.equal(facts.diagnostics.length, 2);
}));

test("unqualified profiles are explicit in JSON/SARIF/human output without changing baseline", () => withFiles({ "main.compact": prefix }, directory => {
  const file = resolve(directory, "main.compact"); compile(file, process.env.COMPACTC_035_TEST, "0.35.0");
  const report = scanFile(file, { compilerVersion: "0.35.0", detectors: [id] });
  assert.equal(report.coverage.baselineStatus, "complete");
  assert.equal(report.status, "incomplete");
  assert.deepEqual(report.findings, []);
  assert.ok(report.coverage.rules!.every(row => row.status === "incomplete"));
  assert.ok(report.diagnostics.every(issue => issue.code === "generic-witness-abi-unavailable" && issue.scope?.detectorId === id));
  assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
  const rendered = sarif(report) as { runs: { properties: { coverage: typeof report.coverage } }[] };
  assert.deepEqual(rendered.runs[0].properties.coverage, report.coverage);
}));

test("the opt-in ABI review leaves ordinary findings unchanged and survives the worker", async () => {
  assert.equal(genericWitnessMaybeAbi.defaultEnabled, false);
  const file = resolve("tests/corpus/known-bugs/counter-generic-witness-positive.compact");
  const ordinary = scanFile(file), selected = scanFile(file, { detectors: [id] });
  assert.equal(ordinary.status, "complete", JSON.stringify(ordinary.diagnostics));
  assert.ok(ordinary.findings.every(finding => finding.detectorId !== id));
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  assert.equal(selected.findings.length, 1);
  assert.equal(selected.findings[0].severity, "low");
  assert.equal(selected.findings[0].confidence, "high");
  const worker = await scanFileIsolated(file, { detectors: [id] });
  assert.deepEqual(worker.findings, selected.findings);
  assert.deepEqual(worker.coverage, selected.coverage);
});

test("experimental Counter mode preserves the independent source-schema contract", () => withFiles({ "main.compact": prefix }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const exact = scanFile(file, { detectors: [id] });
  const counter = scanFile(file, { detectors: [id], experimentalCounterQueries: true });
  assert.equal(counter.status, "complete", JSON.stringify(counter.diagnostics));
  assert.deepEqual(counter.findings, exact.findings);
  assert.ok("analysis" in counter);
  assert.ok(counter.analysis?.coverage.every(row => row.status === "covered" && row.method === "source-work"
    && row.contract === "generic-witness-source-schema-v1"));
  const unavailable = scanFile(file, { detectors: [id], experimentalCounterQueries: true, compilerVersion: "0.35.0" });
  assert.equal(unavailable.status, "incomplete");
  assert.deepEqual(unavailable.findings, []);
  assert.ok("analysis" in unavailable);
  assert.ok(unavailable.analysis?.coverage.every(row => row.status === "incomplete"));
  assert.ok(unavailable.diagnostics.some(issue => issue.scope?.detectorId === id && issue.code === "generic-witness-abi-unavailable"));
}));

test("correlated admission is unchanged when adding the source-only ABI review", () => withFiles({ "main.compact": prefix + `
export ledger rounds: Counter;
witness choice(): Boolean;
export circuit advance(): [] { if (disclose(choice())) { rounds.increment(1); } }` }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const selected = ["ledger-bound-preimage-publication"];
  const before = scanFile(file, { detectors: selected }), after = scanFile(file, { detectors: [...selected, id] });
  assert.equal(before.coverage.baselineStatus, "complete");
  assert.equal(after.coverage.baselineStatus, "complete");
  assert.deepEqual(after.findings.filter(finding => finding.detectorId !== id), before.findings);
  for (const key of ["steps", "paths", "abstractValues", "guardSubsumptions"] as const) assert.equal(after.metrics[key], before.metrics[key], key);
}));
