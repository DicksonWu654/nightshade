import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { conditionalHashRangeFindings, conditionalHashRange } from "../src/detectors/conditional-hash-range.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const id = conditionalHashRange.id;
const source = `import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export circuit update(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
  if (disclose(enabled)) {
    const difference = (a - b) as Uint<128>;
    digest = disclose(persistentHash<Uint<128>>(difference));
  }
}
export circuit idle(): [] { }`;
function compile(file: string) {
  if (!process.env.COMPACTC_TEST) return;
  const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
  assert.equal(result.valid, true, result.error);
}

test("conditional hash source review agrees across engines and cache settings", () => withFiles({ "main.compact": source }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const program = new Program(file), variants = [];
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    const findings = conditionalHashRangeFindings(facts);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].location.line, 6);
    assert.equal(findings[0].severity, "low");
    assert.equal(findings[0].confidence, "high");
    assert.equal(findings[0].metadata.proofFailure, "not-proven");
    variants.push(findings);
  }
  for (const findings of variants) assert.deepEqual(findings, variants[0]);
}));

test("conditional hash source budget exhaustion invalidates every root entry", () => withFiles({ "main.compact": source }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  const facts = new Dataflow(new Program(file)).analyze();
  assert.equal(conditionalHashRangeFindings(facts).length, 1);
  assert.deepEqual(conditionalHashRangeFindings(facts, 0), []);
  assert.equal(facts.diagnostics.length, 2);
  assert.ok(facts.diagnostics.every(issue => issue.code === "conditional-hash-range-unavailable"
    && issue.scope?.kind === "rule" && issue.scope.detectorId === id));
  assert.deepEqual(new Set(facts.diagnostics.map(issue => issue.scope!.entry)), new Set(facts.program.entries));
}));

test("conditional hash scan stays opt-in and preserves baseline coverage on profile gaps", () => withFiles({ "main.compact": source }, directory => {
  const file = resolve(directory, "main.compact"); compile(file);
  assert.equal(scanFile(file).findings.filter(item => item.detectorId === id).length, 0);
  const selected = scanFile(file, { detectors: [id] });
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  assert.equal(selected.findings.length, 1);
  assert.match(human(selected), /conditional-hash-range/);
  const output = sarif(selected) as { runs: { results: { ruleId: string }[] }[] };
  assert.equal(output.runs[0].results[0].ruleId, id);
  const unavailable = scanFile(file, { detectors: [id], compilerVersion: "0.35.0" });
  assert.equal(unavailable.coverage.baselineStatus, "complete");
  assert.equal(unavailable.status, "incomplete");
  assert.equal(unavailable.findings.length, 0);
  assert.ok(unavailable.coverage.rules!.every(row => row.status === "incomplete"));
  assert.match(human(unavailable), /incomplete/i);
}));

test("conditional hash source coverage survives isolated worker and Counter reporting", async () => {
  const file = resolve("tests/corpus/known-bugs/counter-conditional-hash-positive.compact"); compile(file);
  for (const experimentalCounterQueries of [false, true]) {
    const direct = scanFile(file, { detectors: [id], experimentalCounterQueries });
    const worker = await scanFileIsolated(file, { detectors: [id], experimentalCounterQueries });
    assert.equal(direct.status, "complete", JSON.stringify(direct.diagnostics));
    assert.equal(worker.status, direct.status);
    assert.deepEqual(worker.findings, direct.findings);
    assert.deepEqual(worker.coverage, direct.coverage);
    if (experimentalCounterQueries) {
      assert.ok("analysis" in worker);
      const analysis = worker.analysis as { coverage: { method: string; contract: string; status: string }[] };
      assert.ok(analysis.coverage.every(row => row.method === "source-work" && row.contract === "conditional-hash-source-range-v1" && row.status === "covered"));
    }
  }
});
