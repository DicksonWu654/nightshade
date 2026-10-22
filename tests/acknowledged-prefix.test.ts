import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, AnalysisFacts, scanFile } from "../src/index.js";
import { AbstractValue } from "../src/dataflow/index.js";
import { withFiles, semanticPaths } from "./helpers.js";

const outputs = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const values = (value: AbstractValue): unknown => value.items ? value.items.map(values) : value.fields ? Object.fromEntries(Object.entries(value.fields).map(([key, child]) => [key, values(child)])) : value.constant;

const fixturePath = resolve(process.cwd(), "tests/corpus/synthetic-regressions/state16/destructive-list-reset-case-12-corrected.compact");
const fixtureSource = readFileSync(fixturePath, "utf8");
const transition = fixtureSource
  .replace(/^pragma language_version[^\n]*\n/m, "")
  .replace(/^import CompactStandardLibrary;[^\n]*\n/m, "")
  .replace(/\bexport\s+/g, "")
  .replaceAll("Bytes<32>", "Field");

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary;${transition}\n${source}` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = (["instructions", "expressions"] as const).flatMap(engine => [true, false].map(cached => new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze()));
    for (const result of facts) {
      assert.deepEqual(result.completedEntries, program.entries);
      assert.deepEqual(result.diagnostics, []);
      check(result);
    }
    assert.deepEqual(facts[0].paths, facts[1].paths);
    assert.deepEqual(facts[2].paths, facts[3].paths);
    assert.deepEqual(semanticPaths(facts[0]), semanticPaths(facts[1]));
    assert.deepEqual(semanticPaths(facts[2]), semanticPaths(facts[3]));
    assert.deepEqual(facts[0].failedAssertions, facts[1].failedAssertions);
    assert.deepEqual(facts[2].failedAssertions, facts[3].failedAssertions);
  });
}

function acknowledgedCase(readView: number[], newer: number[], acknowledgedCount: number): string {
  const credits = [...readView.slice().reverse(), ...newer.slice().reverse()]
    .map(value => `credit(1 as Field, ${value} as Field);`).join("\n");
  const expected = newer.concat(readView.slice(acknowledgedCount));
  const observations = expected.map((_, index) => `const seen${index} = memos.lookup(1 as Field).head().value; memos.lookup(1 as Field).popFront();`);
  const returned = expected.map((_, index) => `seen${index}`);
  return `export circuit entry(): [Uint<64>,Uint<64>,${expected.map(() => "Field").join(",")}] { initialize(1 as Field); ${credits} clearAcknowledged(1 as Field, ${readView.length} as Uint<64>, ${acknowledgedCount} as Uint<64>); const finalLength = memos.lookup(1 as Field).length(); const scratchLength = newerScratch.lookup(1 as Field).length(); ${observations.join(" ")} return [finalLength,scratchLength,${returned.join(",")}]; }`;
}

for (let newerCount = 0; newerCount <= 3; newerCount++) {
  for (let acknowledgedCount = 0; acknowledgedCount <= 3; acknowledgedCount++) {
    test(`acknowledged-prefix acknowledged prefix preserves newest-first order: newer=${newerCount}, acknowledged=${acknowledgedCount}`, () => {
      const readView = Array.from({ length: acknowledgedCount + 2 }, (_, index) => 100 + index);
      const newer = Array.from({ length: newerCount }, (_, index) => 10 + index);
      const expected = newer.concat(readView.slice(acknowledgedCount));
      compare(acknowledgedCase(readView, newer, acknowledgedCount), facts => assert.deepEqual(outputs(facts).map(values), [[String(expected.length), "0", ...expected.map(String)]]));
    });
  }
}

test("acknowledged-prefix acknowledged counts preserve order with duplicate ciphertext values", () => {
  const readView = [77, 77, 88];
  const newer = [9, 9];
  const acknowledgedCount = 2;
  const expected = [9, 9, 88];
  compare(acknowledgedCase(readView, newer, acknowledgedCount), facts => {
    assert.deepEqual(outputs(facts).map(values), [[String(expected.length), "0", ...expected.map(String)]]);
  });
});

test("acknowledged-prefix bounded acknowledged prefix rejects a fourth newer or acknowledged entry", () => {
  const tooManyAcknowledged = `export circuit entry(): [] { initialize(1 as Field); ${[1,2,3,4].map(value => `credit(1 as Field, ${value} as Field);`).join(" ")} clearAcknowledged(1 as Field, 4 as Uint<64>, 4 as Uint<64>); }`;
  const tooManyNewer = `export circuit entry(): [] { initialize(1 as Field); credit(1 as Field, 100 as Field); ${[1,2,3,4].map(value => `credit(1 as Field, ${value} as Field);`).join(" ")} clearAcknowledged(1 as Field, 1 as Uint<64>, 0 as Uint<64>); }`;
  for (const [source, message] of [[tooManyAcknowledged, '"at most three acknowledged memos"'], [tooManyNewer, '"at most three newer memos"']] as const) {
    compare(source, facts => {
      assert.deepEqual(facts.failedAssertions.map(failure => failure.message), [message]);
      assert.deepEqual(outputs(facts), []);
    });
  }
});

test("acknowledged-prefix actual Bytes32 sources have complete mapped coverage and quiet corrected controls", () => {
  for (const kind of ["positive", "corrected", "lookalike"] as const) {
    const source = resolve(process.cwd(), `tests/corpus/synthetic-regressions/state16/destructive-list-reset-case-12-${kind}.compact`);
    const report = scanFile(source, { detectors: ["destructive-list-reset"], maxSteps: 40000, maxPaths: 256, maxValues: 50000 });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.diagnostics, []);
    assert.deepEqual(report.findings.map(finding => finding.location.line), kind === "positive" ? [14] : []);
    const coverage = report.coverage.rules ?? [];
    assert.equal(coverage.length, report.entrypoints.length);
    assert.equal(coverage.length, 3);
    assert.ok(coverage.every(rule => rule.status === "complete"));
  }
});
