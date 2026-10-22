import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { spoofableAuthorization } from "../src/detectors/authorization.js";
import { withFiles } from "./helpers.js";
import { freshnessBoundCallerTime } from "../src/detectors/freshness-bound-caller-time.js";

type Family = "spoofable" | "freshness";
const root = resolve("tests/corpus/detector-counterexamples");
const manifest = JSON.parse(readFileSync(resolve(root, "manifest.json"), "utf8")) as { schema: string; compilerVersion: "0.34.0"; cases: { family: Family; kind: string; file: string; sha256: string; detectorId: string; expectedFindings: number }[] };
const detectors = { spoofable: spoofableAuthorization, freshness: freshnessBoundCallerTime };
const sha256 = (file: string): string => createHash("sha256").update(readFileSync(file)).digest("hex");

function sourceCase(family: Family, kind: string) {
  const item = manifest.cases.find(candidate => candidate.family === family && candidate.kind === kind);
  assert.ok(item, `${family}/${kind} manifest case`);
  const file = resolve(item.file);
  assert.equal(sha256(file), item.sha256, `${item.file} pinned source hash`);
  return { item, file };
}

test("Synthetic counterexample pack has compiler-valid triplets and no producer labels", () => {
  assert.equal(manifest.schema, "nightshade-detector-counterexamples-1");
  assert.equal(manifest.cases.length, 60);
  for (const family of ["spoofable", "freshness"] as const) {
    for (const kind of ["positive", "corrected", "lookalike"]) {
      const { item, file } = sourceCase(family, kind);
      const result = scanFile(file, { compilerVersion: manifest.compilerVersion, detectors: [item.detectorId] });
      assert.equal(result.status, "complete", item.file);
      assert.deepEqual(result.diagnostics, [], item.file);
      assert.equal(result.findings.filter(finding => finding.detectorId === item.detectorId).length, item.expectedFindings, item.file);
    }
  }
});

test("Synthetic positive alarms retain reference, instruction/expression and cached/uncached agreement", () => {
  for (const family of ["spoofable", "freshness"] as const) {
    const { item, file } = sourceCase(family, "positive");
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const program = new Program(file, [], undefined, undefined, 2, manifest.compilerVersion);
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, [], `${family}/${engine}/${cached}`);
      assert.equal(facts.completedEntries.length, program.entries.length, `${family}/${engine}/${cached}`);
      assert.equal(detectors[family].run(facts).length, 1, `${family}/${engine}/${cached}`);
      assert.ok([...program.files.keys()].some(source => source.endsWith("standard-library.compact")), `${family} reference closure`);
    }
  }
});

test("Synthetic counterexample budget exhaustion remains incomplete and cannot produce a clean alarm", () => {
  for (const family of ["spoofable", "freshness"] as const) {
    const { file } = sourceCase(family, "positive");
    const program = new Program(file, [], undefined, undefined, 2, manifest.compilerVersion);
    const facts = new Dataflow(program, 1, 256, 50000, "instructions", true, true).analyze();
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code.endsWith("-budget")), family);
    assert.notEqual(facts.completedEntries.length, program.entries.length, family);
  }
});

test("freshness requires caller time to reach the represented effect", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger pending: Boolean;
export ledger touched: Boolean;
export circuit execute(currentTime: Uint<64>): [] {
  assert(disclose(currentTime > 0), "clock");
  pending = false;
  touched = true;
}` }, directory => {
    const file = resolve(directory, "main.compact");
    const result = scanFile(file, { compilerVersion: manifest.compilerVersion, detectors: [freshnessBoundCallerTime.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, []);
  });
});

test("freshness leaves direct Boolean time attestations to authorization review", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger pending: Boolean;
witness timeAttestation(now: Uint<64>): Boolean;
export circuit execute(currentTime: Uint<64>): [] {
  assert(timeAttestation(currentTime), "clock");
  pending = false;
}` }, directory => {
    const file = resolve(directory, "main.compact");
    const result = scanFile(file, { compilerVersion: manifest.compilerVersion, detectors: [freshnessBoundCallerTime.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, []);
  });
});
