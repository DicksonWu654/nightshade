import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, scanFileIsolated } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).independentMembershipIdentity54;

test("owned memo membership sources compile and preserve source-reviewed relationships", () => {
  for (const item of labels.cases as { file: string; findingFile?: string; lines: number[]; expectedLedgers: string[] }[]) {
    const file = resolve("tests/corpus", item.file);
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3, "0.34.0");
      assert.equal(accepted.valid, true, `${item.file}: ${accepted.error}`);
    }
    const result = scanFile(file, { detectors: [labels.detector], compilerVersion: "0.34.0", zkirVersion: 3 });
    assert.equal(result.status, "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.diagnostics, [], item.file);
    assert.ok(result.findings.every(finding => resolve(finding.location.file) === resolve("tests/corpus", item.findingFile ?? item.file)), item.file);
    assert.deepEqual([...new Set(result.findings.map(finding => finding.location.line))].sort((a, b) => a - b), item.lines, item.file);
    assert.deepEqual(result.findings.map(finding => finding.metadata.effectLedger).sort(), [...item.expectedLedgers].sort(), item.file);
    assert.ok(result.findings.every(finding => finding.severity === "info"
      && finding.metadata.reviewRequired === true
      && finding.metadata.authenticationIntent === "unknown"
      && finding.metadata.applicationImpact === "not-inferred"), item.file);
    assert.ok(result.coverage.rules?.every(row => row.status !== "incomplete"), item.file);
  }
});

test("supervised memo membership scans preserve exact findings and coverage", async () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/drafts/memo-identity44/${kind}.compact`);
    const options = { detectors: [labels.detector], compilerVersion: "0.34.0" as const, zkirVersion: 3 as const };
    const expected = scanFile(file, options);
    const isolated = await scanFileIsolated(file, options);
    assert.equal(isolated.status, "complete", JSON.stringify(isolated.diagnostics));
    assert.deepEqual(isolated.findings, expected.findings);
    assert.deepEqual(isolated.coverage, expected.coverage);
  }
});
