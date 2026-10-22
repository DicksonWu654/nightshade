import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, scanFileIsolated } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).zeroListGrowth50;

test("owned zero-transfer List sources compile and preserve exact source-first sites", () => {
  for (const item of labels.cases as { file: string; lines: number[]; incomplete?: boolean }[]) {
    const file = resolve("tests/corpus", item.file);
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(accepted.valid, true, `${item.file}: ${accepted.error}`);
    }
    const result = scanFile(file, { detectors: [labels.detector], compilerVersion: "0.34.0", zkirVersion: 2 });
    assert.equal(result.status, item.incomplete ? "incomplete" : "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.equal(result.diagnostics.length > 0, !!item.incomplete, item.file);
    assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.ok(result.findings.every(finding => finding.severity === "info"
      && finding.metadata.contention === "not-inferred"
      && finding.metadata.applicationImpact === "not-inferred"), item.file);
  }
});

test("supervised zero-transfer List scans preserve findings and coverage for the owned triplet", async () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/drafts/zero-list50/${kind}.compact`);
    const options = { detectors: [labels.detector], compilerVersion: "0.34.0" as const, zkirVersion: 2 as const };
    const expected = scanFile(file, options);
    const isolated = await scanFileIsolated(file, options);
    assert.equal(isolated.status, "complete", JSON.stringify(isolated.diagnostics));
    assert.deepEqual(isolated.findings, expected.findings);
    assert.deepEqual(isolated.coverage, expected.coverage);
  }
});
