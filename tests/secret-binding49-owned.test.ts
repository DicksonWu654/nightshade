import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, scanFileIsolated } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).secretBindingDivergence49;

test("owned secret-binding sources compile and retain their source-first review sites", () => {
  for (const item of labels.cases as { file: string; lines: number[] }[]) {
    const file = resolve("tests/corpus", item.file);
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(accepted.valid, true, `${item.file}: ${accepted.error}`);
    }
    const result = scanFile(file, { detectors: [labels.detector], compilerVersion: "0.34.0", zkirVersion: 2 });
    assert.equal(result.status, "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.diagnostics, [], item.file);
    assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.ok(result.findings.every(finding => finding.severity === "info"
      && finding.metadata.crossEntryValueEquality === "not-inferred"
      && finding.metadata.applicationImpact === "not-inferred"), item.file);
  }
});

test("supervised scans preserve the selected secret-binding triplet and exact rule coverage", async () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/drafts/auth39/secret-binding-${kind}.compact`);
    const options = { detectors: [labels.detector], compilerVersion: "0.34.0" as const, zkirVersion: 2 as const };
    const expected = scanFile(file, options);
    const isolated = await scanFileIsolated(file, options);
    assert.equal(isolated.status, "complete", JSON.stringify(isolated.diagnostics));
    assert.deepEqual(isolated.findings, expected.findings);
    assert.deepEqual(isolated.coverage, expected.coverage);
  }
});
