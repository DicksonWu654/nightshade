import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, type AnalysisFacts } from "../src/index.js";
import { sourceObservations } from "../src/analysis/source-observations.js";
import { estimateWork } from "../src/analysis/work.js";
import { informationalDetectors, alwaysTrueAssertion, timeDependence } from "../src/detectors/informational.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

test("shared informational seeds, corrections and lookalikes compile and scan", () => {
  const manifest = JSON.parse(readFileSync(resolve("tests/corpus/known-bugs.json"), "utf8"));
  const cases = manifest.cases.filter((item: { detector: string }) => informationalDetectors.some(rule => rule.id === item.detector));
  assert.deepEqual(cases.map((item: { detector: string }) => item.detector).sort(), informationalDetectors.map(rule => rule.id).sort());
  assert.deepEqual(informationalDetectors.filter(rule => rule.defaultEnabled === false).map(rule => rule.id), ["write-only-ledger"]);
  assert.ok(informationalDetectors.filter(rule => rule.id !== "write-only-ledger").every(rule => rule.defaultEnabled === true));
  for (const item of cases) {
    for (const [path, lines] of [[item.file, item.expectedLines], [item.corrected, []], [item.lookalike, []]] as [string, number[]][]) {
      const file = resolve("tests/corpus", path);
      if (process.env.COMPACTC_TEST) {
        const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
        assert.equal(compiled.valid, true, `${path}: ${compiled.error}`);
      }
      for (const experimentalCounterQueries of [false, true]) {
        const result = scanFile(file, { detectors: [item.detector], experimentalCounterQueries });
        assert.equal(result.status, "complete", `${path}: ${JSON.stringify(result.diagnostics)}`);
        assert.deepEqual(result.findings.map(finding => finding.location.line), lines, path);
      }
    }
  }
});
