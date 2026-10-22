import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const corpus = resolve("tests/corpus");
const manifest = JSON.parse(readFileSync(resolve(corpus, "manifest.json"), "utf8")).ruleGaps20261016 as {
  cases: { file: string; sha256: string; detector: string; lines: number[] }[];
};

test("top rule-gap detectors preserve compiler-valid positive/corrected/lookalike triplets", () => {
  for (const entry of manifest.cases) {
    const file = resolve(corpus, entry.file);
    assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"), entry.sha256, entry.file);
    if (process.env.COMPACTC_TEST) {
      const validated = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validated.valid, true, validated.error);
    }
    const result = scanFile(file, { detectors: [entry.detector], maxSteps: 100000, maxPaths: 256, maxValues: 100000 });
    assert.equal(result.status, "complete", `${entry.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.findings.map(item => item.location.line), entry.lines, entry.file);
  }
});
