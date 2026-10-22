import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile, type ZkirVersion } from "../src/index.js";
import { detectors } from "../src/detectors/index.js";
import type { Policies } from "../src/policies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

interface Seed {
  id: string; detector: string; file: string; corrected: string; lookalike: string;
  expectedLines: number[]; test: string; compiler: string; policies?: Policies;
  zkirVersion?: ZkirVersion;
  requiresOZ?: boolean; expectedMetadata?: Record<string, string>; expectedSeverity?: string;
  knownGap?: { status: string; observedLines: number[]; diagnosticCodes: string[]; reason: string };
}
const seeds: Seed[] = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8")).cases;

test("every shipped rule has a synthetic regression in the shared corpus", () => {
  assert.equal(new Set(seeds.map(seed => seed.id)).size, seeds.length);
  const corpusManifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8"));
  const additional = [...corpusManifest.ruleGaps20261016.detectors,
    ...corpusManifest.developmentRules20261017?.detectors ?? []];
  assert.deepEqual([...new Set([...seeds.map(seed => seed.detector), ...additional])].sort(), detectors.map(rule => rule.id).sort());
});

// Existing informational and receipt tests still own their cases. This extends
// the same registry without a separate benchmark or replay mechanism.
for (const seed of seeds.filter(seed => seed.test === "tests/known-bugs.test.ts")) {
  test(`synthetic detector regression: ${seed.id}${seed.knownGap ? " (known detector gap)" : ""}`, { skip: seed.requiresOZ && !process.env.OZ_COMPACT_TEST }, context => {
    const searchPaths = seed.requiresOZ ? [resolve(process.env.OZ_COMPACT_TEST!, "contracts/src")] : [];
    assert.equal(seed.compiler, "0.34.0");
    for (const [path, expected] of [[seed.file, seed.expectedLines], [seed.corrected, []], [seed.lookalike, []]] as const) {
      const file = resolve("tests/corpus", path);
      if (process.env.COMPACTC_TEST) {
        const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths, 30000, seed.zkirVersion ?? 2);
        assert.equal(compiled.valid, true, `${path}: ${compiled.error}`);
      }
      const scan = scanFile(file, { detectors: [seed.detector], policies: seed.policies, searchPaths, zkirVersion: seed.zkirVersion });
      // Preserve ground-truth lines for missed positives. These assertions
      // characterize a known gap, not a successful detection; reports must
      // include these cases as misses (including incomplete) as detector misses.
      const gap = path === seed.file ? seed.knownGap : undefined;
      if (gap) {
        assert.ok(expected.length > 0);
        context.diagnostic(`NOT DETECTED: ${seed.id}: ${gap.reason}`);
      }
      assert.equal(scan.status, gap?.status ?? "complete", `${path}: ${JSON.stringify(scan.diagnostics)}`);
      assert.deepEqual(scan.diagnostics.map(diagnostic => diagnostic.code), gap?.diagnosticCodes ?? [], path);
      assert.deepEqual(scan.findings.map(finding => finding.location.line), gap?.observedLines ?? expected, path);
      for (const finding of scan.findings) {
        if (seed.expectedSeverity) assert.equal(finding.severity, seed.expectedSeverity, path);
        for (const [key, value] of Object.entries(seed.expectedMetadata ?? {})) assert.equal(finding.metadata[key], value, `${path}: ${key}`);
      }
    }
  });
}
