import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import type { Span } from "../src/model.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

test("allowance manifest sites and source-defined controls qualify with the pinned compiler", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).zeroDefaultGetterMembershipReview42 as {
    detector: string; optIn: boolean; cases: { file: string; lines: number[] }[];
  };
  assert.equal(manifest.optIn, true);
  for (const item of manifest.cases) {
    const file = resolve("tests/corpus", item.file);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, []);
      assert.equal(compiled.valid, true, `${item.file}: ${compiled.error}`);
    }
    const result = scanFile(file, { detectors: [manifest.detector] });
    assert.equal(result.status, "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
  }
});

test("Membership getter source mapping certifies both selected prefixes without an application policy", () => {
  const result = scanFile(resolve("tests/corpus/synthetic-regressions/state16/zero-amount-initial-membership-case-3-positive.compact"), {
    detectors: ["zero-default-getter-membership-review"],
  });
  assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.location.line, 12);
  assert.deepEqual((finding.metadata.initialRequirements as Span[]).map(span => span.line).sort((a, b) => a - b), [11, 12]);
  assert.equal((finding.metadata.sourceKeyBinding as unknown[]).length, 2);
  assert.equal(finding.metadata.applicationPolicy, "not-inferred");
  assert.equal(finding.metadata.crossInvocationEquality, "not-claimed");
  assert.ok(finding.trace.some(event => event.label === "exact numeric Map decrement" && event.location.line === 14));
});
