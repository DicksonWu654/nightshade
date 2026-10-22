import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";

const base = "tests/corpus/drafts/coverage45/anchor-guard-policy";
const policy = { authorization: [{ state: "anchor", guard: "requireOwner" }] };

for (const [kind, expectedCircuit] of [["positive", "writeAnchor"], ["corrected", undefined], ["lookalike", undefined]] as const) {
  test(`anchor guard policy behavior: ${kind}`, () => {
    const result = scanFile(resolve(base, `${kind}.compact`), {
      detectors: ["unguarded-sensitive-state-write"],
      policies: policy,
      compilerVersion: "0.34.0",
      zkirVersion: 3,
    });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.diagnostics, []);
    const findings = result.findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write");
    assert.deepEqual(findings.map(finding => [finding.location.line, finding.metadata.state]), expectedCircuit ? [[21, "anchor"]] : []);
  });
}
