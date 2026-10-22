import assert from "node:assert/strict";
import test from "node:test";
import { cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { scanFile } from "../src/index.js";

for (const [fixture, detector] of [
  ["alias-exact.compact", "unshielded-refund-endpoint-review"],
  ["key-depth-mismatch.compact", "zero-default-getter-membership-review"],
  ["same-root-unrelated-required-quiet.compact", "zero-default-getter-membership-review"],
]) test(`${detector} meters composed source keys identically after relocation: ${basename(fixture)}`, context => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-key-meter-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    const original = resolve("tests/fixtures/path-independent/nested-keys", fixture);
    const summaries = [short, long].map(directory => {
      mkdirSync(directory, { recursive: true });
      cpSync(dirname(original), directory, { recursive: true });
      const result = scanFile(join(directory, basename(original)), { detectors: [detector] });
      assert.equal(result.status, "complete");
      const metrics = Object.fromEntries(Object.entries(result.metrics).filter(([key]) => !key.endsWith("Ms")));
      const summary = JSON.parse(JSON.stringify({ status: result.status, diagnostics: result.diagnostics,
        findings: result.findings, metrics, ruleObservationWork: result.ruleObservationWork }).replaceAll(directory, "<ROOT>"));
      context.diagnostic(JSON.stringify({ pathLength: directory.length, metrics }));
      return summary;
    });
    assert.deepEqual(summaries[1], summaries[0]);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
