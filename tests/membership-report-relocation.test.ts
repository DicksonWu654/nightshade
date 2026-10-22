import assert from "node:assert/strict";
import test from "node:test";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanFile } from "../src/index.js";

test("membership reports retain no path-derived selector digests", context => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-membership-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    mkdirSync(short); mkdirSync(long, { recursive: true });
    for (const selector of ["key", "persistentHash<Bytes<32>>(key)", "(key as Field) as Bytes<32>"]) {
      const source = `import CompactStandardLibrary;export ledger members:Map<Bytes<32>,Set<Bytes<32>>>;export ledger stored:Field;export circuit entry(key:Bytes<32>,next:Field):[]{assert(members.lookup(disclose(${selector})).member(disclose(ownPublicKey().bytes)),"member");stored=disclose(next);}`;
      const reports = [short, long].map(directory => {
        const file = join(directory, "main.compact"); writeFileSync(file, source);
        const result = scanFile(file, { detectors: ["public-key-membership-authorization"] });
        assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
        assert.equal(result.findings.length, 1);
        return JSON.parse(JSON.stringify({ status: result.status, coverage: result.coverage,
          diagnostics: result.diagnostics, findings: result.findings,
          metrics: Object.fromEntries(Object.entries(result.metrics).filter(([key]) => !key.endsWith("Ms"))),
          ruleObservationWork: result.ruleObservationWork }).replaceAll(directory, "<ROOT>"));
      });
      context.diagnostic(selector);
      assert.deepEqual(reports[1], reports[0]);
    }
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test("imported membership review fingerprints omit opaque analysis digests", () => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-imported-membership-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    const reports = [short, long].map(directory => {
      cpSync(resolve("tests/fixtures/path-independent/nested-keys"), directory, { recursive: true });
      const result = scanFile(join(directory, "imported-positive.compact"), { detectors: ["membership-identity-binding-review"] });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, 1);
      return JSON.parse(JSON.stringify({ status: result.status, diagnostics: result.diagnostics, findings: result.findings,
        metrics: Object.fromEntries(Object.entries(result.metrics).filter(([key]) => !key.endsWith("Ms"))),
        ruleObservationWork: result.ruleObservationWork }).replaceAll(directory, "<ROOT>"));
    });
    assert.deepEqual(reports[1], reports[0]);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
