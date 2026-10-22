import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Ajv } from "ajv";
import { Program, scanFile, scanFileIsolated } from "../src/index.js";
import { observeRefundEndpoints } from "../src/analysis/refund-endpoint-observation.js";
import { unshieldedRefundEndpointReview as rule } from "../src/detectors/refund-endpoint.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

interface OwnedCase { file: string; sha256: string; lines: number[]; incomplete?: boolean }
const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).refundEndpoint57;
const options = { detectors: [rule.id], compilerVersion: "0.34.0", zkirVersion: 2 } as const;
const schema = new Ajv({ strict: false, allErrors: true }).compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));

test("owned refund source certificates preserve compiler acceptance and independently reviewed sites", () => {
  for (const item of labels.cases as OwnedCase[]) {
    const file = resolve("tests/corpus", item.file);
    assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"), item.sha256, item.file);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiled.valid, true, `${item.file}: ${compiled.error}`);
    }
    const report = scanFile(file, { ...options, detectors: [...options.detectors] });
    assert.equal(report.status, item.incomplete ? "incomplete" : "complete", `${item.file}: ${JSON.stringify(report.diagnostics)}`);
    assert.deepEqual(report.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.equal(schema(JSON.parse(JSON.stringify(report))), true, `${item.file}: ${JSON.stringify(schema.errors)}`);
    for (const finding of report.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(finding.metadata.certificateScope, "source-local-formula");
      assert.equal(finding.metadata.successfulHistory, "not-certified");
      assert.equal(finding.metadata.fullRecordRecallCredit, false);
    }
    const observed = observeRefundEndpoints(new Program(file), rule, {});
    assert.deepEqual(observed.findings, report.findings, item.file);
    assert.equal(observed.diagnostics.length > 0, !!item.incomplete, item.file);
  }
});

test("supervised refund reports retain the distinct source evidence and scoped refusal", async () => {
  for (const name of ["positive", "dynamic-map-snapshots"]) {
    const file = resolve(`tests/corpus/drafts/arithmetic-endpoint57/${name}.compact`);
    const direct = scanFile(file, { ...options, detectors: [...options.detectors] });
    const isolated = await scanFileIsolated(file, { ...options, detectors: [...options.detectors] });
    assert.deepEqual(isolated.findings, direct.findings, name);
    assert.deepEqual(isolated.coverage, direct.coverage, name);
    assert.deepEqual(isolated.diagnostics, direct.diagnostics, name);
    assert.equal(isolated.schemaVersion, "1.6.0");
  }
});

test("source formula schema rejects borrowed detector, incomplete and budget-bearing certificates", () => {
  const report = scanFile(resolve("tests/corpus/drafts/arithmetic-endpoint57/positive.compact"), { ...options, detectors: [...options.detectors] });
  const plain = JSON.parse(JSON.stringify(report));
  const index = plain.coverage.rules.findIndex((row: { evidence: string }) => row.evidence === "source-local-formula");
  assert.ok(index >= 0);
  assert.equal(schema(plain), true, JSON.stringify(schema.errors));
  for (const change of [{ detectorId: "zero-amount-unshielded-send" }, { status: "incomplete" }, { diagnosticCodes: ["analysis-budget"] }]) {
    const forged = structuredClone(plain);
    Object.assign(forged.coverage.rules[index], change);
    assert.equal(schema(forged), false, JSON.stringify(change));
  }
});

test("owned refund controls keep the exact licensed Counter prefix", () => {
  const original = readFileSync("tests/corpus/known-bugs/counter-zero-unshielded-send-positive.compact").subarray(0, 898);
  for (const name of ["positive", "corrected", "lookalike", "intentional", "intentional-endpoint"])
    assert.deepEqual(readFileSync(`tests/corpus/drafts/arithmetic-endpoint57/${name}.compact`).subarray(0, 898), original, name);
});
