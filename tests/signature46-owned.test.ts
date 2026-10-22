import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const root = resolve("tests/corpus/drafts/signature46");
const rule = "signature-key-identity-exclusion-review";
const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).signatureIdentityExclusion46;

test("owned dual-curve signature fixtures preserve positive, message-only and real quiet controls", () => {
  for (const item of manifest.cases as { file: string; lines: number[] }[]) {
    const result = scanFile(resolve("tests/corpus", item.file), { detectors: [rule], zkirVersion: 3 });
    assert.equal(result.status, "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.diagnostics, [], item.file);
    assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.ok(result.findings.every(finding => finding.severity === "info" && finding.metadata.keyKnownIdentity === false
      && finding.metadata.fullRecordRecallCredit === false), item.file);
    if (item.lines.length) assert.deepEqual(result.findings.map(finding => finding.metadata.curve), ["JubjubPoint", "Secp256k1Point"], item.file);
  }
});

test("owned late and alias checks quiet only their exact snapshot; transformed keys remain unavailable", () => {
  for (const name of ["canonical-generator-key", "exact-key-alias-check", "late-exact-key-check", "post-verifier-exact-key-check", "namesake-verifier"]) {
    const result = scanFile(resolve(root, "controls", `${name}.compact`), { detectors: [rule], zkirVersion: 3 });
    assert.equal(result.status, "complete", `${name}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.findings, [], name);
  }
  const revision = scanFile(resolve(root, "controls/old-revision-does-not-guard.compact"), { detectors: [rule], zkirVersion: 3 });
  assert.equal(revision.status, "complete", JSON.stringify(revision.diagnostics));
  assert.deepEqual(revision.findings.map(finding => finding.location.line), [10]);
  const transformed = scanFile(resolve(root, "controls/point-transform-without-exclusion.compact"), { detectors: [rule], zkirVersion: 3 });
  assert.equal(transformed.status, "incomplete");
  assert.deepEqual(transformed.findings, []);
  assert.ok(transformed.diagnostics.some(issue => issue.code === "signature-identity-review-unavailable"));
});

test("all owned signature46 sources compile under their exact 0.34.0 ZKIR3 profile", { skip: !process.env.COMPACTC_TEST }, () => {
  for (const folder of ["caller-key", "persistent-key", "counter", "controls"]) for (const name of readdirSync(resolve(root, folder))) {
    if (!name.endsWith(".compact")) continue;
    const result = validateWithCompiler(process.env.COMPACTC_TEST!, resolve(root, folder, name), [], 30000, 3, "0.34.0");
    assert.equal(result.valid, true, `${folder}/${name}: ${result.error}`);
  }
});
