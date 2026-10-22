import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Program, scanFile } from "../src/index.js";
import { observeSourceClaims } from "../src/analysis/source-claims-observation.js";
import { sourceClaimShieldedIssuanceReview as rule } from "../src/detectors/source-claims.js";
import { resolvePolicies, type Policies } from "../src/policies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).sourceClaims52;
interface OwnedClaimCase { file: string; sha256: string; lines: number[]; incomplete?: boolean; policies?: Policies }

test("source-first owned claims preserve compiler acceptance, exact sites and refusal across both engines and caches", () => {
  for (const item of labels.cases as OwnedClaimCase[]) {
    const file = resolve("tests/corpus", item.file), policies = item.policies ?? labels.policies;
    assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"), item.sha256, item.file);
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(accepted.valid, true, `${item.file}: ${accepted.error}`);
    }
    const result = scanFile(file, { detectors: [labels.detector], compilerVersion: "0.34.0", zkirVersion: 2, policies });
    assert.equal(result.status, item.incomplete ? "incomplete" : "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.equal(result.diagnostics.length > 0, !!item.incomplete, item.file);
    assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.ok(result.findings.every(finding => finding.severity === "info"
      && finding.metadata.claimMeaning === "explicit-policy"
      && finding.metadata.spendability === "not-established"
      && finding.metadata.applicationImpact === "not-inferred"), item.file);
    const program = new Program(file), resolved = resolvePolicies(program, policies);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const observed = observeSourceClaims(program, rule, resolved, {}, new Set(program.entries), { engine, cached });
      assert.deepEqual(observed.findings, result.findings, `${item.file}/${engine}/${cached}`);
      assert.equal(observed.diagnostics.length > 0, !!item.incomplete, `${item.file}/${engine}/${cached}`);
    }
  }
});
