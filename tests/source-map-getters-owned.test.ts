import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Program, scanFile } from "../src/index.js";
import { observeSourceMapGetters } from "../src/analysis/source-map-getters-observation.js";
import { sourceClaimMapGetterReview as rule } from "../src/detectors/source-map-getters.js";
import { resolvePolicies, type Policies } from "../src/policies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).sourceMapGetters56;
interface OwnedCase { file: string; sha256: string; lines: number[]; incomplete?: boolean; policies?: Policies }
const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

test("owned Map getter contracts preserve compiler acceptance, sites and refusal across engines and caches", () => {
  for (const item of labels.cases as OwnedCase[]) {
    const file = resolve("tests/corpus", item.file), policies = item.policies ?? labels.policies;
    assert.equal(hash(readFileSync(file)), item.sha256, item.file);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiled.valid, true, `${item.file}: ${compiled.error}`);
    }
    const report = scanFile(file, { detectors: [rule.id], policies, compilerVersion: "0.34.0", zkirVersion: 2 });
    assert.equal(report.status, item.incomplete ? "incomplete" : "complete", `${item.file}: ${JSON.stringify(report.diagnostics)}`);
    assert.deepEqual(report.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.ok(report.findings.every(finding => finding.severity === "info"
      && finding.metadata.policyMeaning === "explicit-same-key-configured-value"
      && finding.metadata.runtimeBehavior === "not-established"
      && finding.metadata.applicationImpact === "not-inferred"), item.file);
    const program = new Program(file), resolved = resolvePolicies(program, policies);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const observed = observeSourceMapGetters(program, rule, resolved, {}, new Set(program.entries), { engine, cached });
      assert.deepEqual(observed.findings, report.findings, `${item.file}/${engine}/${cached}`);
      assert.equal(observed.diagnostics.length > 0, !!item.incomplete, `${item.file}/${engine}/${cached}`);
    }
  }
});

test("owned Map getter controls retain the exact licensed Counter scaffold and imported support hashes", () => {
  const prefix = readFileSync("tests/corpus/drafts/enrollment44/counter/positive.compact").subarray(0, 898);
  for (const name of ["positive", "corrected-map-read", "lookalike-auxiliary"])
    assert.deepEqual(readFileSync(`tests/corpus/drafts/map-getter56/counter/${name}.compact`).subarray(0, 898), prefix);
  for (const source of labels.supportFiles as { file: string; sha256: string }[])
    assert.equal(hash(readFileSync(resolve("tests/corpus", source.file))), source.sha256, source.file);
});
