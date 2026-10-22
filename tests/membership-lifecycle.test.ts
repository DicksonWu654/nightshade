import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, scanFileIsolated, type Finding } from "../src/index.js";
import { merkleMembershipNotEnforced as rule } from "../src/detectors/merkle-membership.js";
import { semanticPaths } from "./helpers.js";

const fileFor = (variant: string) => resolve(`tests/corpus/drafts/state37/membership-lifecycle/owned/merkle-membership-not-enforced-case-36-${variant}.compact`);
const selected = (findings: Finding[]) => findings.filter(finding => finding.detectorId === rule.id);
const transported = (value: unknown) => JSON.parse(JSON.stringify(value));

function assertSites(findings: Finding[], positive: boolean): void {
  assert.deepEqual(findings.map(finding => finding.location.line), positive ? [38] : []);
  for (const finding of findings) {
    assert.equal(finding.metadata.entry, "renounceRole");
    assert.equal(finding.metadata.origin, "computed-proof");
    assert.equal(finding.metadata.evidence, "successful-history-without-enforced-trusted-root");
    assert.equal(finding.metadata.doesNotProve, "authorization-or-exploitability");
    assert.equal(finding.metadata.reviewRequired, true);
    assert.equal(finding.trace.find(step => step.kind === "effect")?.location.line, 40);
  }
}

test("membership-lifecycle owned lifecycle keeps exact membership evidence across instruction/reference and cache modes", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const program = new Program(fileFor(variant));
    let histories: string[] | undefined, findings: Finding[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all-private", true).analyze();
      const actual = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assertSites(actual, variant === "positive");
      findings ??= actual;
      assert.deepEqual(actual, findings);
      const current = semanticPaths(facts);
      histories ??= current;
      assert.deepEqual(current, histories);
    }
  }
});

test("membership-lifecycle selected, default and supervised scans agree on membership review sites", async () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = fileFor(variant);
    const targeted = scanFile(file, { detectors: [rule.id] });
    assert.equal(targeted.status, "complete", JSON.stringify(targeted.diagnostics));
    assertSites(targeted.findings, variant === "positive");
    const direct = scanFile(file);
    const isolated = await scanFileIsolated(file);
    const targetedIsolated = await scanFileIsolated(file, { detectors: [rule.id] });
    assert.equal(targetedIsolated.status, "complete", JSON.stringify(targetedIsolated.diagnostics));
    assert.deepEqual(targetedIsolated.findings, transported(targeted.findings));
    for (const report of [direct, isolated]) {
      // Other default rules have independent obligations; this is not an
      // assertion that the contract as a whole has a clean default scan.
      assert.equal(report.coverage.baselineStatus, "complete", JSON.stringify(report.diagnostics));
      assert.ok(report.coverage.detectors.includes(rule.id));
      const coverage = report.coverage.rules?.filter(row => row.detectorId === rule.id);
      assert.ok(coverage?.length);
      assert.ok(coverage.every(row => row.status === "complete"), JSON.stringify(coverage));
      assert.deepEqual(transported(selected(report.findings)), transported(targeted.findings));
    }
  }
});

test("membership-lifecycle original mapped slice retains frozen bytes while required equality closes its historical miss", () => {
  const file = resolve("tests/corpus/synthetic-regressions/state16/merkle-membership-not-enforced-case-36-positive.compact");
  assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"),
    "e385a4930a625f7b87ac2bf795acf4f490752657c2c59d6aae4a7d2eca8ddc3e");
  // The separately supplied nullifier is required to equal the commitment's
  // hash before insertion. Equality dependencies now relate it to the proof.
  // Earlier measured misses remain historical evidence; this partial source
  // still does not establish growth, proof feasibility or future grant effects.
  const report = scanFile(file, { detectors: [rule.id] });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.deepEqual(report.findings.map(finding => finding.location.line), [14]);
  assert.equal(report.findings[0].metadata.entry, "renounce");
  assert.equal(report.findings[0].metadata.origin, "computed-proof");
  assert.equal(report.findings[0].metadata.doesNotProve, "authorization-or-exploitability");
});
