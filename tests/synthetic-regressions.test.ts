import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { detectors, type Finding } from "../src/index.js";
import { assessReproductionCase, corpusFile, loadReproductionRegistry, reproductionKinds, type ReproductionCase, type ReproductionCheck } from "./synthetic-regression-fixtures.js";

test("synthetic regression registry keeps unique triplets, exact targets and source hashes", () => {
  const registry = loadReproductionRegistry();
  assert.equal(registry.cases.length, 123);
  for (const source of registry.cases) for (const target of source.targets)
    assert.ok(detectors.some(rule => rule.id === target.detector), `${source.id}: ${target.detector}`);
  assert.throws(() => corpusFile("../../outside.compact"), /outside owned corpus/);
});

const item: ReproductionCase = { id: "measurement-boundary", compilerVersion: "0.34.0", zkirVersion: 2, requiresOZ: false,
  checks: Object.fromEntries(reproductionKinds.map(kind => [kind, { file: `measurement-${kind}.compact`, sha256: "unused-in-scoring" }])) as ReproductionCase["checks"],
  targets: [{ detector: "relevant-rule", positiveLines: [7] }], groundTruthStatus: "source-reviewed-sites", scope: "Measurement failure boundaries" };
function checks(): ReproductionCheck[] {
  return reproductionKinds.map(kind => ({ kind, compilerValid: true,
    report: { status: "complete", entrypoints: ["entry"], diagnostics: [],
      findings: kind === "positive" ? [{ detectorId: "relevant-rule", location: { file: corpusFile(item.checks[kind].file), line: 7 } } as Finding] : [],
      coverage: { noEntrypointRoots: [], attempted: [], parsed: [], resolved: [], completedEntries: ["entry"], detectors: ["relevant-rule"], baselineStatus: "complete",
        rules: [{ root: "root", entry: "entry", detectorId: "relevant-rule", status: "complete", evidence: "exact-observation", diagnosticCodes: [] }] } } }));
}

test("mapped evidence requires compiler acceptance, exact source sites and quiet complete controls", () => {
  assert.equal(assessReproductionCase(item, checks()).qualifiedSourceClass, true);
  const altered = checks(); altered[1].compilerValid = false;
  assert.equal(assessReproductionCase(item, altered).qualifiedSourceClass, false);
  const incomplete = checks(); incomplete[2].report.coverage.rules![0].status = "incomplete";
  assert.equal(assessReproductionCase(item, incomplete).quietControls, false);
  const missingEntry = checks(); missingEntry[0].report.entrypoints.push("unreported-entry");
  assert.equal(assessReproductionCase(item, missingEntry).positiveDetected, false);
  const collision = checks(); collision[0].report.findings[0].location.file = resolve("tests/corpus/another-source.compact");
  assert.equal(assessReproductionCase(item, collision).positiveDetected, false);
  const absentRule = checks(); for (const check of absentRule) check.report.coverage.detectors = [];
  assert.equal(assessReproductionCase(item, absentRule).qualifiedSourceClass, false);
});

test("matching corrections and intentional lookalikes cannot earn quiet-control credit", () => {
  const observed = checks();
  observed[1].report.findings = [{ detectorId: "relevant-rule", location: { file: corpusFile(item.checks.corrected.file), line: 8 } } as Finding];
  const expectedMatch = { ...item, targets: [{ ...item.targets[0], correctedLines: [8] }] };
  const measured = assessReproductionCase(expectedMatch, observed);
  assert.equal(measured.positiveDetected, true);
  assert.equal(measured.targets[0].observations[1].exactSites, true);
  assert.equal(measured.quietControls, false);
  assert.equal(measured.qualifiedSourceClass, false);
  const pending = assessReproductionCase({ ...item, targets: [], groundTruthStatus: "pending-mapped-sites" }, checks());
  assert.equal(pending.positiveDetected, false);
  assert.equal(pending.qualifiedSourceClass, false);
});

test("unrelated incompleteness stays visible while mapped coverage is assessed separately", () => {
  const observed = checks();
  observed[0].report.status = "incomplete";
  observed[0].report.diagnostics.push({ code: "other-rule-budget", message: "Other observation incomplete", location: observed[0].report.findings[0].location });
  observed[0].report.coverage.rules!.push({ root: "root", entry: "entry", detectorId: "other-rule", status: "incomplete", evidence: "unavailable", diagnosticCodes: ["other-rule-budget"] });
  const result = assessReproductionCase(item, observed);
  assert.equal(result.qualifiedSourceClass, true);
  assert.equal(result.rootStatuses[0].status, "incomplete");
  assert.deepEqual(result.rootStatuses[0].diagnosticCodes, ["other-rule-budget"]);
});
