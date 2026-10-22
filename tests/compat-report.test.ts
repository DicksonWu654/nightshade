import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const { precisionScope, summarize, summarizeCorpus, firstFrontendFailures, scanCategory, matchesScanProfile } = await import(pathToFileURL(resolve("scripts/bench-compat.mjs")).href);

test("compat completion labels valid zero-entry fixtures without masking failures", () => {
  const report = { status: "complete", entrypoints: [], diagnostics: [{ code: "no-entrypoints-analyzed", message: "No entrypoints analyzed; declaration checks completed.",
    location: { file: "root", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } }],
    coverage: { baselineStatus: "complete", resolved: ["root"], noEntrypointRoots: ["root"] } };
  assert.equal(scanCategory(report), "complete");
  assert.equal(scanCategory({ ...report, diagnostics: [] }), "other-incomplete");
  assert.equal(scanCategory({ ...report, diagnostics: [{ ...report.diagnostics[0], message: "forged" }] }), "other-incomplete");
  assert.equal(scanCategory({ ...report, diagnostics: [...report.diagnostics, { code: "analysis-error" }] }), "other-incomplete");
  assert.equal(scanCategory({ ...report, coverage: { ...report.coverage, noEntrypointRoots: [] } }), "other-incomplete");
  assert.equal(scanCategory({ ...report, coverage: { ...report.coverage, noEntrypointRoots: ["other"] } }), "other-incomplete");
  assert.equal(scanCategory({ ...report, diagnostics: [{ code: "worker-timeout" }] }), "other-incomplete");
  assert.equal(scanCategory({ ...report, entrypoints: ["entry"] }), "other-incomplete");
  assert.equal(summarize([{ category: "complete", completionLabel: "no entrypoints analyzed", elapsedSeconds: 1, findings: [] }]).noEntrypointRoots, 1);
});

test("compat recognizes only empty explicit unsupported-profile envelopes, never analysis under another profile", () => {
  const result = { semanticProfile: "compact-0.34.0-zkir3", status: "incomplete", entrypoints: [], findings: [],
    diagnostics: [{ code: "unsupported-compiler-profile" }],
    coverage: { baselineStatus: "incomplete", resolved: [], completedEntries: [], detectors: [] },
    metrics: { frontendMs: 0, analysisMs: 0, detectorMs: 0, cfgNodes: 0, instructionNodes: 0, calls: 0, steps: 0, sources: 0,
      paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0, statefulSummaryHits: 0, readSummaryHits: 0,
      summaryEffects: 0, guardSubsumptions: 0 } };
  for (const version of ["0.28.0", "0.29.0", "0.30.0", "0.31.1", "0.33.0-rc.2", "0.35.0-rc.1", "0.35.0"]) {
    assert.equal(matchesScanProfile(result,version,3),true);
    assert.equal(matchesScanProfile(result,version,2),false);
    for (const patch of [{ status: "complete" }, { findings: [{}] }, { entrypoints: ["entry"] },
      ...[[],undefined,null,{},42,"unsupported-compiler-profile",[null]].map(diagnostics => ({ diagnostics })),
      { diagnostics: [{ code: "unsupported-compiler-profile", scope: { kind: "rule" } }] },
      { ruleObservationWork: [{}] },
      { semanticProfile: "compact-0.31.1-zkir2" },
      ...["resolved","completedEntries","detectors","rules"].map(key => ({ coverage: { ...result.coverage, [key]: ["evidence"] } })),
      { coverage: { ...result.coverage, baselineStatus: "complete" } },
      ...Object.keys(result.metrics).map(key => ({ metrics: { ...result.metrics, [key]: 1 } }))]) {
      assert.equal(matchesScanProfile({ ...result, ...patch },version,3),false,JSON.stringify(patch));
    }
  }
  assert.equal(matchesScanProfile(result,"0.99.0",3),false);
  assert.equal(matchesScanProfile({ ...result, semanticProfile: "compact-0.35.0-zkir2" },"0.35.0",2),true);
  assert.equal(scanCategory(result),"frontend");
});

test("compat precision excludes only pinned intentional entries while retaining findings", () => {
  const app = { repository: "synthetic", file: "fixtures/intentional-helper.compact",
    precisionExcludedEntries: [{ entry: "_transferOwnership", reason: "intentional-helper-exposure" }] };
  assert.ok(app.precisionExcludedEntries.some(row => row.entry === "_transferOwnership"));
  assert.equal(precisionScope(app, { callPath: ["_transferOwnership", "_unsafeUncheckedTransferOwnership"] }), "intentional-helper-exposure");
  assert.equal(precisionScope(app, { callPath: ["transferOwnership", "_transferOwnership"] }), "eligible");
  assert.equal(precisionScope(app, { callPath: [] }), "eligible", "Unattributed findings are not silently excluded");
  assert.equal(precisionScope({ repository: "community", file: app.file }, { callPath: ["_transferOwnership"] }), "eligible", "Naming alone supplies no exclusion");
  assert.equal(precisionScope({ repository: "compact-compiler" }, { callPath: ["entry"] }), "compiler-fixture");
  const findings = ["eligible", "intentional-helper-exposure", "compiler-fixture", undefined].map(precisionScope => ({ precisionScope }));
  const summary = summarize([{ category: "complete", frontendAccepted: true, elapsedSeconds: 1, findings }]);
  assert.equal(summary.findings, 4);
  assert.equal(summary.precisionEligibleFindings, 1);
  assert.equal(summary.precisionExcludedFindings, 2);
  assert.equal(summary.precisionUnclassifiedFindings, 1);
});

test("compat front-end acceptance distinguishes front-end budgets, dataflow budgets and worker failures", () => {
  const row = (file: string, frontendAccepted: boolean, category: string, code: string, elapsedSeconds: number) => ({
    repository: "example", file, frontendAccepted, category, elapsedSeconds, diagnostics: code ? [{ code, message: code }] : [], findings: [],
  });
  const rows = [row("complete", true, "complete", "", 3), row("unknown-export", false, "frontend", "unresolved-name", 0.1),
    row("large-loop", false, "budget", "loop-budget", 0.2), row("path-budget", true, "budget", "analysis-budget", 4),
    row("worker", false, "other-incomplete", "worker-timeout", 60), row("no-entry", true, "other-incomplete", "no-entrypoints", 0.1)];
  assert.deepEqual(firstFrontendFailures(rows).map((row: { file: string }) => row.file), ["unknown-export", "large-loop"]);
  const summary = summarize(rows);
  assert.equal(summary.apps, 6);
  assert.equal(summary.complete, 1);
  assert.equal(summary.frontendAccepted, 3);
  assert.equal(summary.budget, 2);
  assert.deepEqual(summary.timing.complete, { medianSeconds: 3, p95Seconds: 3, maxSeconds: 3 });
  assert.equal(summary.timing.all.p95Seconds, 60);
  assert.equal(summarize([]).timing.complete, null);
  const corpus = summarizeCorpus(rows, [{ compilerExitCode: 255 }]);
  assert.equal(corpus.totalApps, 7, "Compiler rejects stay in the whole-corpus denominator");
  assert.equal(corpus.apps, 6, "Scanner-qualified count is separate");
  assert.equal(corpus.compilerRejected, 1);
});


test("compat distinguishes rule incompleteness from baseline and worker failure", () => {
  const scope = { kind: "rule", detectorId: "low-entropy-hash-disclosure", entry: "root::entry" };
  const result = { status: "incomplete", coverage: { baselineStatus: "complete", resolved: ["root"] }, diagnostics: [{ code: "analysis-budget", scope }] };
  assert.equal(scanCategory(result), "complete");
  assert.equal(scanCategory({ ...result, coverage: { ...result.coverage, baselineStatus: "incomplete" }, diagnostics: [{ code: "analysis-budget" }] }), "budget");
  assert.equal(scanCategory(result, "worker aborted"), "other-incomplete");
  assert.equal(scanCategory({ status: "incomplete", coverage: { resolved: [] }, diagnostics: [{ code: "worker-timeout" }] }), "other-incomplete");
  const entries = [{ detectorId: "hash", status: "incomplete" }, { detectorId: "hash", status: "complete" }];
  const summary = summarize([{ category: "complete", selectedRulesStatus: "incomplete", frontendAccepted: true, elapsedSeconds: 1, findings: [], ruleCoverage: entries }]);
  assert.equal(summary.complete, 1); assert.equal(summary.selectedRulesComplete, 0);
  assert.deepEqual(summary.ruleCoverage, [{ detectorId: "hash", entries: 2, complete: 1, notApplicable: 0, incomplete: 1 }]);
});
