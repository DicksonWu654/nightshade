import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { digest } from "./generative/artifacts.js";
import { expectedFlagObservations, renderCase, type GeneratedCase } from "./generative/model.js";
import { checkRuntimeObservation, incompleteRuntimeResult, makeRuntimeArtifact, RUNTIME_LIMITS, type RuntimeCheckResult, type RuntimeIdentity } from "./generative/runtime-artifacts.js";
import { auditRuntimeCampaign, makeGuidedManifest, type AuditedGuidedCampaign, type GuidedRow } from "./generative/runtime-guided.js";
import { compareGuidedResults, RuntimeCampaignReplay } from "./generative/runtime-guided-replay.js";
import { DEFAULT_SCHEDULE, RuntimeSchedule, type ScheduleOptions, type ScheduleRow } from "./generative/runtime-schedule.js";

const identity: RuntimeIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: "0".repeat(64), runtimeInputsManifestSha256: "1".repeat(64), runtimeAdapterSourceSha256: "2".repeat(64), runtimeAdapterBuildSha256: "3".repeat(64) };
const save = (directory: string, name: string, value: unknown) => {
  const text = JSON.stringify(value, null, 2) + "\n";
  writeFileSync(resolve(directory, name), text);
  return digest(text);
};
const load = (directory: string, name: string) => JSON.parse(readFileSync(resolve(directory, name), "utf8"));

/** Synthetic schema fixture, not evidence that a runtime executed. */
function fixture(input: GeneratedCase): RuntimeCheckResult {
  return checkRuntimeObservation(input, { layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: digest(renderCase(input)), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(row => row.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })) });
}

function writeTranscript(directory: string, options: ScheduleOptions, metadata: RuntimeIdentity, result: (input: GeneratedCase, ordinal: number) => RuntimeCheckResult,
  interruptedAfter?: number, limits = { ...RUNTIME_LIMITS } as { timeoutMs: number; heapMiB: number; maxOutputBytes: number }): AuditedGuidedCampaign {
  const schedule = new RuntimeSchedule(options);
  const rows: GuidedRow[] = [];
  while (schedule.snapshot().outcome.status === "running") {
    if (rows.length === interruptedAfter) { schedule.interrupt(); break; }
    const proposed = schedule.next()!;
    const prefix = String(proposed.ordinal).padStart(4, "0"), decision = `${prefix}-decision.json`, artifact = `${prefix}.json`;
    const decisionSha256 = save(directory, decision, proposed);
    const checked = result(proposed.case, proposed.ordinal);
    const artifactSha256 = save(directory, artifact, makeRuntimeArtifact(proposed.case, metadata, limits, checked));
    rows.push({ ...schedule.record(checked, artifactSha256), decision, decisionSha256, artifact, artifactSha256 });
  }
  save(directory, "summary.json", makeGuidedManifest(schedule, metadata, limits, rows));
  return auditRuntimeCampaign(directory);
}

function synthetic(check: (saved: AuditedGuidedCampaign) => void, options: Partial<ScheduleOptions> = {}, interruptedAfter?: number,
  result: (input: GeneratedCase) => RuntimeCheckResult = fixture) {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-synthetic-replay-"));
  try { check(writeTranscript(directory, { ...DEFAULT_SCHEDULE, mutations: 4, ...options }, identity, result, interruptedAfter)); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}

test("replay rederives measured parents while comparing original and new artifact namespaces", () => {
  synthetic(saved => {
    const replay = new RuntimeCampaignReplay(saved, true);
    let proposal;
    let changedParent = false;
    while ((proposal = replay.next())) {
      assert.equal(proposal.sameDecision, true);
      const original = saved.steps[proposal.decision.ordinal - 1];
      if (proposal.decision.parent) {
        changedParent ||= proposal.decision.parent.artifactSha256 !== original.decision.parent!.artifactSha256;
        assert.equal(proposal.decision.parent.ordinal, original.decision.parent!.ordinal);
      }
      const result = structuredClone(original.artifact.result);
      result.observation!.compiledJavaScriptSha256 = "b".repeat(64);
      result.feedback!.compiledJavaScriptSha256 = "b".repeat(64);
      const checked = replay.record(result, digest(`new-artifact-${proposal.decision.ordinal}`));
      assert.equal(checked.comparison.sameCompiledJavaScript, false);
      assert.equal(checked.comparison.sameObservation, true);
      assert.equal(checked.comparison.sameFeedback, true);
      assert.equal(checked.comparison.matched, true);
    }
    assert.equal(changedParent, true);
    assert.equal(replay.snapshot().outcome.status, "passed");
    assert.equal(replay.snapshot().recordedPrefixMatched, true);
    assert.equal(replay.snapshot().fullPassingScheduleReplayed, true);
  });
});

test("exact replay rejects compiled code drift even with matching observations", () => {
  synthetic(saved => {
    const replay = new RuntimeCampaignReplay(saved);
    replay.next();
    const changed = structuredClone(saved.steps[0].artifact.result);
    changed.observation!.compiledJavaScriptSha256 = "b".repeat(64);
    changed.feedback!.compiledJavaScriptSha256 = "b".repeat(64);
    const checked = replay.record(changed, "b".repeat(64));
    assert.equal(checked.comparison.sameObservation, true);
    assert.equal(checked.comparison.matched, false);
    assert.equal(replay.snapshot().outcome.category, "runtime-replay-result-drift");
    assert.equal(replay.next(), undefined);
  });
});

test("build comparison cannot excuse outcome, feedback, admission or input association drift", () => {
  synthetic(saved => {
    const { decision: _d, decisionSha256: _dh, artifact: _a, artifactSha256: _ah, ...row } = saved.manifest.rows[0];
    const before = saved.steps[0].artifact.result;
    for (const field of ["outcome", "feedback", "admission", "observation"]) {
      const after = structuredClone(before);
      const changedRow: ScheduleRow = structuredClone(row);
      if (field === "outcome") changedRow.category = "invented-category";
      if (field === "feedback") after.feedback!.features.push("invented-measured-feature");
      if (field === "admission") changedRow.admission!.newFeatures = [];
      if (field === "observation") after.observation!.executions[0].result = [];
      assert.equal(compareGuidedResults(before, after, row, changedRow, true).matched, false, field);
    }
    const replay = new RuntimeCampaignReplay(saved, true);
    const proposal = replay.next()!;
    const wire = structuredClone(before.observation!);
    wire.executions[0].result = [];
    const disagreement = checkRuntimeObservation(proposal.decision.case, wire);
    assert.equal(disagreement.status, "failed");
    const checked = replay.record(disagreement, "b".repeat(64));
    assert.equal(checked.comparison.sameStatus, false);
    assert.equal(checked.comparison.sameFeedback, false);
    assert.equal(replay.snapshot().outcome.category, "runtime-replay-result-drift");
    assert.equal(replay.snapshot().attempted, 1);
    assert.equal(replay.next(), undefined);
  });
});

test("saved incomplete prefixes and interruptions cannot become passing full schedules", () => {
  for (const interruption of [0, 2]) synthetic(saved => {
    const replay = new RuntimeCampaignReplay(saved);
    let proposal;
    while ((proposal = replay.next())) replay.record(saved.steps[proposal.decision.ordinal - 1].artifact.result, digest(`new:${proposal.decision.ordinal}`));
    const state = replay.snapshot();
    assert.equal(state.outcome.status, "incomplete");
    assert.equal(state.outcome.category, "runtime-replay-saved-incomplete");
    assert.equal(state.finalComparison!.sameScheduleOutcome, null, "a saved signal is not re-enacted");
    assert.equal(state.fullPassingScheduleReplayed, false);
    assert.equal(state.executionReplay, interruption > 0);
    assert.equal(state.measured, interruption);
  }, {}, interruption);
  synthetic(saved => {
    const replay = new RuntimeCampaignReplay(saved);
    let proposal;
    while ((proposal = replay.next())) replay.record(saved.steps[proposal.decision.ordinal - 1].artifact.result, digest(`bounded:${proposal.decision.ordinal}`));
    assert.equal(replay.snapshot().outcome.category, "runtime-evaluation-budget");
    assert.equal(replay.snapshot().recordedPrefixMatched, true);
    assert.equal(replay.snapshot().fullPassingScheduleReplayed, false);
  }, { maxEvaluations: 2 });
});

test("worker failures, new interruption and invalid evidence do not advance a replay as clean", () => {
  synthetic(saved => {
    const replay = new RuntimeCampaignReplay(saved);
    const proposal = replay.next()!;
    const before = replay.snapshot();
    const corrupt = structuredClone(saved.steps[0].artifact.result);
    corrupt.feedback!.features.push("invented");
    assert.throws(() => replay.record(corrupt, "b".repeat(64)));
    assert.deepEqual(replay.snapshot(), before);
    assert.deepEqual(replay.next(), proposal);
    const checked = replay.record(incompleteRuntimeResult("worker-timeout", "Synthetic timeout; no runtime execution"), "b".repeat(64));
    assert.equal(checked.comparison.matched, false);
    assert.equal(replay.snapshot().outcome.category, "worker-timeout");
    assert.equal(replay.snapshot().measured, 0);
    assert.equal(replay.next(), undefined);
    const interrupted = new RuntimeCampaignReplay(saved);
    interrupted.interrupt();
    assert.equal(interrupted.snapshot().outcome.category, "runtime-replay-interrupted");
    assert.equal(interrupted.snapshot().executionReplay, false);
  });
});

test("proposal mismatch is explicit and cannot authorize a worker evaluation", () => {
  synthetic(saved => {
    // Post-audit fault injection into this synthetic in-memory test only.
    saved.steps[0].decision.random.before++;
    const replay = new RuntimeCampaignReplay(saved);
    assert.equal(replay.next()!.sameDecision, false);
    assert.equal(replay.snapshot().outcome.category, "runtime-replay-decision-drift");
    assert.equal(replay.snapshot().attempted, 0);
    assert.throws(() => replay.record(saved.steps[0].artifact.result, "b".repeat(64)), /executable/);
  });
});

function cli(args: string[]) {
  return spawnSync(process.execPath, [resolve("dist/tests/generative/runtime-guided.js"), ...args], { encoding: "utf8", timeout: 120000, maxBuffer: 1024 * 1024 });
}
const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };

test("actual campaign execution replay matches; identity drift requires explicit build comparison", qualified, () => {
  assert.ok(process.env.COMPACTC_TEST, "Runtime qualification also requires pinned COMPACTC_TEST");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-measured-campaign-replay-"));
  try {
    const source = resolve(directory, "original");
    const generated = cli(["--output", source, "--mutations", "1", "--seed", "42"]);
    assert.equal(generated.status, 0, generated.stderr || generated.stdout);
    const audited = auditRuntimeCampaign(source);
    const originalSummary = readFileSync(resolve(source, "summary.json"));
    const exact = resolve(directory, "exact");
    const rerun = cli(["--replay-campaign", source, "--output", exact]);
    assert.equal(rerun.status, 0, rerun.stderr || rerun.stdout);
    const report = load(exact, "summary.json");
    assert.equal(report.mode, "exact-replay");
    assert.equal(report.comparison, false);
    assert.equal(report.attempted, 5);
    assert.equal(report.measured, 5);
    assert.equal(report.executionReplay, true);
    assert.equal(report.fullPassingScheduleReplayed, true);
    assert.equal(report.originalManifestSha256, digest(originalSummary));
    assert.deepEqual(report.changedIdentityFields, []);
    assert.ok(report.rows.every((row: any) => row.sameDecision && row.checked.comparison.matched));
    assert.deepEqual(readFileSync(resolve(source, "summary.json")), originalSummary);
    assert.equal(cli(["--replay-campaign", source, "--output", exact]).status, 2);
    assert.equal(cli(["--replay-campaign", source, "--output", resolve(source, "nested")]).status, 2);
    assert.equal(existsSync(resolve(source, "nested")), false);
    symlinkSync(source, resolve(directory, "alias"), "dir");
    assert.equal(cli(["--replay-campaign", source, "--output", resolve(directory, "alias", "nested")]).status, 2);

    // Rewrite only test metadata and compiled identities, preserving actual
    // observed values. This simulates drift; it is not a second compiler build.
    const changed = mkdtempSync(resolve(directory, "changed-"));
    writeTranscript(changed, audited.manifest.options, { ...audited.manifest.identity, node: "v0.0.0" }, (_input, ordinal) => {
      const result = structuredClone(audited.steps[ordinal - 1].artifact.result);
      result.observation!.compiledJavaScriptSha256 = "f".repeat(64);
      result.feedback!.compiledJavaScriptSha256 = "f".repeat(64);
      return result;
    });
    const refused = resolve(directory, "refused");
    const refusal = cli(["--replay-campaign", changed, "--output", refused]);
    assert.equal(refusal.status, 2);
    assert.match(refusal.stderr, /identity mismatch/);
    assert.equal(existsSync(refused), false);
    const compared = resolve(directory, "compared");
    const comparison = cli(["--replay-campaign", changed, "--output", compared, "--compare-build"]);
    assert.equal(comparison.status, 0, comparison.stderr || comparison.stdout);
    const comparedReport = load(compared, "summary.json");
    assert.equal(comparedReport.mode, "build-comparison");
    assert.equal(comparedReport.comparison, true);
    assert.deepEqual(comparedReport.changedIdentityFields, ["node"]);
    assert.ok(comparedReport.rows.every((row: any) => row.checked.comparison.sameCompiledJavaScript === false && row.checked.comparison.sameObservation && row.checked.comparison.sameFeedback));
    const newParent = load(compared, "0005-decision.json").parent;
    assert.equal(newParent.artifactSha256, comparedReport.rows[newParent.ordinal - 1].artifactSha256);
    assert.notEqual(newParent.artifactSha256, auditRuntimeCampaign(changed).steps[newParent.ordinal - 1].artifactSha256);

    const corrupt = resolve(directory, "corrupt");
    cpSync(source, corrupt, { recursive: true });
    const manifest = load(corrupt, "summary.json"), artifact = load(corrupt, "0001.json");
    artifact.result.feedback.features.push("invented-feature");
    manifest.rows[0].artifactSha256 = save(corrupt, "0001.json", artifact);
    save(corrupt, "summary.json", manifest);
    const noExecution = resolve(directory, "no-execution");
    assert.equal(cli(["--replay-campaign", corrupt, "--output", noExecution]).status, 2);
    assert.equal(existsSync(noExecution), false, "corrupt audit evidence cannot launch replay");

    const wrongOutcome = mkdtempSync(resolve(directory, "injected-outcome-"));
    writeTranscript(wrongOutcome, audited.manifest.options, audited.manifest.identity, input => {
      const wire = structuredClone(audited.steps[0].artifact.result.observation!);
      wire.executions[0].result = []; // Postmeasurement test fault, not a runtime bug.
      return checkRuntimeObservation(input, wire);
    });
    const drift = resolve(directory, "drift");
    assert.equal(cli(["--replay-campaign", wrongOutcome, "--output", drift, "--compare-build"]).status, 2);
    const driftReport = load(drift, "summary.json");
    assert.equal(driftReport.outcome.category, "runtime-replay-result-drift");
    assert.equal(driftReport.attempted, 1);
    assert.equal(driftReport.rows[0].checked.comparison.sameStatus, false);
    assert.equal(driftReport.rows[0].checked.comparison.sameFeedback, false);
    assert.equal(load(drift, "0001.json").result.status, "passed", "fresh evidence must remain accurate even on replay mismatch");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("[timing] actual replay preserves the original worker timeout and cannot upgrade incomplete evidence", qualified, () => {
  assert.ok(process.env.COMPACTC_TEST, "Runtime qualification also requires pinned COMPACTC_TEST");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-campaign-replay-budget-"));
  try {
    const source = resolve(directory, "timed");
    assert.equal(cli(["--output", source, "--mutations", "1", "--timeout-ms", "1"]).status, 2);
    const output = resolve(directory, "replayed");
    assert.equal(cli(["--replay-campaign", source, "--output", output]).status, 2);
    const summary = load(output, "summary.json");
    assert.equal(summary.limits.timeoutMs, 1);
    assert.equal(summary.attempted, 1);
    assert.equal(summary.measured, 0);
    assert.equal(summary.outcome.category, "worker-timeout");
    assert.equal(summary.fullPassingScheduleReplayed, false);
    assert.equal(load(output, "0001.json").result.status, "incomplete");
    const refused = resolve(directory, "override");
    assert.equal(cli(["--replay-campaign", source, "--output", refused, "--timeout-ms", "60000"]).status, 2);
    assert.equal(existsSync(refused), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
