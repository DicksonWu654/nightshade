import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { incompletePersistentResult, makePersistentArtifact, runPersistentSequenceIsolated, validatePersistentArtifact, type PersistentResult } from "./generative/persistent-artifacts.js";
import { extractPersistentFeedback } from "./generative/persistent-feedback.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";
import { PersistentSchedule } from "./generative/persistent-schedule.js";
import { foldPersistentSchedule } from "./generative/persistent-schedule-audit.js";
import { readAuditedPersistentGuided } from "./generative/persistent-guided-audit.js";
import { persistentGuidedBuildIdentity, persistentGuidedCounts, persistentGuidedNames, persistentGuidedOutcome, PERSISTENT_GUIDED_LIMITS, validatePersistentGuidedConfiguration, type PersistentGuidedFileReference, type PersistentGuidedIdentity, type PersistentGuidedInvocation, type PersistentGuidedSummary } from "./generative/persistent-guided-format.js";
import { writePersistentGuidedRun, type PersistentGuidedEvaluator } from "./generative/persistent-guided.js";
import { persistentGuidedReplayMain, replayPersistentGuided, validatePersistentGuidedReplayConfiguration, type PersistentGuidedReplayInvocation } from "./generative/persistent-guided-replay.js";

const identity: PersistentGuidedIdentity = {
  persistent: { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 },
  modules: { feedback: { sourceSha256: "4".repeat(64), builtSha256: "5".repeat(64) }, corpus: { sourceSha256: "6".repeat(64), builtSha256: "7".repeat(64) }, schedule: { sourceSha256: "8".repeat(64), builtSha256: "9".repeat(64) } },
};
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const config = (mutations = 0) => validatePersistentGuidedConfiguration({ schedule: { seed: 7, mutations, maxEvaluations: 4 + mutations }, workerLimits: limits });
const json = (directory: string, name = "summary.json") => JSON.parse(readFileSync(resolve(directory, name), "utf8"));
function root(context: TestContext): string { const path = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-persistent-replay-"))); context.after(() => rmSync(path, { recursive: true, force: true })); return path; }

/** Synthetic schema-only observations, never evidence of compiled execution. */
function wire(sequence: PersistentSequence, salt = "synthetic"): PersistentObservation {
  const expected = expectedPersistentSequence(sequence), view = (state: { count: string; next: string }) => ({ ...state, publicSha256: persistentDigest(`${salt}:${state.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)), initial: view(expected.initial), rows: expected.rows.map(row => ({ ...row, before: view(row.before), after: view(row.after), slots: row.slots.map(view) })), final: view(expected.final) };
}
const checked = (sequence: PersistentSequence, observation = wire(sequence)) => checkPersistentObservation(sequence, observation, PERSISTENT_SOURCE_SHA256);
const passing: PersistentGuidedEvaluator = async sequence => checked(sequence);
const source = (directory: string, configuration: unknown = config(), evaluate = passing) => writePersistentGuidedRun(directory, configuration, evaluate, () => identity, undefined, () => 0);
const replay = (input: string, output: string, evaluate = passing) => replayPersistentGuided(input, output, evaluate, () => identity, {}, undefined, () => 0);
function failure(sequence: PersistentSequence, next = "99"): PersistentResult { const observation = wire(sequence); observation.initial.next = next; return checked(sequence, observation); }

/** Rebuild a consistent minified archive with genuine original-byte parent links. */
function compactArchive(input: string, output: string, tightByteBudget = false): PersistentGuidedSummary {
  const audited = readAuditedPersistentGuided(input), saved = audited.summary;
  const configuration = structuredClone(saved.configuration);
  if (tightByteBudget) configuration.corpusBudgets.maxEvidenceBytes = audited.steps.reduce((sum, step) => sum + Buffer.byteLength(JSON.stringify(step.artifact)), 0);
  const schedule = new PersistentSchedule(identity.persistent, configuration.workerLimits, configuration.schedule, configuration.corpusBudgets);
  mkdirSync(output);
  const originals: Buffer[] = [], invocations: PersistentGuidedInvocation[] = [], files: PersistentGuidedSummary["files"] = [];
  let evidenceBytes = 0;
  const save = (name: string, value: unknown): PersistentGuidedFileReference => {
    const bytes = Buffer.from(JSON.stringify(value)); writeFileSync(resolve(output, name), bytes, { flag: "wx" }); evidenceBytes += bytes.length;
    return { name, sha256: persistentDigest(bytes), bytes: bytes.length };
  };
  for (const step of audited.steps) {
    const decision = schedule.next()!;
    assert.deepEqual(decision.sequence, step.artifact.sequence);
    const names = persistentGuidedNames(decision.ordinal), decisionRef = save(names.decision, decision), artifact = save(names.artifact, step.artifact);
    const original = readFileSync(resolve(output, names.artifact)); originals.push(original); schedule.record(original);
    const invocation: PersistentGuidedInvocation = { ...structuredClone(step.invocation), decision: decisionRef, artifact };
    assert.equal(invocation.returnedArtifact, null); invocations.push(invocation);
    files.push({ ordinal: decision.ordinal, decision: decisionRef, artifact, invocation: save(names.invocation, invocation), returnedArtifact: null });
  }
  const transcript = foldPersistentSchedule(identity.persistent, configuration.workerLimits, configuration.schedule, configuration.corpusBudgets, originals, saved.transcript.stopReason).transcript;
  const summary: PersistentGuidedSummary = { ...saved, configuration, transcript, files, counts: persistentGuidedCounts(transcript, invocations), outcome: persistentGuidedOutcome(transcript, invocations, saved.elapsedMs, configuration, saved.postIdentity, saved.finalAbortCause), evidenceBytesBeforeSummary: evidenceBytes };
  save("summary.json", summary); assert.deepEqual(readAuditedPersistentGuided(output).summary, summary);
  return summary;
}

test("exact replay records fixed limits, full evidence and new parent associations in a fresh bounded archive", async context => {
  const directory = root(context), input = resolve(directory, "input"), output = resolve(directory, "replay"), saved = await source(input, config(3));
  let calls = 0;
  const summary = await replay(input, output, async (sequence, workerLimits) => {
    calls++; assert.deepEqual(workerLimits, limits); assert.equal(existsSync(resolve(output, persistentGuidedNames(calls).decision)), true);
    return checked(sequence);
  });
  assert.equal(calls, 7); assert.deepEqual(summary.outcome, { status: "passed", diagnostics: [] });
  assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.allArtifactBytesMatched, true); assert.equal(summary.reproducedQualifiedFailure, false);
  assert.deepEqual(summary.saved.outcome, saved.outcome); assert.equal(summary.saved.summarySha256, persistentDigest(readFileSync(resolve(input, "summary.json"))));
  assert.ok(summary.rows.every(row => row.disposition === "matched" && row.sameDecision && row.comparison?.sameFullResult && row.comparison.sameArtifactBytes));
  assert.ok(Object.values(summary.scheduleComparison).every(Boolean)); assert.equal(summary.counts.evaluatorInvoked, 7);
  let actualBytes = 0;
  for (const row of summary.rows) for (const ref of Object.values(row.fresh)) if (ref) {
    const bytes = readFileSync(resolve(output, ref.name)); actualBytes += bytes.length;
    assert.equal(ref.sha256, persistentDigest(bytes)); assert.equal(ref.bytes, bytes.length);
  }
  assert.equal(actualBytes, summary.evidenceBytesBeforeSummary);
  assert.equal(readdirSync(output).length, 22); assert.ok(actualBytes + readFileSync(resolve(output, "summary.json")).length < PERSISTENT_GUIDED_LIMITS.archiveBytes);
  const invocation = json(output, "0001-invocation.json") as PersistentGuidedReplayInvocation;
  assert.deepEqual(invocation.workerLimits, limits); assert.equal(invocation.resultOrigin, "evaluator"); assert.equal(invocation.abortSource, null);
  assert.equal(invocation.timing.remainingMsAtLaunch, 60000);
  const disk = json(output); summary.rows.length = 0; summary.identity.modules.feedback.sourceSha256 = "0".repeat(64); assert.deepEqual(json(output), disk);
  await assert.rejects(() => replay(input, output, async () => assert.fail("No overwrite invocation")), /EEXIST/);
});

test("original formatting changes preserve semantic evidence and map only the validated parent ordinal", async context => {
  const directory = root(context), canonical = resolve(directory, "canonical"), input = resolve(directory, "minified"), output = resolve(directory, "replay");
  await source(canonical, config(3)); const saved = compactArchive(canonical, input);
  const summary = await replay(input, output);
  assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.allArtifactBytesMatched, false); assert.equal(summary.outcome.status, "passed");
  assert.equal(summary.scheduleComparison.sameRawSnapshot, false); assert.equal(summary.scheduleComparison.sameEvidenceBytes, false);
  assert.equal(summary.scheduleComparison.sameCorpusSemantics, true); assert.equal(summary.scheduleComparison.sameCounts, true);
  assert.ok(summary.rows.every(row => row.comparison?.sameFullResult && !row.comparison.sameArtifactBytes));
  const actual = summary.schedule.decisions[4], prior = saved.transcript.decisions[4];
  assert.ok(actual.parent && prior.parent); assert.equal(actual.parent.ordinal, prior.parent.ordinal);
  assert.notEqual(actual.parent.artifactSha256, prior.parent.artifactSha256);
  assert.equal(actual.parent.artifactSha256, summary.rows[actual.parent.ordinal - 1].fresh.artifact!.sha256);
  assert.equal(prior.parent.artifactSha256, summary.rows[prior.parent.ordinal - 1].saved.artifact.sha256);
  assert.equal(summary.rows[4].sameDecision, true);
});

test("different serialization cannot hide a fresh corpus byte-budget refusal", async context => {
  const directory = root(context), canonical = resolve(directory, "canonical"), input = resolve(directory, "minified"), output = resolve(directory, "replay");
  await source(canonical, config(8)); const saved = compactArchive(canonical, input, true);
  assert.equal(saved.outcome.status, "passed");
  let calls = 0;
  const summary = await replay(input, output, async sequence => { calls++; return checked(sequence); });
  assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false); assert.ok(calls < saved.files.length);
  const last = summary.schedule.rows.at(-1)!; assert.equal(last.diagnostic, "persistent-corpus-evidence-budget");
  assert.ok(summary.outcome.diagnostics.includes("persistent-corpus-evidence-budget"));
  assert.equal(summary.rows[calls - 1].comparison!.sameFullResult, true); assert.equal(summary.rows[calls - 1].comparison!.sameAdmission, false);
  assert.ok(summary.rows.slice(calls).every(row => row.disposition === "not-replayed"));
  assert.equal(validatePersistentArtifact(json(output, persistentGuidedNames(calls).artifact)).result.status, "passed", "Keep the actual passing case that exhausted corpus accounting");
});

test("full observation and compiled-code drift stop before later invocations despite equal status, signature or features", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input, config(2));
  for (const kind of ["observation", "compiled"] as const) {
    let calls = 0;
    const summary = await replay(input, resolve(directory, kind), async sequence => {
      calls++;
      const observed = wire(sequence, kind === "observation" ? "changed" : "synthetic"); if (kind === "compiled") observed.compiledJavaScriptSha256 = "0".repeat(64);
      const result = checked(sequence, observed); assert.equal(result.status, "passed");
      const before = extractPersistentFeedback(sequence, checked(sequence)), after = extractPersistentFeedback(sequence, result);
      assert.equal(before.status, "complete"); assert.equal(after.status, "complete");
      if (before.status === "complete" && after.status === "complete") assert.deepEqual(before.feedback.features, after.feedback.features, "Same feature descriptors do not authorize replay continuation");
      return result;
    });
    assert.equal(calls, 1); assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.outcome.status, "incomplete");
    const comparison = summary.rows[0].comparison!; assert.equal(comparison.sameStatus, true); assert.equal(comparison.sameSignature, true); assert.equal(comparison.sameFullResult, false);
    assert.equal(comparison.sameObservation, kind === "compiled"); assert.equal(comparison.sameCompiledJavaScript, kind === "observation");
    assert.ok(summary.outcome.diagnostics.includes("persistent-replay-result-drift"));
    assert.ok(summary.rows.slice(1).every(row => row.disposition === "not-replayed"));
  }
});

test("a qualified failure is reproduced separately from a passing campaign and signature equality is insufficient", async context => {
  const directory = root(context), input = resolve(directory, "input");
  const saved = await source(input, config(), async sequence => failure(sequence)); assert.equal(saved.outcome.status, "failed");
  const exact = await replay(input, resolve(directory, "exact"), async sequence => failure(sequence));
  assert.equal(exact.exactEvidenceMatched, true); assert.equal(exact.reproducedQualifiedFailure, true); assert.equal(exact.outcome.status, "failed"); assert.deepEqual(exact.saved.outcome, saved.outcome);
  for (const variant of ["failure", "passed"] as const) {
    const summary = await replay(input, resolve(directory, variant), async sequence => variant === "failure" ? failure(sequence, "100") : checked(sequence));
    assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.reproducedQualifiedFailure, false); assert.equal(summary.outcome.status, "incomplete");
    assert.equal(summary.rows[0].comparison!.sameSignature, variant === "failure"); assert.equal(summary.rows[0].comparison!.sameObservation, false);
  }
});

test("saved incomplete and uninvoked work stays incomplete without inventing fresh evaluator provenance", async context => {
  const directory = root(context);
  const prefix = resolve(directory, "prefix"), incomplete = resolve(directory, "incomplete"), uninvoked = resolve(directory, "uninvoked");
  await source(prefix, { ...config(), schedule: { seed: 7, mutations: 0, maxEvaluations: 2 } });
  const prefixReplay = await replay(prefix, resolve(directory, "prefix-replay"));
  assert.equal(prefixReplay.counts.evaluatorInvoked, 2); assert.equal(prefixReplay.counts.matched, 2); assert.equal(prefixReplay.exactEvidenceMatched, false); assert.equal(prefixReplay.outcome.status, "incomplete");
  assert.ok(prefixReplay.outcome.diagnostics.includes("persistent-replay-saved-incomplete"));
  const timedOut: PersistentGuidedEvaluator = async () => incompletePersistentResult("worker-timeout", "Synthetic evaluator timeout");
  await source(incomplete, config(), timedOut);
  for (const mode of ["same", "passing"] as const) {
    const replayed = await replay(incomplete, resolve(directory, `incomplete-${mode}`), mode === "same" ? timedOut : passing);
    assert.equal(replayed.exactEvidenceMatched, false); assert.equal(replayed.outcome.status, "incomplete");
    const invocation = json(resolve(directory, `incomplete-${mode}`), "0001-invocation.json") as PersistentGuidedReplayInvocation;
    assert.equal(invocation.resultOrigin, "evaluator"); assert.equal(invocation.result.diagnostic, mode === "same" ? "worker-timeout" : "persistent-model-checked");
    assert.equal(replayed.rows[0].comparison!.matched, false);
  }
  let ticks = 0;
  await writePersistentGuidedRun(uninvoked, { ...config(), maxElapsedMs: 20 }, async () => assert.fail("Saved proposal must not invoke"), () => identity, undefined, () => ++ticks >= 3 ? 20 : 0);
  const skipped = await replay(uninvoked, resolve(directory, "uninvoked-replay"), async () => assert.fail("Saved uninvoked marker must stay uninvoked"));
  assert.equal(skipped.counts.evaluatorInvoked, 0); assert.equal(skipped.rows[0].disposition, "saved-uninvoked"); assert.equal(skipped.rows[0].fresh.artifact, null); assert.equal(skipped.exactEvidenceMatched, false);
  assert.deepEqual(readdirSync(resolve(directory, "uninvoked-replay")), ["summary.json"]);
  const supervisor = resolve(directory, "supervisor");
  await source(supervisor, config(), async () => { throw new Error("Synthetic saved protocol exception"); });
  const supervisorReplay = await replay(supervisor, resolve(directory, "supervisor-replay"));
  assert.equal(supervisorReplay.counts.evaluatorInvoked, 1); assert.equal(supervisorReplay.rows[0].saved.resultOrigin, "supervisor");
  assert.equal(supervisorReplay.rows[0].comparison!.matched, false); assert.equal(supervisorReplay.exactEvidenceMatched, false); assert.equal(supervisorReplay.outcome.status, "incomplete");
});

test("decision drift is caught before the next evaluation with its pending proposal preserved", async context => {
  const directory = root(context), input = resolve(directory, "input"), output = resolve(directory, "replay"); await source(input, config(2));
  const originalNext = PersistentSchedule.prototype.next; let calls = 0;
  try {
    const summary = await replay(input, output, async sequence => {
      if (++calls === 4) {
        // Trusted test instrumentation, installed only after the one source audit.
        PersistentSchedule.prototype.next = function () { const next = originalNext.call(this); if (next) next.random.words[0] ^= 1; return next; };
      }
      return checked(sequence);
    });
    assert.equal(calls, 4); assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.rows[4].disposition, "decision-drift");
    assert.equal(summary.rows[4].sameDecision, false); assert.equal(summary.rows[4].fresh.artifact, null); assert.ok(summary.rows[4].fresh.decision);
    assert.equal(summary.schedule.snapshot.pending?.ordinal, 5); assert.equal(summary.counts.recorded, 4); assert.equal(summary.counts.proposed, 5);
    assert.ok(summary.outcome.diagnostics.includes("persistent-replay-decision-drift")); assert.equal(existsSync(resolve(output, "0005.json")), false);
  } finally { PersistentSchedule.prototype.next = originalNext; }
});

test("saved zero-row interruption and saved final-envelope gaps never become complete campaigns", async context => {
  const directory = root(context), empty = resolve(directory, "empty"), controller = new AbortController(); controller.abort();
  const savedEmpty = await writePersistentGuidedRun(empty, config(), async () => assert.fail("Pre-interrupted source cannot invoke"), () => identity, controller.signal, () => 0);
  assert.equal(savedEmpty.counts.recorded, 0); assert.equal(savedEmpty.outcome.status, "incomplete");
  const replayedEmpty = await replay(empty, resolve(directory, "empty-replay"), async () => assert.fail("Zero-row source cannot invoke"));
  assert.equal(replayedEmpty.counts.evaluatorInvoked, 0); assert.equal(replayedEmpty.rows.length, 0); assert.equal(replayedEmpty.exactEvidenceMatched, false); assert.equal(replayedEmpty.outcome.status, "incomplete");
  assert.deepEqual(replayedEmpty.saved.outcome, savedEmpty.outcome); assert.ok(replayedEmpty.outcome.diagnostics.includes("persistent-replay-saved-incomplete"));
  for (const mode of ["signal", "unavailable"] as const) {
    const input = resolve(directory, mode), finalController = new AbortController(); let providers = 0;
    const saved = await writePersistentGuidedRun(input, config(), passing, () => {
      if (++providers === 2) { if (mode === "unavailable") throw new Error("Synthetic saved post-identity gap"); finalController.abort(); }
      return identity;
    }, finalController.signal, () => 0);
    assert.equal(saved.transcript.snapshot.outcome.status, "passed"); assert.equal(saved.outcome.status, "incomplete");
    const replayed = await replay(input, resolve(directory, `${mode}-replay`));
    assert.equal(replayed.counts.evaluatorInvoked, 4); assert.equal(replayed.counts.matched, 4); assert.equal(replayed.scheduleComparison.sameRawSnapshot, true);
    assert.equal(replayed.postIdentity.status, "matched"); assert.equal(replayed.finalAbortCause, null);
    assert.equal(replayed.exactEvidenceMatched, false); assert.equal(replayed.outcome.status, "incomplete"); assert.deepEqual(replayed.saved.outcome, saved.outcome);
    assert.deepEqual(replayed.outcome.diagnostics, ["persistent-replay-saved-incomplete"]);
  }
});

test("one detached audit precedes identity checks and no saved input is re-opened after it", async context => {
  const directory = root(context), input = resolve(directory, "input"), output = resolve(directory, "replay"); await source(input, config(2));
  let providers = 0;
  const summary = await replayPersistentGuided(input, output, passing, () => { if (++providers === 1) rmSync(input, { recursive: true }); return identity; }, {}, undefined, () => 0);
  assert.equal(providers, 2); assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.outcome.status, "passed");
  const invalid = resolve(directory, "invalid"); await source(invalid); writeFileSync(resolve(invalid, "0001.json"), "{}");
  let invalidProviders = 0, invalidCalls = 0;
  await assert.rejects(() => replayPersistentGuided(invalid, resolve(directory, "refused"), async () => { invalidCalls++; return {}; }, () => { invalidProviders++; return identity; }));
  assert.equal(invalidProviders, 0); assert.equal(invalidCalls, 0); assert.equal(existsSync(resolve(directory, "refused")), false);
});

test("every initial identity component is exact and malformed options refuse without reading accessors", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input);
  const identities: PersistentGuidedIdentity[] = [];
  for (const key of Object.keys(identity.persistent) as (keyof typeof identity.persistent)[]) {
    const changed = structuredClone(identity);
    changed.persistent[key] = key.endsWith("Sha256") ? "0".repeat(64) : key === "node" ? "v22.23.3" : `${identity.persistent[key]}-changed`;
    identities.push(changed);
  }
  for (const module of ["feedback", "corpus", "schedule"] as const) for (const key of ["sourceSha256", "builtSha256"] as const) { const changed = structuredClone(identity); changed.modules[module][key] = "0".repeat(64); identities.push(changed); }
  for (const [index, changed] of identities.entries()) {
    const output = resolve(directory, `identity-${index}`);
    await assert.rejects(() => replayPersistentGuided(input, output, async () => assert.fail("No mismatched-identity invocation"), () => changed));
    assert.equal(existsSync(output), false);
  }
  let getterCalls = 0;
  const badConfig = Object.defineProperty({}, "maxElapsedMs", { enumerable: true, get() { getterCalls++; return 1; } });
  assert.throws(() => validatePersistentGuidedReplayConfiguration(badConfig)); assert.equal(getterCalls, 0);
  for (const value of [{ arbitraryAdapter: "x" }, { maxElapsedMs: undefined }, { maxElapsedMs: 0 }, { maxElapsedMs: 60001 }, { maxElapsedMs: 1.5 }, { maxElapsedMs: -0 }]) assert.throws(() => validatePersistentGuidedReplayConfiguration(value));
  await assert.rejects(() => replayPersistentGuided(input, resolve(directory, "clock"), passing, () => identity, {}, undefined, () => -1)); assert.equal(existsSync(resolve(directory, "clock")), false);
});

test("[timing] real cancellation races bound ignored callbacks using the narrower saved allowance or overall deadline", async context => {
  const directory = root(context);
  for (const mode of ["saved", "overall"] as const) {
    const input = resolve(directory, mode), output = resolve(directory, `${mode}-replay`);
    await source(input, { ...config(), maxElapsedMs: mode === "saved" ? 100 : 60000 });
    let signalSeen: AbortSignal | undefined, calls = 0;
    const summary = await replayPersistentGuided(input, output, async (_sequence, workerLimits, signal) => {
      signalSeen = signal; calls++; assert.deepEqual(workerLimits, limits); return new Promise(() => {});
    }, () => identity, { maxElapsedMs: mode === "saved" ? 2000 : 100 });
    assert.equal(calls, 1); assert.equal(signalSeen?.aborted, true); assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.finalAbortCause, "deadline");
    assert.equal(summary.finalAbortSource, mode === "saved" ? "saved-launch-allowance" : "replay-deadline"); assert.equal(summary.exactEvidenceMatched, false);
    const invocation = json(output, "0001-invocation.json") as PersistentGuidedReplayInvocation;
    assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.result.diagnostic, "worker-interrupted"); assert.equal(invocation.returnedArtifact, null);
    assert.deepEqual(invocation.workerLimits, limits); assert.ok(invocation.timing.remainingMsAtLaunch! <= 100);
    assert.equal(invocation.timing.remainingMsAtLaunch, Math.min(invocation.timing.savedRemainingMsAtLaunch, invocation.timing.replayRemainingMsAtLaunch!));
    const artifact = validatePersistentArtifact(json(output, "0001.json")); assert.deepEqual(artifact.limits, limits); assert.equal(Object.hasOwn(artifact.result, "diagnosticResponse"), false);
  }
});

test("external cancellation returns promptly and late resolve or reject cannot mutate evidence", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input);
  for (const mode of ["resolve", "reject"] as const) {
    const output = resolve(directory, mode), controller = new AbortController();
    let signalSeen: AbortSignal | undefined, deferredResolve!: (value: unknown) => void, deferredReject!: (reason: unknown) => void, launch!: () => void, sequenceSeen: PersistentSequence | undefined;
    const launched = new Promise<void>(resolve => { launch = resolve; });
    const running = replayPersistentGuided(input, output, async (sequence, _limits, signal) => {
      sequenceSeen = sequence; signalSeen = signal; launch(); return new Promise((resolve, reject) => { deferredResolve = resolve; deferredReject = reject; });
    }, () => identity, {}, controller.signal);
    await launched; controller.abort(); const summary = await running;
    assert.equal(summary.finalAbortCause, "external-signal"); assert.equal(summary.counts.evaluatorInvoked, 1); assert.equal(summary.counts.retained, 0); assert.equal(summary.exactEvidenceMatched, false);
    assert.equal(summary.rows[0].fresh.returnedArtifact, null); assert.equal(getEventListeners(controller.signal, "abort").length, 0); assert.equal(getEventListeners(signalSeen!, "abort").length, 0);
    const before = readdirSync(output).sort().map(name => [name, readFileSync(resolve(output, name)).toString("hex")]);
    if (mode === "resolve") deferredResolve(checked(sequenceSeen!)); else deferredReject(new Error("Synthetic late rejection"));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(readdirSync(output).sort().map(name => [name, readFileSync(resolve(output, name)).toString("hex")]), before);
  }
});

test("settled passed and failed results survive post-await cancellation only as terminal returned evidence", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input, { ...config(), maxElapsedMs: 20 });
  for (const mode of ["passed", "failed"] as const) {
    let ticks = 0; const output = resolve(directory, mode);
    const summary = await replayPersistentGuided(input, output, async sequence => mode === "passed" ? checked(sequence) : failure(sequence), () => identity, { maxElapsedMs: 1000 }, undefined, () => ++ticks >= 5 ? 20 : 0);
    assert.equal(summary.finalAbortSource, "saved-launch-allowance"); assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.counts.retained, 0);
    const invocation = json(output, "0001-invocation.json") as PersistentGuidedReplayInvocation;
    assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.result.status, "incomplete"); assert.equal(invocation.result.diagnostic, "worker-interrupted");
    assert.equal(invocation.returnedArtifact!.name, "0001-returned.json");
    const returned = validatePersistentArtifact(json(output, "0001-returned.json")); assert.equal(returned.result.status, mode); assert.deepEqual(returned.limits, limits);
    assert.equal(summary.schedule.rows[0].admission?.admittedFeatureIds.length, 0);
  }
});

test("cancellation after proposal but before callback records an uninvoked supervisor case", async context => {
  const directory = root(context), input = resolve(directory, "input"), output = resolve(directory, "replay"); await source(input);
  let ticks = 0;
  const summary = await replayPersistentGuided(input, output, async () => assert.fail("No launch after cancellation"), () => identity, { maxElapsedMs: 20 }, undefined, () => ++ticks >= 3 ? 20 : 0);
  assert.equal(summary.rows[0].disposition, "not-invoked"); assert.equal(summary.counts.evaluatorInvoked, 0); assert.equal(summary.counts.recorded, 1);
  const invocation = json(output, "0001-invocation.json") as PersistentGuidedReplayInvocation;
  assert.equal(invocation.evaluatorInvoked, false); assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.timing.startedAtMs, null); assert.equal(invocation.timing.remainingMsAtLaunch, null);
  assert.equal(invocation.result.diagnostic, "worker-interrupted"); assert.equal(summary.exactEvidenceMatched, false);
});

test("on-time evaluator incompletes retain diagnostics and malformed or thrown results stay supervisor-origin", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input);
  let getters = 0;
  const malformed = Object.defineProperty({}, "status", { enumerable: true, get() { getters++; return "passed"; } });
  for (const mode of ["incomplete", "throw", "malformed"] as const) {
    const output = resolve(directory, mode);
    const summary = await replay(input, output, async () => { if (mode === "throw") throw new Error("Synthetic throw"); return mode === "malformed" ? malformed : incompletePersistentResult("worker-output-budget", "Synthetic measured output limit"); });
    const invocation = json(output, "0001-invocation.json") as PersistentGuidedReplayInvocation;
    assert.equal(invocation.evaluatorInvoked, true); assert.equal(invocation.resultOrigin, mode === "incomplete" ? "evaluator" : "supervisor"); assert.equal(invocation.abortCause, null);
    assert.equal(invocation.result.diagnostic, mode === "incomplete" ? "worker-output-budget" : "persistent-protocol"); assert.equal(summary.exactEvidenceMatched, false);
    assert.equal(summary.rows[0].disposition, "incomplete");
  }
  assert.equal(getters, 0);
});

test("post-final identity, signal and deadline disqualify the envelope without rewriting recorded evidence", async context => {
  const directory = root(context), input = resolve(directory, "input"); await source(input);
  for (const mode of ["drift", "unavailable", "invalid", "signal", "deadline"] as const) {
    const output = resolve(directory, mode), controller = new AbortController(); let providers = 0, finished = false;
    const summary = await replayPersistentGuided(input, output, passing, () => {
      if (++providers === 1) return identity;
      finished = true;
      if (mode === "unavailable") throw new Error("Synthetic identity unavailable");
      if (mode === "invalid") return { ...identity, approved: true };
      if (mode === "signal") controller.abort();
      if (mode === "drift") { const changed = structuredClone(identity); changed.modules.schedule.builtSha256 = "0".repeat(64); return changed; }
      return identity;
    }, { maxElapsedMs: 20 }, controller.signal, () => finished && mode === "deadline" ? 20 : 0);
    assert.equal(summary.counts.evaluatorInvoked, 4); assert.equal(summary.counts.matched, 4); assert.equal(summary.schedule.snapshot.outcome.status, "passed");
    assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.rows.every(row => row.comparison!.matched), true);
    assert.equal(summary.postIdentity.status, mode === "drift" ? "drift" : mode === "invalid" || mode === "unavailable" ? "unavailable" : "matched");
    assert.equal(summary.finalAbortCause, mode === "signal" ? "external-signal" : mode === "deadline" ? "deadline" : null);
    for (const row of summary.rows) { const invocation = json(output, row.fresh.invocation!.name) as PersistentGuidedReplayInvocation; assert.equal(invocation.resultOrigin, "evaluator"); assert.equal(invocation.abortCause, null); }
  }
});

test("CLI accepts only exact owned replay controls", async () => {
  for (const args of [[], ["--output", "x"], ["--replay", "x"], ["--replay", "x", "--output", "y", "--output", "z"], ["--replay", "x", "--output", "y", "--compare-build"], ["--source", "x"], ["--replay", "x", "--output", "y", "--max-elapsed-ms", "01"], ["--replay", "x", "--output", "y", "--max-elapsed-ms", "60001"]]) await assert.rejects(() => persistentGuidedReplayMain(args));
});

test("[timing] pinned compiled owned campaign audits and replays exact measured evidence", { skip: !process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST, timeout: 180000 }, async context => {
  const directory = root(context), input = resolve(directory, "input"), output = resolve(directory, "replay"), compiler = resolve(process.env.COMPACTC_TEST!), runtime = resolve(process.env.COMPACT_RUNTIME_TEST!);
  const provider = () => persistentGuidedBuildIdentity(compiler, runtime);
  const evaluate: PersistentGuidedEvaluator = (sequence, workerLimits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, workerLimits, signal);
  const saved = await writePersistentGuidedRun(input, { schedule: { seed: 7, mutations: 1, maxEvaluations: 5 } }, evaluate, provider);
  assert.equal(saved.outcome.status, "passed"); assert.equal(readAuditedPersistentGuided(input).summary.outcome.status, "passed");
  const summary = await replayPersistentGuided(input, output, evaluate, provider);
  assert.equal(summary.outcome.status, "passed"); assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.allArtifactBytesMatched, true); assert.equal(summary.counts.evaluatorInvoked, 5);
});
