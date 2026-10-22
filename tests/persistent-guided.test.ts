import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { incompletePersistentResult, runPersistentSequenceIsolated, validatePersistentArtifact, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";
import { persistentGuidedMain, writePersistentGuidedRun, type PersistentGuidedEvaluator } from "./generative/persistent-guided.js";
import { guidedJsonBytes, persistentGuidedBuildIdentity, persistentGuidedNames, persistentGuidedOutcome, PERSISTENT_GUIDED_LIMITS, validatePersistentGuidedConfiguration, validatePersistentGuidedIdentity, validatePersistentGuidedInvocation, validatePersistentGuidedSummary, type PersistentGuidedIdentity, type PersistentGuidedInvocation, type PersistentGuidedSummary } from "./generative/persistent-guided-format.js";
import { auditPersistentSchedule } from "./generative/persistent-schedule-audit.js";

const identity: PersistentGuidedIdentity = {
  persistent: { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 },
  modules: { feedback: { sourceSha256: "4".repeat(64), builtSha256: "5".repeat(64) }, corpus: { sourceSha256: "6".repeat(64), builtSha256: "7".repeat(64) }, schedule: { sourceSha256: "8".repeat(64), builtSha256: "9".repeat(64) } },
};
const savedLimits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const configuration = () => validatePersistentGuidedConfiguration({ schedule: { seed: 1, mutations: 0, maxEvaluations: 4 }, workerLimits: savedLimits });
const json = (path: string) => JSON.parse(readFileSync(path, "utf8"));
function directory(context: TestContext): string { const root = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-guided-")); context.after(() => rmSync(root, { recursive: true, force: true })); return root; }

/** Explicit schema-only evidence. No compiled runtime generated these observations. */
function wire(sequence: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(sequence), view = (state: { count: string; next: string }) => ({ ...state, publicSha256: persistentDigest(`synthetic:${state.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)), initial: view(expected.initial), rows: expected.rows.map(row => ({ ...row, before: view(row.before), after: view(row.after), slots: row.slots.map(view) })), final: view(expected.final) };
}
const checked = (sequence: PersistentSequence, observation = wire(sequence)) => checkPersistentObservation(sequence, observation, PERSISTENT_SOURCE_SHA256);
const passing: PersistentGuidedEvaluator = async sequence => checked(sequence);
const invoke = (root: string, name: string, evaluate = passing, config: unknown = configuration()) => writePersistentGuidedRun(resolve(root, name), config, evaluate, () => identity, undefined, () => 0);
function invocationData(output: string, summary: PersistentGuidedSummary): PersistentGuidedInvocation[] { return summary.files.map(files => json(resolve(output, files.invocation.name))); }
function originalData(output: string, summary: PersistentGuidedSummary): Buffer[] { return summary.files.map(files => readFileSync(resolve(output, files.artifact.name))); }

test("owned writer saves exact bounded references and reconstructable original cases before returning detached data", async context => {
  const root = directory(context), output = resolve(root, "run");
  let calls = 0, providerCalls = 0;
  const summary = await writePersistentGuidedRun(output, configuration(), async (sequence, limits, signal) => {
    calls++; assert.equal(existsSync(resolve(output, persistentGuidedNames(calls).decision)), true, "Decision must be saved before invocation");
    assert.deepEqual(limits, savedLimits); assert.equal(signal.aborted, false); return checked(sequence);
  }, () => { providerCalls++; return identity; }, undefined, () => 0);
  assert.equal(calls, 4); assert.equal(providerCalls, 2); assert.deepEqual(summary.outcome, { status: "passed", diagnostics: [] });
  assert.deepEqual(summary.counts, { proposed: 4, recorded: 4, evaluatorInvoked: 4, corpusConsidered: 4, retained: 4 });
  const invocations = invocationData(output, summary), originals = originalData(output, summary);
  assert.deepEqual(auditPersistentSchedule(summary.transcript, originals).transcript, summary.transcript);
  assert.deepEqual(validatePersistentGuidedSummary(summary, summary.transcript, invocations), summary);
  let bytes = 0;
  for (const [index, files] of summary.files.entries()) {
    assert.equal(files.returnedArtifact, null);
    for (const file of [files.decision, files.artifact, files.invocation]) {
      const contents = readFileSync(resolve(output, file.name)); bytes += contents.length;
      assert.equal(file.sha256, persistentDigest(contents)); assert.equal(file.bytes, contents.length);
      assert.equal(contents.toString().endsWith("\n"), true);
    }
    const artifact = validatePersistentArtifact(JSON.parse(originals[index].toString()));
    assert.deepEqual(artifact.sequence, summary.transcript.decisions[index].sequence);
    assert.deepEqual(artifact.limits, savedLimits); assert.equal(artifact.result.status, "passed");
    assert.deepEqual(invocations[index].result, { status: "passed", diagnostic: "persistent-model-checked", signature: "persistent-model-checked" });
    assert.equal(invocations[index].resultOrigin, "evaluator"); assert.equal(invocations[index].timing.remainingMsAtLaunch, 60000);
  }
  assert.equal(summary.evidenceBytesBeforeSummary, bytes); assert.equal(readdirSync(output).length, 13);
  const persisted = json(resolve(output, "summary.json")); summary.files.length = 0; summary.identity.modules.feedback.sourceSha256 = "0".repeat(64);
  assert.deepEqual(json(resolve(output, "summary.json")), persisted);
  await assert.rejects(() => invoke(root, "run", async () => assert.fail("Must not overwrite")), /EEXIST/);
});

test("final corpus refusal retains original evidence without inventing a consideration or parent", async context => {
  const root = directory(context), config = { ...configuration(), corpusBudgets: { maxConsiderations: 1 } };
  const summary = await invoke(root, "considerations", passing, config), output = resolve(root, "considerations");
  assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.files.length, 2);
  assert.deepEqual(summary.counts, { proposed: 2, recorded: 2, evaluatorInvoked: 2, corpusConsidered: 1, retained: 1 });
  const last = summary.transcript.rows[1]; assert.equal(last.admission!.artifact, null); assert.equal(last.admission!.ordinal, null);
  assert.equal(last.artifact!.sha256, summary.files[1].artifact.sha256);
  const originals = originalData(output, summary); assert.deepEqual(auditPersistentSchedule(summary.transcript, originals).transcript, summary.transcript);
  assert.ok(summary.evidenceBytesBeforeSummary > summary.transcript.snapshot.corpus.evidenceBytes);
  const byteBound = await invoke(root, "bytes", passing, { ...configuration(), corpusBudgets: { maxEvidenceBytes: 1 } });
  assert.equal(byteBound.counts.evaluatorInvoked, 1); assert.equal(byteBound.counts.corpusConsidered, 0); assert.equal(byteBound.counts.retained, 0);
  assert.ok(byteBound.outcome.diagnostics.includes("persistent-corpus-evidence-budget"));
  assert.equal(existsSync(resolve(root, "bytes", "0001.json")), true);
});

test("qualified terminal failure stays separate from corpus novelty and can use existing case replay", async context => {
  const root = directory(context); let calls = 0;
  const summary = await invoke(root, "failed", async sequence => {
    const observed = wire(sequence); if (++calls === 4) observed.initial.next = "99";
    return checked(sequence, observed);
  });
  assert.equal(calls, 4); assert.deepEqual(summary.outcome, { status: "failed", diagnostics: ["persistent-model-disagreement"] });
  assert.equal(summary.transcript.snapshot.outcome.status, "failed"); assert.equal(summary.counts.retained, 3);
  const artifact = validatePersistentArtifact(json(resolve(root, "failed", "0004.json")));
  assert.equal(artifact.result.status, "failed"); assert.equal(artifact.result.signature, "persistent-model|field:initial.next");
  assert.equal(summary.files[3].returnedArtifact, null); assert.equal(readdirSync(resolve(root, "failed")).some(file => file.includes("reduction")), false);
});

test("ordinary evaluator incomplete diagnostics are preserved; unqualified and thrown responses are supervisor protocol", async context => {
  const root = directory(context); let getterCalls = 0;
  for (const diagnostic of ["worker-timeout", "worker-output-budget", "worker-failed"]) {
    const summary = await invoke(root, diagnostic, async () => incompletePersistentResult(diagnostic, "Synthetic worker-classification test"));
    const invocation = invocationData(resolve(root, diagnostic), summary)[0];
    assert.equal(invocation.resultOrigin, "evaluator"); assert.equal(invocation.result.diagnostic, diagnostic); assert.equal(invocation.abortCause, null);
    assert.deepEqual(summary.outcome, { status: "incomplete", diagnostics: [diagnostic] });
  }
  for (const [name, evaluate] of [
    ["throws", async () => { throw new Error("Synthetic failure"); }],
    ["forged", async (sequence: PersistentSequence) => ({ ...checked(sequence), signature: "invented" })],
    ["accessor", async (sequence: PersistentSequence) => { const result = checked(sequence); Object.defineProperty(result, "observation", { enumerable: true, get() { getterCalls++; return {}; } }); return result; }],
    ["error-accessor", async () => { throw Object.defineProperty({}, "message", { get() { getterCalls++; return "forged"; } }); }],
  ] as [string, PersistentGuidedEvaluator][]) {
    const summary = await invoke(root, name, evaluate), invocation = invocationData(resolve(root, name), summary)[0];
    assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.evaluatorInvoked, true); assert.equal(invocation.result.diagnostic, "persistent-protocol");
    assert.equal(invocation.abortCause, null); assert.equal(invocation.returnedArtifact, null);
    assert.deepEqual(summary.outcome.diagnostics, ["persistent-campaign-protocol", "persistent-protocol"]);
  }
  assert.equal(getterCalls, 0);
});

test("before-proposal cancellation has no invented invocation and post-decision cancellation is explicitly uninvoked", async context => {
  const root = directory(context), before = new AbortController(); before.abort();
  const none = await writePersistentGuidedRun(resolve(root, "before"), configuration(), async () => assert.fail("Must not execute"), () => identity, before.signal, () => 0);
  assert.deepEqual(none.counts, { proposed: 0, recorded: 0, evaluatorInvoked: 0, corpusConsidered: 0, retained: 0 });
  assert.equal(none.transcript.stopReason, "persistent-campaign-interrupted"); assert.deepEqual(readdirSync(resolve(root, "before")), ["summary.json"]);
  const deadline = await writePersistentGuidedRun(resolve(root, "before-deadline"), { ...configuration(), maxElapsedMs: 20 }, async () => assert.fail("Must not execute"), () => identity, undefined, () => 20);
  assert.equal(deadline.transcript.stopReason, "persistent-campaign-time-budget"); assert.equal(deadline.counts.proposed, 0);
  for (const original of [none, deadline]) {
    const forged = { ...structuredClone(original), elapsedMs: original.configuration.maxElapsedMs, finalAbortCause: original.finalAbortCause === "deadline" ? "external-signal" as const : "deadline" as const };
    forged.outcome = persistentGuidedOutcome(forged.transcript, [], forged.elapsedMs, forged.configuration, forged.postIdentity, forged.finalAbortCause);
    assert.throws(() => validatePersistentGuidedSummary(forged, original.transcript, []), /between-proposal stop cause/, "Recomputed diagnostics cannot replace a between-proposal cancellation cause");
  }
  const pending = new AbortController(); let ticks = 0;
  const uninvoked = await writePersistentGuidedRun(resolve(root, "pending"), configuration(), async () => assert.fail("Must not execute"), () => identity, pending.signal, () => { if (++ticks === 3) pending.abort(); return 0; });
  const invocation = invocationData(resolve(root, "pending"), uninvoked)[0];
  assert.equal(uninvoked.counts.proposed, 1); assert.equal(uninvoked.counts.evaluatorInvoked, 0); assert.equal(uninvoked.counts.retained, 0);
  assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.evaluatorInvoked, false);
  assert.equal(invocation.timing.startedAtMs, null); assert.equal(invocation.timing.remainingMsAtLaunch, null);
  assert.equal(invocation.abortCause, "external-signal"); assert.equal(invocation.result.diagnostic, "worker-interrupted");
  assert.equal(validatePersistentArtifact(json(resolve(root, "pending", "0001.json"))).result.status, "incomplete");
  assert.equal(getEventListeners(pending.signal, "abort").length, 0);
});

test("in-flight cancellation returns promptly and a later evaluator result cannot write or change evidence", async context => {
  const root = directory(context), controller = new AbortController(), output = resolve(root, "cancelled");
  let launch!: () => void, settle!: (value: unknown) => void, model: PersistentSequence | undefined;
  const launched = new Promise<void>(resolve => { launch = resolve; });
  const work = writePersistentGuidedRun(output, configuration(), async (sequence, limits, signal) => {
    model = sequence; assert.deepEqual(limits, savedLimits); assert.equal(signal.aborted, false); launch();
    return new Promise(resolve => { settle = resolve; });
  }, () => identity, controller.signal, () => 0);
  await launched; controller.abort(); const summary = await work;
  const invocation = invocationData(output, summary)[0];
  assert.equal(invocation.evaluatorInvoked, true); assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.returnedArtifact, null);
  assert.equal(summary.counts.retained, 0); assert.equal(summary.outcome.status, "incomplete");
  const forged = { ...structuredClone(summary), elapsedMs: summary.configuration.maxElapsedMs, finalAbortCause: "deadline" as const };
  forged.outcome = persistentGuidedOutcome(forged.transcript, [invocation], forged.elapsedMs, forged.configuration, forged.postIdentity, forged.finalAbortCause);
  assert.throws(() => validatePersistentGuidedSummary(forged, summary.transcript, [invocation]), /first invocation cause/, "A later deadline cannot replace the original external cancellation, even with consistent derived diagnostics");
  const files = readdirSync(output).sort().map(name => [name, readFileSync(resolve(output, name)).toString("hex")]);
  settle(checked(model!)); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(readdirSync(output).sort().map(name => [name, readFileSync(resolve(output, name)).toString("hex")]), files);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("settled late responses are preserved once but supervisor selection earns no novelty", async context => {
  const root = directory(context);
  for (const late of ["passed", "failed"] as const) {
    let ticks = 0;
    const config = { ...configuration(), maxElapsedMs: 20 };
    const output = resolve(root, late);
    const summary = await writePersistentGuidedRun(output, config, async (sequence, limits) => {
      assert.deepEqual(limits, savedLimits, "Saved timeout remains fixed despite the narrower overall deadline");
      const observation = wire(sequence); if (late === "failed") observation.initial.next = "99";
      return checked(sequence, observation);
    }, () => identity, undefined, () => ++ticks >= 5 ? 25 : 0);
    const invocation = invocationData(output, summary)[0];
    assert.equal(invocation.resultOrigin, "supervisor"); assert.equal(invocation.abortCause, "deadline"); assert.equal(invocation.timing.remainingMsAtLaunch, 20);
    assert.equal(invocation.result.status, "incomplete"); assert.equal(invocation.result.diagnostic, "worker-interrupted");
    assert.equal(invocation.returnedArtifact!.name, "0001-returned.json");
    const returned = validatePersistentArtifact(json(resolve(output, "0001-returned.json")));
    assert.equal(returned.result.status, late); assert.deepEqual(returned.limits, savedLimits);
    assert.equal(summary.counts.retained, 0); assert.equal(summary.outcome.status, "incomplete"); assert.equal(readdirSync(output).length, 5);
    assert.ok(summary.outcome.diagnostics.includes("persistent-campaign-time-budget"));
    const forged = { ...structuredClone(summary), finalAbortCause: "external-signal" as const };
    forged.outcome = persistentGuidedOutcome(forged.transcript, [invocation], forged.elapsedMs, forged.configuration, forged.postIdentity, forged.finalAbortCause);
    assert.throws(() => validatePersistentGuidedSummary(forged, summary.transcript, [invocation]), /first invocation cause/, "A later signal cannot replace the original deadline, even with consistent derived diagnostics");
  }
});

test("[timing] real overall timer bounds an evaluator that never settles without clipping saved worker limits", async context => {
  const root = directory(context); let signalSeen: AbortSignal | undefined;
  const summary = await writePersistentGuidedRun(resolve(root, "deadline"), { ...configuration(), maxElapsedMs: 1000 }, async (_sequence, limits, signal) => {
    signalSeen = signal; assert.deepEqual(limits, savedLimits); return new Promise(() => {});
  }, () => identity);
  assert.equal(summary.outcome.status, "incomplete"); assert.ok(summary.outcome.diagnostics.includes("persistent-campaign-time-budget"));
  assert.equal(signalSeen?.aborted, true); assert.equal(summary.counts.evaluatorInvoked, 1); assert.equal(summary.counts.retained, 0);
  const invocation = invocationData(resolve(root, "deadline"), summary)[0]; assert.equal(invocation.returnedArtifact, null);
});

test("post-final deadline and post-identity drift preserve passing cases while disqualifying the campaign", async context => {
  const root = directory(context);
  for (const mode of ["time", "drift", "unavailable", "invalid"] as const) {
    let providers = 0, expired = false;
    const summary = await writePersistentGuidedRun(resolve(root, mode), { ...configuration(), maxElapsedMs: 20 }, passing, () => {
      if (++providers === 1) return identity;
      if (mode === "time") expired = true;
      if (mode === "unavailable") throw new Error("Synthetic provider failure");
      if (mode === "invalid") return { ...identity, missing: true };
      if (mode === "drift") return { ...identity, modules: { ...identity.modules, schedule: { ...identity.modules.schedule, builtSha256: "0".repeat(64) } } };
      return identity;
    }, undefined, () => expired ? 20 : 0);
    assert.equal(summary.transcript.snapshot.outcome.status, "passed"); assert.equal(summary.outcome.status, "incomplete");
    assert.equal(summary.counts.evaluatorInvoked, 4); assert.equal(summary.counts.retained, 4);
    assert.deepEqual(summary.outcome.diagnostics, [mode === "time" ? "persistent-campaign-time-budget" : mode === "drift" ? "persistent-campaign-build-drift" : "persistent-campaign-identity-unavailable"]);
    assert.equal(summary.postIdentity.status, mode === "time" ? "matched" : mode === "drift" ? "drift" : "unavailable");
    assert.ok(invocationData(resolve(root, mode), summary).every(value => value.resultOrigin === "evaluator" && value.abortCause === null));
  }
});

test("invalid metadata/options and CLI controls refuse before directory creation without accessor execution", async context => {
  const root = directory(context); let calls = 0;
  const badConfig = { ...configuration() }; Object.defineProperty(badConfig, "maxElapsedMs", { enumerable: true, get() { calls++; return 1; } });
  const badIdentity = structuredClone(identity); Object.defineProperty(badIdentity.modules.feedback, "sourceSha256", { enumerable: true, get() { calls++; return "a".repeat(64); } });
  for (const [name, config, provider, clock] of [
    ["getter", badConfig, () => identity, () => 0], ["identity", configuration(), () => badIdentity, () => 0],
    ["maximum", { ...configuration(), maxElapsedMs: 60001 }, () => identity, () => 0],
    ["clock", configuration(), () => identity, () => -0], ["extra", { ...configuration(), adapter: "saved" }, () => identity, () => 0],
  ] as const) {
    const output = resolve(root, name); await assert.rejects(() => writePersistentGuidedRun(output, config, async () => { calls++; return {}; }, provider, undefined, clock)); assert.equal(existsSync(output), false);
  }
  assert.equal(calls, 0);
  for (const args of [
    ["--output", "new", "--adapter", "saved"], ["--output", "new", "--output", "again"], ["--output", "new", "--seed", "-1"],
    ["--output", "new", "--max-elapsed-ms", "60001"], ["--source", "owned", "--output", "new"], ["--output", "new", "--compare-build"],
  ]) await assert.rejects(() => persistentGuidedMain(args));
  assert.deepEqual(validatePersistentGuidedIdentity(Object.assign(Object.create(null), identity)), identity);
  assert.deepEqual(validatePersistentGuidedConfiguration(Object.assign(Object.create(null), configuration())), configuration());
});

test("shared envelope validators enforce exact timing, data fields and derived counts", async context => {
  const root = directory(context), summary = await invoke(root, "format"), invocations = invocationData(resolve(root, "format"), summary);
  let calls = 0;
  for (const mutate of [
    (value: any) => { value.timing.remainingMsAtLaunch--; }, (value: any) => { value.timing.startedAtMs = null; },
    (value: any) => { value.timing.proposedAtMs = 1; }, (value: any) => { value.resultOrigin = "predicted"; },
    (value: any) => { value.extra = 1; }, (value: any) => { value.decision.name = "../other.json"; },
    (value: any) => { value.evaluatorInvoked = false; }, (value: any) => { value.abortCause = "deadline"; },
    (value: any) => { Object.defineProperty(value.timing, "finishedAtMs", { enumerable: true, get() { calls++; return 0; } }); },
  ]) { const value = structuredClone(invocations[0]); mutate(value); assert.throws(() => validatePersistentGuidedInvocation(value, 60000)); }
  for (const mutate of [
    (value: any) => { value.counts.evaluatorInvoked++; }, (value: any) => { value.evidenceBytesBeforeSummary++; },
    (value: any) => { value.configuration.maxElapsedMs = 1; }, (value: any) => { value.files[0].ordinal = 2; },
    (value: any) => { value.postIdentity.status = "drift"; }, (value: any) => { value.outcome.diagnostics = ["invented"]; },
    (value: any) => { Object.defineProperty(value.files[0], "artifact", { enumerable: true, get() { calls++; return {}; } }); },
  ]) { const value = structuredClone(summary); mutate(value); assert.throws(() => validatePersistentGuidedSummary(value, summary.transcript, invocations)); }
  assert.equal(calls, 0);
  assert.throws(() => guidedJsonBytes({ data: "x".repeat(200) }, 10), /evidence-budget/);
  assert.throws(() => (PERSISTENT_GUIDED_LIMITS as any).archiveBytes = Number.MAX_SAFE_INTEGER, TypeError);
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() { assert.ok(process.env.COMPACT_RUNTIME_TEST); assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST requires pinned COMPACTC_TEST"); return { compiler: process.env.COMPACTC_TEST, runtime: process.env.COMPACT_RUNTIME_TEST }; }

test("[timing] actual pinned CLI records the fixed lifecycle and exact original cases", qualified, context => {
  inputs(); const root = directory(context), output = resolve(root, "actual");
  const result = spawnSync(process.execPath, [resolve("dist/tests/generative/persistent-guided.js"), "--output", output, "--mutations", "0", "--max-evaluations", "4"], { encoding: "utf8", timeout: 120000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr + result.stdout);
  const summary = json(resolve(output, "summary.json")) as PersistentGuidedSummary;
  assert.equal(summary.outcome.status, "passed"); assert.equal(summary.counts.evaluatorInvoked, 4);
  const lifecycle = validatePersistentArtifact(json(resolve(output, "0004.json")));
  assert.equal(lifecycle.result.status, "passed");
  if (lifecycle.result.status === "passed") assert.deepEqual(lifecycle.result.observation.rows.flatMap(row => row.witnesses), ["7", "8", "8", "9", "9"]);
  assert.deepEqual(auditPersistentSchedule(summary.transcript, originalData(output, summary)).transcript, summary.transcript);
  assert.deepEqual(validatePersistentGuidedSummary(summary, summary.transcript, invocationData(output, summary)), summary);
});

test("[timing] actual fixed worker timeout remains evaluator incomplete with exact saved limits", qualified, async context => {
  const { compiler, runtime } = inputs(), root = directory(context), output = resolve(root, "timeout"), tiny = { ...PERSISTENT_LIMITS, timeoutMs: 1 };
  const summary = await writePersistentGuidedRun(output, { ...configuration(), workerLimits: tiny }, (sequence, limits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal), () => persistentGuidedBuildIdentity(compiler, runtime));
  assert.equal(summary.outcome.status, "incomplete"); assert.ok(summary.outcome.diagnostics.includes("worker-timeout"));
  assert.equal(summary.counts.evaluatorInvoked, 1); assert.equal(summary.counts.retained, 0);
  const invocation = invocationData(output, summary)[0]; assert.equal(invocation.resultOrigin, "evaluator"); assert.equal(invocation.abortCause, null); assert.deepEqual(invocation.workerLimits, tiny);
});

test("[timing] actual fixed evaluator is cancelled by the independent campaign signal", qualified, async context => {
  const { compiler, runtime } = inputs(), root = directory(context), output = resolve(root, "cancel"), external = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const summary = await writePersistentGuidedRun(output, { ...configuration(), workerLimits: PERSISTENT_LIMITS }, (sequence, limits, signal) => {
      const work = runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal);
      timer = setTimeout(() => external.abort(), 5); return work;
    }, () => persistentGuidedBuildIdentity(compiler, runtime), external.signal);
    assert.equal(summary.outcome.status, "incomplete"); assert.ok(summary.outcome.diagnostics.includes("persistent-campaign-interrupted"));
    const invocation = invocationData(output, summary)[0]; assert.equal(invocation.evaluatorInvoked, true); assert.equal(invocation.resultOrigin, "supervisor");
    assert.deepEqual(invocation.workerLimits, PERSISTENT_LIMITS); assert.equal(invocation.result.diagnostic, "worker-interrupted");
    assert.equal(summary.counts.retained, 0);
  } finally { if (timer) clearTimeout(timer); }
});
