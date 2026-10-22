import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";
import { persistentListBuildIdentity, PERSISTENT_LIST_FILE_BYTES, readPersistentListArtifact, type PersistentListIdentity } from "./generative/persistent-list-artifacts.js";
import {
  checkPersistentListObservation, expectedPersistentListSequence, generatePersistentListSequence, incompletePersistentListResult,
  persistentListDigest, PERSISTENT_LIST_LIMITS, PERSISTENT_LIST_LOCK_SHA256, PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_SOURCE_SHA256,
  type PersistentListObservation, type PersistentListResult, type PersistentListSequence,
} from "./generative/persistent-list-model.js";
import { persistentListReplayMain, recordPersistentList, replayPersistentList, validatePersistentListRecordConfiguration, validatePersistentListReplayConfiguration, type PersistentListEvaluator } from "./generative/persistent-list-replay.js";
import { runPersistentListSequenceIsolated } from "./generative/persistent-list-runtime.js";

const identity: PersistentListIdentity = {
  analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64),
  parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64),
  semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64",
  runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256,
  listWorkerSourceSha256: "1".repeat(64), listWorkerBuildSha256: "2".repeat(64), listFixtureSha256: PERSISTENT_LIST_SOURCE_SHA256,
};
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const config = { seed: 7, steps: 12, workerLimits: limits, maxElapsedMs: 60000 };
const zero = () => 0;
function root(context: TestContext): string { const path = mkdtempSync(resolve(tmpdir(), "nightshade-list-replay-")); context.after(() => rmSync(path, { recursive: true, force: true })); return path; }
const caseFile = (directory: string) => resolve(directory, "case.json");
const json = (directory: string, name = "summary.json") => JSON.parse(readFileSync(resolve(directory, name), "utf8"));

/** Synthetic schema/property-checker evidence only; not execution attestation. */
function wire(sequence: PersistentListSequence, salt = "synthetic"): PersistentListObservation {
  const expected = expectedPersistentListSequence(sequence), initialHash = persistentListDigest(`${salt}:initial`);
  let current = initialHash;
  const slots = Array<string>(4).fill(current);
  const rows = expected.rows.map(row => {
    const beforeHash = current;
    if (row.operation.kind === "push" || row.operation.kind === "guardedPop" && row.outcome === "evaluation-success") current = persistentListDigest(`${salt}:mutation:${row.index}`);
    if (row.operation.kind === "save") slots[row.operation.slot] = current;
    if (row.operation.kind === "restore") current = slots[row.operation.slot];
    return { ...row, before: { ...row.before, publicSha256: beforeHash }, after: { ...row.after, publicSha256: current }, slots: row.slots.map((view, index) => ({ ...view, publicSha256: slots[index] })) };
  });
  return {
    schemaVersion: "nightshade-persistent-list-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-guarded-list",
    compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256,
    sourceSha256: PERSISTENT_LIST_SOURCE_SHA256, compiledJavaScriptSha256: persistentListDigest("synthetic compiled code"),
    sequenceSha256: persistentListDigest(JSON.stringify(sequence)), initial: { ...expected.initial, publicSha256: initialHash }, rows, final: { ...expected.final, publicSha256: current },
  };
}
const checked = (sequence: PersistentListSequence, observation = wire(sequence)) => checkPersistentListObservation(sequence, observation);
const passing: PersistentListEvaluator = async sequence => checked(sequence);
function failure(sequence: PersistentListSequence, next = "99"): PersistentListResult { const observation = wire(sequence); observation.initial.next = next; return checked(sequence, observation); }
const record = (directory: string, evaluate = passing, configuration: unknown = config) => recordPersistentList(directory, configuration, evaluate, () => identity, undefined, zero);
const replay = (input: string, output: string, evaluate = passing) => replayPersistentList(caseFile(input), output, evaluate, () => identity, {}, undefined, zero);

test("List recording and exact replay preserve generated sequence, worker limits, full evidence and truthful file references", async context => {
  const directory = root(context), input = resolve(directory, "record"), output = resolve(directory, "replay");
  const recorded = await record(input);
  assert.deepEqual(recorded.sequence, generatePersistentListSequence(7, 12));
  assert.equal(recorded.mode, "record"); assert.equal(recorded.saved, null); assert.equal(recorded.savedEnvelope, null); assert.equal(recorded.exactEvidenceMatched, false);
  let calls = 0;
  const replayed = await replay(input, output, async (sequence, bounded, signal) => {
    calls++; assert.deepEqual(bounded, limits); assert.ok(signal instanceof AbortSignal); return checked(sequence);
  });
  assert.equal(calls, 1); assert.equal(replayed.savedEnvelope, "not-inspected"); assert.equal(replayed.exactEvidenceMatched, true);
  assert.deepEqual(replayed.outcome, { status: "passed", diagnostics: [] });
  assert.ok(Object.values(replayed.comparison!).every(value => value === true));
  assert.deepEqual(replayed.invocation, { evaluatorInvoked: true, resultOrigin: "evaluator", timing: { startedAtMs: 0, finishedAtMs: 0, remainingMsAtLaunch: 60000 }, abortCause: null, result: { status: "passed", diagnostic: "persistent-list-model-checked", signature: "persistent-list-model-checked" } });
  const original = readFileSync(caseFile(input)), fresh = readFileSync(caseFile(output));
  assert.equal(replayed.saved!.originalSha256, persistentListDigest(original)); assert.equal(replayed.saved!.bytes, original.length);
  assert.equal(replayed.artifact.sha256, persistentListDigest(fresh)); assert.equal(replayed.artifact.bytes, fresh.length);
  assert.deepEqual(readdirSync(output).sort(), ["case.json", "summary.json"]);
  const persisted = json(output); replayed.sequence.operations.length = 0; replayed.identity.node = "v1.0.0"; assert.deepEqual(json(output), persisted);
  await assert.rejects(() => replay(input, output, async () => assert.fail("Exclusive mkdir must precede invocation")), /EEXIST/);
});

test("alternative original JSON formatting matches case semantics while exact bytes remain different", async context => {
  const directory = root(context), input = resolve(directory, "record"); await record(input);
  const saved = readPersistentListArtifact(caseFile(input)).artifact;
  const original = Buffer.from("\n " + JSON.stringify({ result: saved.result, limits: saved.limits, sequence: saved.sequence, identity: saved.identity, executionLayer: saved.executionLayer, purpose: saved.purpose, schemaVersion: saved.schemaVersion }, null, 2) + " \n");
  writeFileSync(caseFile(input), original);
  const summary = await replay(input, resolve(directory, "replay"));
  assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.comparison!.sameCanonicalArtifact, true); assert.equal(summary.comparison!.sameOriginalBytes, false);
  assert.equal(summary.saved!.originalSha256, persistentListDigest(original)); assert.equal(summary.saved!.bytes, original.length);
});

test("one detached read survives source replacement and evaluator mutation of supplied sequence and limits", async context => {
  const directory = root(context), input = resolve(directory, "record"), output = resolve(directory, "replay"); await record(input);
  const original = readFileSync(caseFile(input)); let identities = 0;
  const summary = await replayPersistentList(caseFile(input), output, async (sequence, bounded) => {
    const result = checked(sequence); sequence.operations.length = 0; bounded.timeoutMs = 1; return result;
  }, () => { if (++identities === 1) writeFileSync(caseFile(input), "not an artifact anymore"); return identity; }, {}, undefined, zero);
  assert.equal(summary.exactEvidenceMatched, true); assert.equal(summary.saved!.originalSha256, persistentListDigest(original));
  assert.deepEqual(summary.sequence, generatePersistentListSequence(7, 12)); assert.deepEqual(summary.configuration.workerLimits, limits);
  assert.deepEqual(readPersistentListArtifact(caseFile(output)).artifact.sequence, summary.sequence);
});

test("every saved identity field and invalid source/configuration refuses before mkdir or evaluator invocation", async context => {
  const directory = root(context), input = resolve(directory, "record"); await record(input);
  let calls = 0;
  for (const key of Object.keys(identity) as (keyof PersistentListIdentity)[]) {
    const next = { ...identity, [key]: key.endsWith("Sha256") ? "0".repeat(64) : key === "node" ? "v22.23.3" : "other" };
    const output = resolve(directory, key);
    await assert.rejects(() => replayPersistentList(caseFile(input), output, async () => { calls++; return null; }, () => next));
    assert.equal(existsSync(output), false);
  }
  const absent = resolve(directory, "absent");
  await assert.rejects(() => replayPersistentList(resolve(directory, "missing.json"), absent, passing, () => { calls++; return identity; }));
  await assert.rejects(() => replayPersistentList(caseFile(input), absent, passing, () => { calls++; return identity; }, { workerLimits: limits }));
  await assert.rejects(() => recordPersistentList(absent, { seed: 1, workerLimits: undefined }, passing, () => { calls++; return identity; }));
  assert.equal(calls, 0); assert.equal(existsSync(absent), false);
});

test("full observation drift including consistent hash renaming and compiled code cannot pass equal labels", async context => {
  const directory = root(context), input = resolve(directory, "record"); await record(input);
  for (const kind of ["hashes", "compiled"] as const) {
    const summary = await replay(input, resolve(directory, kind), async sequence => {
      const observation = wire(sequence, kind === "hashes" ? "renamed" : "synthetic");
      if (kind === "compiled") observation.compiledJavaScriptSha256 = "0".repeat(64);
      const result = checked(sequence, observation); assert.equal(result.status, "passed"); return result;
    });
    assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false);
    assert.equal(summary.comparison!.sameStatus, true); assert.equal(summary.comparison!.sameSignature, true);
    assert.equal(summary.comparison!.sameFullResult, false); assert.equal(summary.comparison!.sameObservation, false);
    assert.equal(summary.comparison!.sameCompiledJavaScript, kind === "hashes");
    assert.ok(summary.outcome.diagnostics.includes("persistent-list-replay-result-drift"));
    assert.equal(readPersistentListArtifact(caseFile(resolve(directory, kind))).artifact.result.status, "passed");
  }
});

test("qualified synthetic failure is recorded and reproduced as failure, and equal signatures cannot hide new values", async context => {
  const directory = root(context), input = resolve(directory, "record");
  const saved = await record(input, async sequence => failure(sequence)); assert.equal(saved.outcome.status, "failed");
  const exact = await replay(input, resolve(directory, "exact"), async sequence => failure(sequence));
  assert.equal(exact.exactEvidenceMatched, true); assert.equal(exact.outcome.status, "failed");
  for (const variant of ["other-failure", "passing"]) {
    const summary = await replay(input, resolve(directory, variant), variant === "passing" ? passing : async sequence => failure(sequence, "100"));
    assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false);
    assert.equal(summary.comparison!.sameSignature, variant === "other-failure"); assert.equal(summary.comparison!.sameFullResult, false);
  }
});

test("saved and fresh incomplete results remain incomplete while ordinary worker codes keep evaluator provenance", async context => {
  const directory = root(context), input = resolve(directory, "record");
  const timedOut: PersistentListEvaluator = async () => incompletePersistentListResult("worker-timeout", "Synthetic worker deadline");
  await record(input, timedOut);
  for (const kind of ["same", "passing"]) {
    const summary = await replay(input, resolve(directory, kind), kind === "same" ? timedOut : passing);
    assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false);
    assert.ok(summary.outcome.diagnostics.includes("persistent-list-replay-saved-incomplete"));
    assert.equal(summary.comparison!.bothComplete, false); assert.equal(summary.comparison!.matched, false); assert.equal(summary.comparison!.sameObservation, null);
    assert.equal(summary.invocation.resultOrigin, "evaluator"); assert.equal(summary.invocation.result.diagnostic, kind === "same" ? "worker-timeout" : "persistent-list-model-checked");
  }
  const passingInput = resolve(directory, "passing-input"); await record(passingInput);
  for (const diagnostic of ["worker-output-budget", "worker-input-budget", "worker-failed", "worker-launch", "persistent-list-compiler"] as const) {
    const summary = await replay(passingInput, resolve(directory, diagnostic), async () => incompletePersistentListResult(diagnostic, "Synthetic worker failure"));
    assert.equal(summary.invocation.resultOrigin, "evaluator"); assert.equal(summary.invocation.result.diagnostic, diagnostic); assert.equal(summary.exactEvidenceMatched, false);
  }
});

test("thrown and malformed evaluator results become explicit supervisor protocol evidence", async context => {
  const directory = root(context);
  const evaluators: PersistentListEvaluator[] = [async () => { throw new Error("Synthetic exception"); }, async () => ({}), async sequence => ({ ...checked(sequence), signature: "forged" })];
  for (const [index, evaluate] of evaluators.entries()) {
    const output = resolve(directory, String(index)), summary = await record(output, evaluate);
    assert.equal(summary.invocation.evaluatorInvoked, true); assert.equal(summary.invocation.resultOrigin, "supervisor");
    assert.equal(summary.invocation.result.diagnostic, "persistent-list-protocol"); assert.equal(summary.outcome.status, "incomplete");
    assert.equal(Object.hasOwn(readPersistentListArtifact(caseFile(output)).artifact.result, "observation"), false);
  }
});

test("preabort and preflight deadline save uninvoked supervisor cases without clipping worker limits", async context => {
  const directory = root(context), input = resolve(directory, "record"); await record(input);
  for (const mode of ["record", "replay"] as const) for (const cause of ["external-signal", "deadline"] as const) {
    const controller = new AbortController(); if (cause === "external-signal") controller.abort();
    const output = resolve(directory, `${mode}-${cause}`), clock = () => cause === "deadline" ? 20 : 0;
    const evaluate: PersistentListEvaluator = async () => assert.fail("Pre-aborted operation must not invoke evaluator");
    const summary = mode === "record" ? await recordPersistentList(output, { ...config, maxElapsedMs: 20 }, evaluate, () => identity, controller.signal, clock)
      : await replayPersistentList(caseFile(input), output, evaluate, () => identity, { maxElapsedMs: 20 }, controller.signal, clock);
    assert.equal(summary.invocation.evaluatorInvoked, false); assert.equal(summary.invocation.resultOrigin, "supervisor");
    assert.equal(summary.invocation.timing.startedAtMs, null); assert.equal(summary.invocation.timing.remainingMsAtLaunch, null);
    assert.equal(summary.invocation.abortCause, cause); assert.equal(summary.finalAbortCause, cause);
    assert.equal(summary.invocation.result.diagnostic, "worker-interrupted"); assert.equal(summary.returnedArtifact, null);
    assert.deepEqual(readPersistentListArtifact(caseFile(output)).artifact.limits, limits);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  }
});

test("[timing] overall deadline races an evaluator that ignores abort and late resolution/rejection cannot write evidence", async context => {
  const directory = root(context);
  for (const late of ["resolve", "reject"] as const) {
    let finish: ((value: unknown) => void) | undefined, reject: ((error: unknown) => void) | undefined, supplied: PersistentListSequence | undefined;
    const output = resolve(directory, late), started = performance.now();
    // Leave enough setup slack for a loaded compiler-gated worker to invoke
    // the intentionally never-settling evaluator before the supervisor timer
    // fires; the test is about late completion isolation, not a 15ms race.
    const summary = await recordPersistentList(output, { ...config, maxElapsedMs: 100 }, (sequence, bounded) => {
      supplied = sequence; assert.deepEqual(bounded, limits); return new Promise((yes, no) => { finish = yes; reject = no; });
    }, () => identity);
    assert.ok(performance.now() - started < 2000); assert.ok(finish && reject && supplied);
    assert.equal(summary.finalAbortCause, "deadline"); assert.equal(summary.invocation.resultOrigin, "supervisor"); assert.equal(summary.returnedArtifact, null);
    const before = readdirSync(output).map(name => [name, readFileSync(resolve(output, name), "utf8")]);
    if (late === "resolve") finish(checked(supplied)); else reject(new Error("Synthetic late ignored rejection"));
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(readdirSync(output).map(name => [name, readFileSync(resolve(output, name), "utf8")]), before);
  }
});

test("[timing] external cancellation races ignored signal and remains first cause even after deadline", async context => {
  const directory = root(context), controller = new AbortController(); let time = 0;
  const summary = await recordPersistentList(resolve(directory, "run"), { ...config, maxElapsedMs: 30 }, async () => {
    setTimeout(() => { controller.abort(); time = 30; }, 5); return new Promise(() => {});
  }, () => identity, controller.signal, () => time);
  assert.equal(summary.invocation.abortCause, "external-signal"); assert.equal(summary.finalAbortCause, "external-signal");
  assert.equal(summary.returnedArtifact, null); assert.equal(summary.outcome.status, "incomplete");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("already settled valid evidence is retained once when the post-await clock disqualifies selection", async context => {
  const directory = root(context); let time = 0;
  const output = resolve(directory, "record"), summary = await recordPersistentList(output, { ...config, maxElapsedMs: 20 }, async (sequence, bounded) => {
    assert.equal(bounded.timeoutMs, 1000); time = 20; return checked(sequence);
  }, () => identity, undefined, () => time);
  assert.equal(summary.invocation.resultOrigin, "supervisor"); assert.equal(summary.invocation.result.diagnostic, "worker-interrupted");
  assert.equal(summary.invocation.abortCause, "deadline"); assert.equal(summary.returnedArtifact!.name, "returned-case.json");
  const returned = readPersistentListArtifact(resolve(output, "returned-case.json"));
  assert.equal(returned.artifact.result.status, "passed"); assert.equal(summary.returnedArtifact!.sha256, returned.sha256);
  assert.equal(readPersistentListArtifact(caseFile(output)).artifact.result.status, "incomplete");
  assert.deepEqual(readdirSync(output).sort(), ["case.json", "returned-case.json", "summary.json"]);
});

test("replay retains settled signal-disqualified evidence and saved worker timeout exceeds its independent overall budget", async context => {
  const directory = root(context), input = resolve(directory, "record"), output = resolve(directory, "replay"); await record(input);
  const controller = new AbortController(); let settled = false;
  const summary = await replayPersistentList(caseFile(input), output, async (sequence, bounded) => {
    assert.deepEqual(bounded, limits); const result = checked(sequence); settled = true; return result;
  }, () => identity, { maxElapsedMs: 20 }, controller.signal, () => { if (settled) controller.abort(); return 0; });
  assert.equal(summary.invocation.resultOrigin, "supervisor"); assert.equal(summary.invocation.abortCause, "external-signal");
  assert.equal(summary.finalAbortCause, "external-signal"); assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false);
  assert.equal(summary.invocation.timing.remainingMsAtLaunch, 20); assert.equal(summary.configuration.workerLimits.timeoutMs, 1000);
  assert.equal(readPersistentListArtifact(resolve(output, "returned-case.json")).artifact.result.status, "passed");
  assert.equal(readPersistentListArtifact(caseFile(output)).artifact.result.status, "incomplete");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("preflight identity work consumes the overall budget and prevents evaluator launch", async context => {
  const directory = root(context); let time = 0;
  const summary = await recordPersistentList(resolve(directory, "record"), { ...config, maxElapsedMs: 20 }, async () => assert.fail("Expired preflight must not invoke"), () => { time = 20; return identity; }, undefined, () => time);
  assert.equal(summary.invocation.evaluatorInvoked, false); assert.equal(summary.invocation.abortCause, "deadline");
  assert.equal(summary.configuration.workerLimits.timeoutMs, 1000); assert.equal(summary.elapsedMs, 20);
});

test("post-identity drift, unavailable identity, final signal and final deadline disqualify envelopes without rewriting actual cases", async context => {
  const directory = root(context), input = resolve(directory, "record"); await record(input);
  for (const mode of ["record", "replay"] as const) for (const gap of ["drift", "unavailable", "signal", "deadline"] as const) {
    let calls = 0, time = 0; const controller = new AbortController(), output = resolve(directory, `${mode}-${gap}`);
    const provider = () => {
      if (++calls === 2) {
        if (gap === "drift") return { ...identity, listWorkerBuildSha256: "0".repeat(64) };
        if (gap === "unavailable") throw new Error("Synthetic unavailable final identity");
        if (gap === "signal") controller.abort();
        if (gap === "deadline") time = 20;
      }
      return identity;
    };
    const summary = mode === "record" ? await recordPersistentList(output, { ...config, maxElapsedMs: 20 }, passing, provider, controller.signal, () => time)
      : await replayPersistentList(caseFile(input), output, passing, provider, { maxElapsedMs: 20 }, controller.signal, () => time);
    assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.exactEvidenceMatched, false); assert.equal(summary.invocation.resultOrigin, "evaluator");
    assert.equal(summary.invocation.abortCause, null); assert.equal(summary.returnedArtifact, null);
    assert.equal(readPersistentListArtifact(caseFile(output)).artifact.result.status, "passed");
    assert.equal(summary.postIdentity.status, gap === "drift" || gap === "unavailable" ? gap : "matched");
    assert.equal(summary.finalAbortCause, gap === "deadline" ? "deadline" : gap === "signal" ? "external-signal" : null);
  }
});

test("case-only replay explicitly leaves an incomplete originating recording envelope uninspected", async context => {
  const directory = root(context), input = resolve(directory, "record"), controller = new AbortController(); let calls = 0;
  const recorded = await recordPersistentList(input, config, passing, () => { if (++calls === 2) controller.abort(); return identity; }, controller.signal, zero);
  assert.equal(recorded.outcome.status, "incomplete"); assert.equal(readPersistentListArtifact(caseFile(input)).artifact.result.status, "passed");
  const savedSummary = readFileSync(resolve(input, "summary.json"));
  const replayed = await replay(input, resolve(directory, "replay"));
  assert.equal(replayed.exactEvidenceMatched, true); assert.equal(replayed.outcome.status, "passed"); assert.equal(replayed.savedEnvelope, "not-inspected");
  assert.equal(replayed.saved!.status, "passed"); assert.deepEqual(readFileSync(resolve(input, "summary.json")), savedSummary);
  assert.equal(json(input).outcome.status, "incomplete", "Matching only case evidence cannot clear the originating envelope");
});

function oversized(sequence: PersistentListSequence): PersistentListResult {
  const observation = wire(sequence), views = [observation.initial, ...observation.rows.flatMap(row => [row.before, row.after, ...row.slots]), observation.final];
  for (const view of views) view.values = Array<string>(64).fill("1".repeat(80));
  let excess = Buffer.byteLength(JSON.stringify(observation)) - (PERSISTENT_LIST_FILE_BYTES - 128);
  assert.ok(excess > 0);
  for (const view of views) for (let index = 0; index < view.values.length && excess > 0; index++) {
    const remove = Math.min(79, excess); view.values[index] = view.values[index].slice(remove); excess -= remove;
  }
  assert.equal(excess, 0);
  const result = checked(sequence, observation); assert.equal(result.status, "failed"); return result;
}

test("artifact envelope overhead becomes explicit incomplete evidence, including an oversized returned companion", async context => {
  const directory = root(context);
  for (const cancellation of [false, true]) {
    let time = 0; const output = resolve(directory, String(cancellation));
    const summary = await recordPersistentList(output, { ...config, steps: 32, maxElapsedMs: 20 }, async sequence => {
      const result = oversized(sequence); if (cancellation) time = 20; return result;
    }, () => identity, undefined, () => time);
    assert.equal(summary.outcome.status, "incomplete"); assert.equal(summary.invocation.resultOrigin, "supervisor");
    assert.ok(summary.outcome.diagnostics.includes("persistent-list-evaluation-artifact-budget"));
    assert.equal(summary.invocation.result.diagnostic, cancellation ? "worker-interrupted" : "persistent-list-observation-budget");
    assert.equal(summary.finalAbortCause, cancellation ? "deadline" : null); assert.equal(summary.returnedArtifact, null);
    assert.equal(Object.hasOwn(readPersistentListArtifact(caseFile(output)).artifact.result, "observation"), false);
    assert.deepEqual(readdirSync(output).sort(), ["case.json", "summary.json"]);
  }
});

test("configuration data is closed, detached and bounded without invoking accessors", () => {
  assert.deepEqual(validatePersistentListRecordConfiguration({ seed: 0 }), { seed: 0, steps: 32, workerLimits: PERSISTENT_LIST_LIMITS, maxElapsedMs: 60000 });
  assert.deepEqual(validatePersistentListReplayConfiguration({}), { maxElapsedMs: 60000 });
  const detached = validatePersistentListRecordConfiguration(config); detached.workerLimits.timeoutMs = 1; assert.equal(limits.timeoutMs, 1000);
  let reads = 0;
  const accessor = Object.defineProperty({ seed: 1 }, "workerLimits", { enumerable: true, get() { reads++; return limits; } });
  for (const value of [accessor, { seed: 1, workerLimits: undefined }, { seed: 1, steps: undefined }, { seed: 1, maxElapsedMs: undefined }, { seed: -0 }, { seed: 4294967296 }, { seed: 1, steps: 33 }, { seed: 1, maxElapsedMs: 0 }, { seed: 1, maxElapsedMs: 60001 }, { seed: 1, source: "unsupported" }, Object.assign(Object.create({}), { seed: 1 }), Object.assign({ seed: 1 }, { [Symbol("extra")]: true })]) assert.throws(() => validatePersistentListRecordConfiguration(value));
  for (const value of [{ maxElapsedMs: undefined }, { maxElapsedMs: -0 }, { maxElapsedMs: 1.5 }, { compareBuild: true }, { workerLimits: limits }]) assert.throws(() => validatePersistentListReplayConfiguration(value));
  assert.equal(reads, 0);
});

test("clock seams reject invalid or decreasing integer time before output or launch", async context => {
  const directory = root(context);
  for (const value of [-0, -1, NaN, Infinity, 0.5]) {
    const output = resolve(directory, String(value));
    await assert.rejects(() => recordPersistentList(output, config, async () => assert.fail("Invalid clock must not invoke"), () => identity, undefined, () => value));
    assert.equal(existsSync(output), false);
  }
  let ticks = 0; const output = resolve(directory, "decreasing");
  await assert.rejects(() => recordPersistentList(output, config, async () => assert.fail("Decreasing clock must not invoke"), () => identity, undefined, () => ticks++ ? 0 : 1));
  assert.equal(existsSync(output), false);
});

test("CLI rejects duplicate/unknown/mixed flags, noncanonical integers and saved-limit overrides before I/O", async context => {
  const directory = root(context), base = ["--record", "--seed", "7", "--steps", "1", "--output", resolve(directory, "new")];
  for (const args of [[], ["--record"], [...base, "--record"], [...base, "--seed", "8"], [...base, "--replay", "case.json"], [...base, "--compare-build"], [...base, "--source", "arbitrary"], ...["01", "-0", "+1", "1.0", "1e2", "4294967296"].map(seed => base.map((value, index) => index === 2 ? seed : value)), ...["--timeout-ms", "--heap-mib", "--max-output-bytes", "--seed", "--steps"].map(flag => ["--replay", "/must-not-read", "--output", resolve(directory, "new"), flag, "1"]), [...base, "--max-elapsed-ms", "60001"]]) await assert.rejects(() => persistentListReplayMain(args));
  assert.equal(existsSync(resolve(directory, "new")), false);
  const cli = fileURLToPath(new URL("./generative/persistent-list-replay.js", import.meta.url));
  const help = spawnSync(process.execPath, [cli, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0); assert.match(help.stdout, /compiled evaluation only/); assert.match(help.stdout, /originating recording envelope is not inspected or cleared/);
  const invalid = spawnSync(process.execPath, [cli, "--compare-build"], { encoding: "utf8" }); assert.equal(invalid.status, 2);
});

test("[timing] pinned generated List recording, detached artifact read and exact replay preserve actual full compiler observations", { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false }, async context => {
  assert.ok(process.env.COMPACTC_TEST); assert.ok(process.env.COMPACT_RUNTIME_TEST);
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST, directory = root(context), input = resolve(directory, "record"), output = resolve(directory, "replay");
  const evaluate: PersistentListEvaluator = (sequence, bounded, signal) => runPersistentListSequenceIsolated(sequence, compiler, runtime, bounded, signal);
  const provider = () => persistentListBuildIdentity(compiler, runtime);
  const recorded = await recordPersistentList(input, { seed: 7, steps: 32 }, evaluate, provider);
  assert.equal(recorded.outcome.status, "passed", JSON.stringify(recorded));
  const saved = readPersistentListArtifact(caseFile(input)); assert.equal(saved.artifact.result.status, "passed");
  const replayed = await replayPersistentList(caseFile(input), output, evaluate, provider);
  assert.equal(replayed.outcome.status, "passed", JSON.stringify(replayed)); assert.equal(replayed.exactEvidenceMatched, true); assert.equal(replayed.savedEnvelope, "not-inspected");
  assert.equal(replayed.comparison!.sameOriginalBytes, true); assert.equal(replayed.comparison!.sameObservation, true);
  assert.deepEqual(readPersistentListArtifact(caseFile(output)).artifact.result, saved.artifact.result);
});
