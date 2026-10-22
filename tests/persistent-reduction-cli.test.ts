import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { runNodeModule, WorkerFailure } from "../src/runtime/process.js";
import { incompletePersistentResult, makePersistentArtifact, persistentBuildIdentity, runPersistentSequenceIsolated, validatePersistentArtifact, type PersistentIdentity } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";
import { persistentReductionMain, writePersistentReductionRun, type OwnedPersistentEvaluator } from "./generative/persistent-reduction-cli.js";

const input = validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 17, operations: [{ kind: "inspect" }, { kind: "reject" }, { kind: "inspect" }] });
const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
/** Synthetic schema-only evidence, never a claim of actual runtime execution. */
function fixture(sequence: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(sequence);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic count:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
function fault(sequence: PersistentSequence, delta = 1n, field: "next" | "count" = "next", compiled?: string) {
  const wire = fixture(sequence);
  const row = wire.rows.find(row => row.operation === "reject");
  if (row) row.after[field] = String(BigInt(row.after[field]) + delta);
  if (compiled) wire.compiledJavaScriptSha256 = compiled;
  return checkPersistentObservation(sequence, wire, PERSISTENT_SOURCE_SHA256);
}
const savedLimits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const source = () => Buffer.from(JSON.stringify(makePersistentArtifact(input, identity, savedLimits, fault(input)), null, 3) + "\n\n");
const json = (path: string) => JSON.parse(readFileSync(path, "utf8"));
function directory(context: TestContext) {
  const root = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-reduction-cli-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("owned injected orchestration saves exact input, original replay, every attempt and detached final evidence", async context => {
  const root = directory(context), output = resolve(root, "run"), bytes = source();
  const summary = await writePersistentReductionRun(bytes, identity, output, async (sequence, limits, signal) => {
    assert.equal(signal.aborted, false); assert.deepEqual(limits, savedLimits);
    return fault(sequence);
  });
  assert.equal(summary.reductionStatus, "complete"); assert.equal(summary.replay.matchedFailure, true);
  assert.ok(summary.checks > 0); assert.equal(summary.checks, summary.attempts.length);
  assert.deepEqual(readFileSync(resolve(output, "input.json")), bytes);
  assert.equal(summary.final!.caseStatus, "failed"); assert.deepEqual(summary.final!.originalRows, [1]);
  const final = validatePersistentArtifact(json(resolve(output, "final.json")));
  assert.deepEqual(final.sequence.operations, [{ kind: "reject" }]);
  assert.equal(final.result.status, "failed"); assert.equal(final.result.signature, "persistent-model|row:0|operation:reject|field:after.next");
  for (const file of [summary.input, summary.originalReplay, ...summary.attempts, summary.final!]) {
    const data = readFileSync(resolve(output, file.artifact));
    assert.equal(file.bytes, data.length); assert.equal(file.sha256, persistentDigest(data));
    validatePersistentArtifact(JSON.parse(data.toString("utf8")));
  }
  assert.deepEqual(json(resolve(output, summary.final!.sourceArtifact)), final);
  assert.ok(summary.attempts.every(attempt => attempt.evaluatorInvoked));
  assert.equal(readdirSync(output).length, summary.checks + 4);
  const persisted = json(resolve(output, "summary.json"));
  summary.attempts.length = 0; summary.identity.node = "v0.0.0";
  assert.notDeepEqual(summary, persisted); assert.deepEqual(json(resolve(output, "summary.json")), persisted);
  await assert.rejects(() => writePersistentReductionRun(bytes, identity, output, async () => assert.fail("cannot overwrite evidence")), /EEXIST/);
});

test("original replay must retain exact failure observations and code before any reduction", async context => {
  const root = directory(context);
  const cases: [string, OwnedPersistentEvaluator][] = [
    ["passed", async sequence => checkPersistentObservation(sequence, fixture(sequence), PERSISTENT_SOURCE_SHA256)],
    ["same-property-new-value", async sequence => fault(sequence, 2n)],
    ["different-property", async sequence => fault(sequence, 1n, "count")],
    ["compiled-drift", async sequence => fault(sequence, 1n, "next", "f".repeat(64))],
    ["infrastructure", async () => incompletePersistentResult("worker-failed", "synthetic infrastructure failure")],
    ["forged", async sequence => ({ ...fault(sequence), signature: "invented" })],
  ];
  for (const [name, evaluate] of cases) {
    let calls = 0;
    const summary = await writePersistentReductionRun(source(), identity, resolve(root, name), async (...args) => { calls++; return evaluate(...args); });
    assert.equal(calls, 1); assert.equal(summary.reductionStatus, "incomplete"); assert.equal(summary.replay.matchedFailure, false);
    assert.equal(summary.checks, 0); assert.equal(summary.final, null);
    assert.ok(summary.diagnostics.includes(name === "infrastructure" || name === "forged" ? "persistent-reduction-original-incomplete" : "persistent-reduction-replay-drift"));
  }
  const passing = checkPersistentObservation(input, fixture(input), PERSISTENT_SOURCE_SHA256);
  const bytes = Buffer.from(JSON.stringify(makePersistentArtifact(input, identity, savedLimits, passing)));
  const nonfailure = await writePersistentReductionRun(bytes, identity, resolve(root, "nonfailure"), async sequence => checkPersistentObservation(sequence, fixture(sequence), PERSISTENT_SOURCE_SHA256));
  assert.deepEqual(nonfailure.diagnostics, ["persistent-reduction-not-failed"]); assert.equal(nonfailure.final, null);
});

test("identity/schema/budget refusal precedes directory creation and no failure injection option exists", async context => {
  const root = directory(context);
  for (const [name, bytes, current] of [
    ["drift", source(), { ...identity, node: "v0.0.0" }],
    ["malformed", Buffer.from("{"), identity],
    ["source", Buffer.from(JSON.stringify({ ...JSON.parse(source().toString()), source: "arbitrary" })), identity],
    ["oversized", Buffer.alloc(1048577), identity],
  ] as const) {
    const output = resolve(root, name);
    await assert.rejects(() => writePersistentReductionRun(bytes, current, output, async () => assert.fail("refused input must not execute")));
    assert.equal(existsSync(output), false);
  }
  const output = resolve(root, "bounds");
  await assert.rejects(() => writePersistentReductionRun(source(), identity, output, async () => fault(input), { maxChecks: 257 }));
  assert.equal(existsSync(output), false);
  for (const flag of ["--inject-failure", "--compare-build", "--adapter", "--source", "--timeout-ms"]) await assert.rejects(() => persistentReductionMain(["--reduce", "owned.json", "--output", output, flag, "1"]), /Invalid persistent reduction argument/);
});

test("[timing] saved worker ceilings survive reduction, and total allowance includes original replay time", async context => {
  const root = directory(context);
  const calls: number[] = [];
  const summary = await writePersistentReductionRun(source(), identity, resolve(root, "clamped"), async (sequence, limits) => {
    calls.push(limits.timeoutMs); assert.equal(limits.heapMiB, savedLimits.heapMiB); assert.equal(limits.maxOutputBytes, savedLimits.maxOutputBytes);
    if (calls.length === 1) await new Promise(resolve => setTimeout(resolve, 30));
    return fault(sequence);
  }, { maxElapsedMs: 300 });
  assert.equal(summary.reductionStatus, "complete"); assert.ok(calls[0] <= 300 && calls[0] > 0);
  assert.ok(calls[1] < calls[0] - 15, "original replay consumes the total deadline");
  assert.deepEqual(summary.savedWorkerLimits, savedLimits);
  for (const record of [summary.originalReplay, ...summary.attempts]) {
    const artifact = validatePersistentArtifact(json(resolve(root, "clamped", record.artifact)));
    assert.deepEqual(artifact.limits, record.limits); assert.ok(record.limits.timeoutMs <= savedLimits.timeoutMs);
    assert.equal(record.limits.heapMiB, savedLimits.heapMiB); assert.equal(record.limits.maxOutputBytes, savedLimits.maxOutputBytes);
  }
});

test("sticky incomplete and check exhaustion retain accepted failure and all attempt records", async context => {
  const root = directory(context);
  let calls = 0;
  const sticky = await writePersistentReductionRun(source(), identity, resolve(root, "sticky"), async sequence => ++calls === 2 ? incompletePersistentResult("worker-output-budget", "synthetic exhaustion") : fault(sequence));
  assert.equal(sticky.reductionStatus, "incomplete"); assert.ok(sticky.diagnostics.includes("persistent-reduction-evaluation-incomplete"));
  assert.ok(sticky.attempts.some(attempt => attempt.preserved)); assert.equal(sticky.attempts[0].preserved, false);
  assert.equal(sticky.final!.caseStatus, "failed"); assert.deepEqual(sticky.final!.originalRows, [1]);
  const exhausted = await writePersistentReductionRun(source(), identity, resolve(root, "budget"), async sequence => fault(sequence), { maxChecks: 1 });
  assert.equal(exhausted.reductionStatus, "incomplete"); assert.equal(exhausted.checks, 1);
  assert.ok(exhausted.diagnostics.includes("persistent-reduction-check-budget")); assert.equal(exhausted.final!.sourceArtifact, "attempt-0001.json");
});

test("[timing] total timeout and external cancellation persist original/attempt incomplete evidence and reject late results", async context => {
  const root = directory(context);
  let late: ((value: unknown) => void) | undefined, observed: AbortSignal | undefined;
  const timed = await writePersistentReductionRun(source(), identity, resolve(root, "original-timeout"), (_sequence, _limits, signal) => {
    observed = signal; return new Promise(resolve => { late = resolve; });
  }, { maxElapsedMs: 20 });
  assert.equal(observed!.aborted, true); assert.equal(timed.checks, 0); assert.equal(timed.final, null);
  assert.ok(timed.diagnostics.includes("persistent-reduction-time-budget"));
  const before = readFileSync(resolve(root, "original-timeout/summary.json"));
  late!(fault(input)); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(readFileSync(resolve(root, "original-timeout/summary.json")), before);
  let calls = 0;
  const candidate = await writePersistentReductionRun(source(), identity, resolve(root, "candidate-timeout"), async sequence => {
    if (++calls === 1) return fault(sequence);
    return new Promise(() => {});
  }, { maxElapsedMs: 30 });
  assert.equal(candidate.reductionStatus, "incomplete"); assert.equal(candidate.checks, 1);
  assert.ok(candidate.diagnostics.includes("persistent-reduction-time-budget")); assert.equal(candidate.final!.sourceArtifact, "original-replay.json");
  assert.equal(validatePersistentArtifact(json(resolve(root, "candidate-timeout/attempt-0001.json"))).result.status, "incomplete");
  for (const mode of ["before", "during"] as const) {
    const controller = new AbortController(); if (mode === "before") controller.abort();
    const summary = await writePersistentReductionRun(source(), identity, resolve(root, mode), async sequence => { controller.abort(); return fault(sequence); }, { signal: controller.signal });
    assert.equal(summary.reductionStatus, "incomplete"); assert.ok(summary.diagnostics.includes("persistent-reduction-interrupted")); assert.equal(summary.final, null);
    assert.equal(summary.originalReplay.evaluatorInvoked, mode === "during"); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  }
});

async function waitForFile(path: string, milliseconds = 5000): Promise<void> {
  const deadline = Date.now() + milliseconds;
  while (!existsSync(path)) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${path}`);
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

test("[timing] supervisor optional abort rejects before launch and kills an active worker with cleanup", async context => {
  const root = directory(context), marker = resolve(root, "started.json"), module = resolve(root, "worker.mjs");
  writeFileSync(module, `import { writeFileSync } from 'node:fs'; import { tmpdir } from 'node:os'; writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ pid: process.pid, temporary: tmpdir() })); setInterval(() => {}, 1000);\n`);
  const before = new AbortController(); before.abort();
  await assert.rejects(runNodeModule(module, {}, { timeoutMs: 10000 }, before.signal), error => error instanceof WorkerFailure && error.code === "worker-interrupted");
  assert.equal(existsSync(marker), false); assert.equal(getEventListeners(before.signal, "abort").length, 0);
  const listeners = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
  const during = new AbortController();
  const running = runNodeModule(module, {}, { timeoutMs: 10000 }, during.signal);
  const rejected = assert.rejects(running, error => error instanceof WorkerFailure && error.code === "worker-interrupted");
  await waitForFile(marker);
  const started = json(marker); assert.equal(existsSync(started.temporary), true);
  during.abort(); await rejected;
  assert.equal(existsSync(started.temporary), false); assert.throws(() => process.kill(started.pid, 0), /ESRCH/);
  assert.equal(getEventListeners(during.signal, "abort").length, 0);
  assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], listeners);
  const success = resolve(root, "success.mjs"); writeFileSync(success, "console.log('owned success');\n");
  const finished = new AbortController();
  assert.equal((await runNodeModule(success, {}, {}, finished.signal)).stdout.trim(), "owned success");
  assert.equal(getEventListeners(finished.signal, "abort").length, 0); finished.abort();
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function cli(args: string[]) { return spawnSync(process.execPath, [resolve("dist/tests/generative/persistent-reduction-cli.js"), ...args], { encoding: "utf8", timeout: 90000, maxBuffer: 1048576 }); }
test("[timing] actual owned CLI replays genuine nonfailure, refuses identity drift, and records saved-limit exhaustion", qualified, async context => {
  assert.ok(process.env.COMPACTC_TEST);
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!;
  const root = directory(context), measured = await runPersistentSequenceIsolated(input, compiler, runtime);
  assert.equal(measured.status, "passed");
  const currentIdentity = persistentBuildIdentity(compiler, runtime);
  const artifact = makePersistentArtifact(input, currentIdentity, PERSISTENT_LIMITS, measured);
  const path = resolve(root, "case.json"); writeFileSync(path, JSON.stringify(artifact));
  const output = resolve(root, "passing");
  const run = cli(["--reduce", path, "--output", output]);
  assert.equal(run.status, 2, run.stderr || run.stdout);
  const summary = json(resolve(output, "summary.json"));
  assert.deepEqual(summary.diagnostics, ["persistent-reduction-not-failed"]); assert.equal(summary.checks, 0); assert.equal(summary.final, null);
  assert.equal(validatePersistentArtifact(json(resolve(output, "original-replay.json"))).result.status, "passed");
  artifact.identity.node = "v0.0.0"; writeFileSync(path, JSON.stringify(artifact));
  const refused = resolve(root, "refused"), refusal = cli(["--reduce", path, "--output", refused]);
  assert.equal(refusal.status, 2); assert.match(refusal.stderr, /exact build identity/); assert.equal(existsSync(refused), false);
  artifact.identity = currentIdentity; artifact.limits.timeoutMs = 1; writeFileSync(path, JSON.stringify(artifact));
  const timeout = resolve(root, "timeout");
  assert.equal(cli(["--reduce", path, "--output", timeout]).status, 2);
  const incomplete = validatePersistentArtifact(json(resolve(timeout, "original-replay.json")));
  assert.equal(incomplete.result.diagnostic, "worker-timeout"); assert.equal(incomplete.limits.timeoutMs, 1);
  assert.equal(json(resolve(timeout, "summary.json")).checks, 0);
});

test("[timing] actual fixed-fixture wrapper and CLI cancellation remain incomplete", qualified, async context => {
  assert.ok(process.env.COMPACTC_TEST);
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!;
  const cancelled = new AbortController(); cancelled.abort();
  const result = await runPersistentSequenceIsolated(input, compiler, runtime, PERSISTENT_LIMITS, cancelled.signal);
  assert.equal(result.status, "incomplete"); assert.equal(result.diagnostic, "worker-interrupted");
  const root = directory(context), measured = await runPersistentSequenceIsolated(input, compiler, runtime);
  assert.equal(measured.status, "passed");
  const path = resolve(root, "case.json"), output = resolve(root, "cancelled");
  writeFileSync(path, JSON.stringify(makePersistentArtifact(input, persistentBuildIdentity(compiler, runtime), PERSISTENT_LIMITS, measured)));
  const child = spawn(process.execPath, [resolve("dist/tests/generative/persistent-reduction-cli.js"), "--reduce", path, "--output", output], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = ""; child.stderr.on("data", value => { stderr += value; });
  const exited = new Promise<number | null>((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
  context.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
  await waitForFile(resolve(output, "input.json"));
  child.kill("SIGINT");
  assert.equal(await exited, 2, stderr);
  const summary = json(resolve(output, "summary.json"));
  assert.equal(summary.reductionStatus, "incomplete"); assert.ok(summary.diagnostics.includes("persistent-reduction-interrupted"));
  assert.equal(validatePersistentArtifact(json(resolve(output, "original-replay.json"))).result.diagnostic, "worker-interrupted");
  assert.equal(summary.checks, 0); assert.equal(summary.final, null);
});
