import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { replayPersistentReduction, persistentReductionReplayMain, type PersistentReductionReplayOptions } from "./generative/persistent-reduction-replay.js";
import { writePersistentReductionRun, type OwnedPersistentEvaluator, type PersistentReductionRunOptions } from "./generative/persistent-reduction-cli.js";
import { incompletePersistentResult, makePersistentArtifact, persistentBuildIdentity, runPersistentSequenceIsolated, validatePersistentArtifact, type PersistentIdentity, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";

const input = validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 17, operations: [{ kind: "inspect" }, { kind: "reject" }, { kind: "inspect" }] });
const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const savedLimits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };

/** Synthetic protocol/model observations only, never evidence of a runtime bug. */
function fixture(model: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(model);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic count:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(model)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const passed = (model: PersistentSequence) => checkPersistentObservation(model, fixture(model), PERSISTENT_SOURCE_SHA256);
function fault(model: PersistentSequence, delta = 1n, field: "next" | "count" = "next", compiled?: string): PersistentResult {
  const wire = fixture(model), row = wire.rows.find(row => row.operation === "reject");
  if (row) row.after[field] = String(BigInt(row.after[field]) + delta);
  if (compiled) wire.compiledJavaScriptSha256 = compiled;
  return checkPersistentObservation(model, wire, PERSISTENT_SOURCE_SHA256);
}
function directory(context: TestContext): string {
  const root = mkdtempSync(resolve(tmpdir(), "nightshade-reduction-replay-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}
const json = (path: string) => JSON.parse(readFileSync(path, "utf8"));
const artifactAt = (directory: string, file: string) => validatePersistentArtifact(json(resolve(directory, file)));
async function saved(directory: string, evaluate: OwnedPersistentEvaluator = async model => fault(model), options: PersistentReductionRunOptions = {}, initial = fault(input)) {
  return writePersistentReductionRun(Buffer.from(JSON.stringify(makePersistentArtifact(input, identity, savedLimits, initial))), identity, directory, evaluate, options);
}

test("replay matches every saved invocation in order with exact saved limits and retains the failed final", async context => {
  const root = directory(context), source = resolve(root, "source"), output = resolve(root, "replay");
  const original = await saved(source);
  const observed: PersistentSequence[] = [];
  const summary = await replayPersistentReduction(source, identity, output, async (model, limits, signal) => {
    assert.deepEqual(limits, savedLimits); assert.equal(signal.aborted, false);
    observed.push(structuredClone(model)); return fault(model);
  });
  assert.equal(summary.replayStatus, "complete"); assert.equal(summary.savedReductionStatus, "complete"); assert.equal(summary.exactEvidenceMatched, true);
  assert.equal(summary.savedFinalStatus, "failed"); assert.equal(summary.invocations, 3); assert.equal(summary.recordedInvocations, 3);
  assert.deepEqual(observed.map(model => model.operations), [input.operations, [{ kind: "inspect" }, { kind: "reject" }], [{ kind: "reject" }]]);
  assert.deepEqual(summary.rows.map(row => row.savedFile), ["original-replay.json", "attempt-0001.json", "attempt-0002.json"]);
  assert.ok(summary.rows.every(row => row.state === "matched" && row.replayEvaluatorInvoked && row.comparison!.exactEvidenceMatch));
  assert.deepEqual(summary.finalSource, { savedFile: original.final!.sourceArtifact, replayArtifact: "replay-0003.json", matched: true });
  assert.equal(artifactAt(output, summary.finalSource!.replayArtifact!).result.status, "failed");
  assert.equal(summary.savedSummarySha256, persistentDigest(readFileSync(resolve(source, "summary.json"))));
  for (const row of summary.rows) {
    const bytes = readFileSync(resolve(output, row.fresh!.artifact));
    assert.equal(row.fresh!.sha256, persistentDigest(bytes)); assert.equal(row.fresh!.bytes, bytes.length);
    assert.equal(row.savedSha256, persistentDigest(readFileSync(resolve(source, row.savedFile))));
    assert.deepEqual(artifactAt(output, row.fresh!.artifact).limits, artifactAt(source, row.savedFile).limits);
  }
  assert.equal(readdirSync(output).length, 4, "input/final copies are not extra runtime invocations");
  const persisted = json(resolve(output, "summary.json")); summary.rows.length = 0;
  assert.deepEqual(json(resolve(output, "summary.json")), persisted);
});

test("[timing] replay does not rewrite saved worker limits to fit its independent shorter overall deadline", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const seen: number[] = [];
  const summary = await replayPersistentReduction(source, identity, resolve(root, "replay"), async (model, limits) => {
    seen.push(limits.timeoutMs); assert.deepEqual(limits, savedLimits); return fault(model);
  }, { maxElapsedMs: 300 });
  assert.equal(summary.replayStatus, "complete"); assert.deepEqual(seen, [1000, 1000, 1000]);
  assert.equal(summary.maxElapsedMs, 300);
});

test("exact evidence replay preserves saved check exhaustion, passing refusal and uninvoked records", async context => {
  const root = directory(context), partial = resolve(root, "partial");
  await saved(partial, async model => fault(model), { maxChecks: 1 });
  const checked = await replayPersistentReduction(partial, identity, resolve(root, "partial-replay"), async model => fault(model));
  assert.equal(checked.replayStatus, "complete"); assert.equal(checked.exactEvidenceMatched, true);
  assert.equal(checked.savedReductionStatus, "incomplete"); assert.deepEqual(checked.savedReductionDiagnostics, ["persistent-reduction-check-budget"]); assert.equal(checked.savedFinalStatus, "failed");
  const refusal = resolve(root, "refusal"); await saved(refusal, async model => passed(model), {}, passed(input));
  const refused = await replayPersistentReduction(refusal, identity, resolve(root, "refusal-replay"), async model => passed(model));
  assert.equal(refused.replayStatus, "complete"); assert.equal(refused.savedReductionStatus, "incomplete");
  assert.deepEqual(refused.savedReductionDiagnostics, ["persistent-reduction-not-failed"]); assert.equal(refused.savedFinalStatus, null); assert.equal(refused.finalSource, null);
  const controller = new AbortController(); controller.abort();
  const uninvoked = resolve(root, "uninvoked"); await saved(uninvoked, async () => assert.fail("pre-aborted source evaluator"), { signal: controller.signal });
  const retained = await replayPersistentReduction(uninvoked, identity, resolve(root, "uninvoked-replay"), async () => assert.fail("saved uninvoked row cannot execute"));
  assert.equal(retained.replayStatus, "incomplete"); assert.equal(retained.invocations, 0); assert.equal(retained.recordedInvocations, 0); assert.equal(retained.exactEvidenceMatched, false);
  assert.equal(retained.rows[0].state, "saved-uninvoked"); assert.equal(retained.rows[0].fresh, null);
});

test("matching saved/fresh incomplete classes never become exact evidence success", async context => {
  const root = directory(context), source = resolve(root, "source");
  await saved(source, async () => incompletePersistentResult("worker-timeout", "Synthetic saved timeout"));
  const result = await replayPersistentReduction(source, identity, resolve(root, "same-class"), async () => incompletePersistentResult("worker-timeout", "Synthetic fresh timeout"));
  assert.equal(result.replayStatus, "incomplete"); assert.equal(result.exactEvidenceMatched, false);
  assert.equal(result.rows[0].comparison!.sameIncompleteClass, true); assert.equal(result.rows[0].comparison!.exactEvidenceMatch, false); assert.equal(result.rows[0].state, "incomplete");
  assert.ok(result.diagnostics.includes("persistent-reduction-replay-saved-incomplete")); assert.ok(result.diagnostics.includes("persistent-reduction-replay-evaluation-incomplete"));
  const completed = await replayPersistentReduction(source, identity, resolve(root, "new-complete"), async model => fault(model));
  assert.equal(completed.replayStatus, "incomplete"); assert.equal(completed.rows[0].state, "incomplete"); assert.equal(completed.rows[0].comparison!.sameIncompleteClass, null);
});

test("early observation/signature/status/compiled drift stops before outstanding saved invocations", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const variants: [string, (model: PersistentSequence) => PersistentResult, keyof NonNullable<Awaited<ReturnType<typeof replayPersistentReduction>>["rows"][number]["comparison"]>][] = [
    ["observation", model => fault(model, 2n), "sameObservation"],
    ["signature", model => fault(model, 1n, "count"), "sameSignature"],
    ["status", model => passed(model), "sameStatus"],
    ["compiled", model => fault(model, 1n, "next", "f".repeat(64)), "sameCompiledJavaScript"],
  ];
  for (const [name, evaluate, differing] of variants) {
    let calls = 0;
    const summary = await replayPersistentReduction(source, identity, resolve(root, name), async model => ++calls === 1 ? fault(model) : evaluate(model));
    assert.equal(calls, 2); assert.equal(summary.replayStatus, "incomplete"); assert.equal(summary.exactEvidenceMatched, false);
    assert.deepEqual(summary.rows.map(row => row.state), ["matched", "drift", "not-replayed"]);
    assert.equal(summary.rows[1].comparison![differing], false);
    assert.equal(summary.rows[2].replayEvaluatorInvoked, false); assert.equal(summary.rows[2].fresh, null); assert.equal(summary.rows[2].comparison, null);
    assert.deepEqual(summary.finalSource, { savedFile: "attempt-0002.json", replayArtifact: null, matched: false });
  }
});

test("identity and malformed audit refusal occur before directory creation or evaluator calls", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const changed = resolve(root, "identity-refused");
  await assert.rejects(() => replayPersistentReduction(source, { ...identity, node: "v0.0.0" }, changed, async () => assert.fail("identity refusal must not evaluate")), /exact build identity/);
  assert.equal(existsSync(changed), false);
  const bad = resolve(root, "bad-source"); cpSync(source, bad, { recursive: true }); writeFileSync(resolve(bad, "summary.json"), "{");
  const refused = resolve(root, "audit-refused");
  await assert.rejects(() => replayPersistentReduction(bad, identity, refused, async () => assert.fail("audit failure must not evaluate")), /invalid JSON/);
  assert.equal(existsSync(refused), false);
  for (const options of [{ maxElapsedMs: 0 }, { maxElapsedMs: 60001 }, { maxElapsedMs: NaN }, { maxElapsedMs: 1.5 }, { maxElapsedMs: undefined }, { source: "arbitrary" }, { signal: {} }]) {
    await assert.rejects(() => replayPersistentReduction(source, identity, refused, async () => assert.fail("invalid options must not evaluate"), options as PersistentReductionReplayOptions));
  }
  assert.equal(existsSync(refused), false);
});

test("replay uses one detached audited snapshot even if the trusted test evaluator mutates saved files", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const originalSummary = readFileSync(resolve(source, "summary.json"));
  const originalHashes = new Map(readdirSync(source).map(file => [file, persistentDigest(readFileSync(resolve(source, file)))]));
  let calls = 0;
  const replay = await replayPersistentReduction(source, identity, resolve(root, "replay"), async model => {
    if (++calls === 1) {
      for (const file of readdirSync(source)) writeFileSync(resolve(source, file), "mutated after audit\n");
    }
    return fault(model);
  });
  assert.equal(replay.replayStatus, "complete"); assert.equal(calls, 3);
  assert.equal(replay.savedSummarySha256, persistentDigest(originalSummary));
  for (const file of replay.savedFiles) assert.equal(file.sha256, originalHashes.get(file.file));
});

test("evaluator mutation is isolated and thrown, stale, forged or accessor responses stay incomplete", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const retained: PersistentResult[] = [];
  const output = resolve(root, "detached");
  const good = await replayPersistentReduction(source, identity, output, async (model, limits) => {
    const result = fault(model); retained.push(result);
    model.operations.push({ kind: "accept" }); limits.heapMiB = 256;
    return result;
  });
  assert.equal(good.replayStatus, "complete");
  const before = readFileSync(resolve(output, "replay-0001.json"));
  retained[0].signature = "mutated after replay";
  if (retained[0].status !== "incomplete") retained[0].observation.rows.length = 0;
  assert.deepEqual(readFileSync(resolve(output, "replay-0001.json")), before);
  assert.deepEqual(artifactAt(output, "replay-0001.json").limits, savedLimits);
  const invalid: [string, (model: PersistentSequence) => unknown][] = [
    ["throw", () => { throw new Error("Synthetic evaluator exception"); }],
    ["unreadable", () => { throw { toString() { assert.fail("error coercion must not run"); } }; }],
    ["undefined", () => undefined],
    ["stale", () => fault(input)],
    ["forged", model => ({ ...fault(model), signature: "invented" })],
    ["accessor", model => { const result = fault(model); if (result.status !== "incomplete") Object.defineProperty(result.observation.rows[0].after, "next", { enumerable: true, get() { assert.fail("must not invoke observation getter"); } }); return result; }],
  ];
  for (const [name, evaluate] of invalid) {
    let calls = 0; const target = resolve(root, name);
    const summary = await replayPersistentReduction(source, identity, target, async model => ++calls === 1 ? fault(model) : evaluate(model));
    assert.equal(calls, 2); assert.deepEqual(summary.rows.map(row => row.state), ["matched", "incomplete", "not-replayed"]);
    assert.equal(summary.replayStatus, "incomplete"); assert.equal(artifactAt(target, "replay-0002.json").result.diagnostic, "persistent-protocol");
  }
});

test("[timing] deadline races retain exact saved limits, abort pending evaluation and ignore late matching evidence", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  let signal: AbortSignal | undefined, finish: ((value: unknown) => void) | undefined;
  const output = resolve(root, "timed");
  const summary = await replayPersistentReduction(source, identity, output, (_model, limits, observed) => {
    assert.deepEqual(limits, savedLimits); signal = observed;
    return new Promise(resolve => { finish = resolve; });
  }, { maxElapsedMs: 20 });
  assert.equal(signal!.aborted, true); assert.equal(summary.replayStatus, "incomplete"); assert.equal(summary.invocations, 1);
  assert.ok(summary.diagnostics.includes("persistent-reduction-replay-time-budget"));
  assert.deepEqual(summary.rows.map(row => row.state), ["incomplete", "not-replayed", "not-replayed"]);
  const timed = artifactAt(output, "replay-0001.json"); assert.deepEqual(timed.limits, savedLimits); assert.equal(timed.result.diagnostic, "worker-timeout");
  const recorded = readFileSync(resolve(output, "summary.json")); finish!(fault(input)); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(readFileSync(resolve(output, "summary.json")), recorded);
});

test("pre-abort and cancellation after a matched original leave pending invocations unexecuted", async context => {
  const root = directory(context), source = resolve(root, "source"); await saved(source);
  const before = new AbortController(); before.abort();
  const pre = await replayPersistentReduction(source, identity, resolve(root, "pre"), async () => assert.fail("pre-aborted replay cannot execute"), { signal: before.signal });
  assert.equal(pre.invocations, 0); assert.equal(pre.replayStatus, "incomplete"); assert.ok(pre.rows.every(row => row.state === "not-replayed" && row.fresh === null));
  assert.ok(pre.diagnostics.includes("persistent-reduction-replay-interrupted"));
  const controller = new AbortController(); let calls = 0;
  const output = resolve(root, "during");
  const during = await replayPersistentReduction(source, identity, output, async model => { if (++calls === 2) controller.abort(); return fault(model); }, { signal: controller.signal });
  assert.equal(calls, 2); assert.equal(during.replayStatus, "incomplete");
  assert.deepEqual(during.rows.map(row => row.state), ["matched", "incomplete", "not-replayed"]);
  assert.equal(artifactAt(output, "replay-0002.json").result.diagnostic, "worker-interrupted");
});

test("replay output cannot overwrite evidence and CLI cannot select arbitrary source or inject failures", async context => {
  const root = directory(context), source = resolve(root, "source"), output = resolve(root, "replay"); await saved(source);
  await replayPersistentReduction(source, identity, output, async model => fault(model));
  const original = readFileSync(resolve(output, "summary.json"));
  await assert.rejects(() => replayPersistentReduction(source, identity, output, async () => assert.fail("exclusive output must refuse before evaluation")), /EEXIST/);
  assert.deepEqual(readFileSync(resolve(output, "summary.json")), original);
  for (const flag of ["--source", "--state", "--adapter", "--compare-build", "--inject-failure", "--timeout-ms"]) {
    await assert.rejects(() => persistentReductionReplayMain(["--replay", source, "--output", resolve(root, flag.slice(2)), flag, "1"]), /Invalid persistent reduction replay argument/);
  }
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
const cli = (args: string[]) => spawnSync(process.execPath, [resolve("dist/tests/generative/persistent-reduction-replay.js"), ...args], { encoding: "utf8", timeout: 90000, maxBuffer: 1048576 });
test("[timing] actual fixed-fixture CLI preserves genuine nonfailure refusal and a saved 1ms runtime timeout", qualified, async context => {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned compiler alongside runtime");
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!, root = directory(context);
  const measured = await runPersistentSequenceIsolated(input, compiler, runtime); assert.equal(measured.status, "passed");
  const current = persistentBuildIdentity(compiler, runtime), artifact = makePersistentArtifact(input, current, PERSISTENT_LIMITS, measured);
  const evaluate: OwnedPersistentEvaluator = (model, limits, signal) => runPersistentSequenceIsolated(model, compiler, runtime, limits, signal);
  const passing = resolve(root, "passing"); await writePersistentReductionRun(Buffer.from(JSON.stringify(artifact)), current, passing, evaluate);
  const passedOutput = resolve(root, "passing-replay"), success = cli(["--replay", passing, "--output", passedOutput]);
  assert.equal(success.status, 2, success.stderr || success.stdout);
  const matching = json(resolve(passedOutput, "summary.json"));
  assert.equal(matching.replayStatus, "complete"); assert.equal(matching.savedReductionStatus, "incomplete"); assert.equal(matching.savedFinalStatus, null);
  assert.deepEqual(matching.savedReductionDiagnostics, ["persistent-reduction-not-failed"]);
  artifact.limits.timeoutMs = 1;
  const timed = resolve(root, "timed"); await writePersistentReductionRun(Buffer.from(JSON.stringify(artifact)), current, timed, evaluate);
  const timedOutput = resolve(root, "timed-replay"), timeout = cli(["--replay", timed, "--output", timedOutput]);
  assert.equal(timeout.status, 2, timeout.stderr || timeout.stdout);
  const incomplete = json(resolve(timedOutput, "summary.json"));
  assert.equal(incomplete.replayStatus, "incomplete"); assert.equal(incomplete.exactEvidenceMatched, false);
  assert.equal(incomplete.rows[0].comparison.sameIncompleteClass, true);
  const fresh = artifactAt(timedOutput, "replay-0001.json"); assert.equal(fresh.limits.timeoutMs, 1); assert.equal(fresh.result.diagnostic, "worker-timeout");
});
