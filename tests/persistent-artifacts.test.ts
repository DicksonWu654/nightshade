import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { checkPersistentResponse, comparePersistentResults, incompletePersistentResult, makePersistentArtifact, PERSISTENT_FILE_BYTES, persistentBuildIdentity, persistentIdentityChanges, readPersistentFile, runPersistentSequenceIsolated, validatePersistentArtifact, validatePersistentLimits, validatePersistentResult, type PersistentIdentity } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_REJECTION, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation } from "./generative/persistent-model.js";

const sequence = validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 1, operations: [{ kind: "accept" }, { kind: "save", slot: 1 }, { kind: "reject" }, { kind: "accept" }, { kind: "restore", slot: 1 }, { kind: "inspect" }] });
/** Schema-only data, explicitly not evidence that a runtime executed. */
function fixture(): PersistentObservation {
  const expected = expectedPersistentSequence(sequence);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic count:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const syntheticIdentity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const checked = (wire: unknown = fixture()) => checkPersistentObservation(sequence, wire, PERSISTENT_SOURCE_SHA256);

// The sequence itself is also independently bounded by runtime-persistent.test.ts.
test("persistent results retain detached failures and derive property-specific signatures", () => {
  const good = checked();
  assert.equal(good.status, "passed");
  assert.deepEqual(validatePersistentResult(sequence, good), good);
  const mutations: [string, (wire: PersistentObservation) => void][] = [
    ["row:0|operation:accept|field:result", wire => { wire.rows[0].result = "99"; }],
    ["row:2|operation:reject|field:after.next", wire => { wire.rows[2].after.next = "99"; }],
    ["row:1|operation:save|field:slots.1.count", wire => { wire.rows[1].slots[1].count = "99"; }],
    ["row:4|operation:restore|field:after.publicSha256", wire => { wire.rows[4].after.publicSha256 = "f".repeat(64); }],
    ["row:0|operation:accept|field:witnesses", wire => { wire.rows[0].witnesses.push("8"); }],
    ["field:final.count", wire => { wire.final.count = "99"; }],
  ];
  for (const [signature, mutate] of mutations) {
    const wire = fixture(); mutate(wire);
    const bad = checked(wire);
    assert.equal(bad.status, "failed");
    assert.equal(bad.signature, `persistent-model|${signature}`);
    assert.deepEqual(validatePersistentResult(sequence, bad), bad);
    assert.throws(() => validatePersistentResult(sequence, { ...bad, signature: "persistent-model|invented" }), /qualification/);
    assert.throws(() => validatePersistentResult(sequence, { ...bad, message: "invented" }), /qualification/);
    assert.throws(() => validatePersistentResult(sequence, { ...good, observation: wire }), /qualification/);
    wire.rows.length = 0; assert.equal(bad.observation.rows.length, sequence.operations.length);
  }
  const wrongSource = fixture(); wrongSource.sourceSha256 = "f".repeat(64);
  assert.equal(checked(wrongSource).status, "incomplete");
  const absent = fixture(); absent.rows.pop();
  assert.equal(checked(absent).status, "incomplete");
  const exception = fixture(); exception.rows[2].error = { name: "Error", message: PERSISTENT_REJECTION } as never;
  assert.equal(checked(exception).diagnostic, "persistent-unqualified-rejection");
});

test("persistent artifact validation rejects arbitrary inputs, forged labels, identities and accessor data", () => {
  const artifact = makePersistentArtifact(sequence, syntheticIdentity, PERSISTENT_LIMITS, checked());
  assert.deepEqual(validatePersistentArtifact(JSON.parse(JSON.stringify(artifact))), artifact);
  for (const altered of [
    { ...artifact, source: "arbitrary" }, { ...artifact, state: {} }, { ...artifact, adapter: "other" },
    { ...artifact, sequence: { ...sequence, operations: [{ kind: "call", circuit: "other" }] } },
    { ...artifact, identity: { ...syntheticIdentity, persistentFixtureSha256: "f".repeat(64) } },
    { ...artifact, identity: { ...syntheticIdentity, runtimeLockSha256: "f".repeat(64) } },
    { ...artifact, limits: { ...PERSISTENT_LIMITS, heapMiB: 512 } },
    { ...artifact, result: { ...artifact.result, status: "failed" } },
    { ...artifact, result: { ...artifact.result, feedback: "invented" } },
  ]) assert.throws(() => validatePersistentArtifact(altered));
  const hidden = structuredClone(artifact);
  Object.defineProperty(hidden.identity, "persistentWorkerBuildSha256", { value: "a".repeat(64), enumerable: false });
  assert.throws(() => validatePersistentArtifact(hidden), /hidden field/);
  const accessor = structuredClone(artifact);
  if (accessor.result.status !== "incomplete") Object.defineProperty(accessor.result.observation.rows[0], "witnesses", { enumerable: true, get() { assert.fail("getter must not run"); } });
  assert.throws(() => validatePersistentArtifact(accessor), /qualification/);
  for (const limits of [{ timeoutMs: 1 }, { ...PERSISTENT_LIMITS, timeoutMs: 0 }, { ...PERSISTENT_LIMITS, maxOutputBytes: 1048577 }]) assert.throws(() => validatePersistentLimits(limits));
  assert.deepEqual(persistentIdentityChanges(syntheticIdentity, { ...syntheticIdentity, persistentWorkerBuildSha256: "4".repeat(64) }), ["persistentWorkerBuildSha256"]);
  const changed = fixture(); changed.compiledJavaScriptSha256 = "f".repeat(64);
  const comparison = comparePersistentResults(artifact.result, checked(changed));
  assert.equal(comparison.sameObservation, true);
  assert.equal(comparison.sameCompiledJavaScript, false);
  const first = fixture(), second = fixture();
  first.rows[0].result = "98"; second.rows[0].result = "99";
  const differentEvidence = comparePersistentResults(checked(first), checked(second));
  assert.equal(differentEvidence.sameStatus, true);
  assert.equal(differentEvidence.sameSignature, true);
  assert.equal(differentEvidence.sameObservation, false, "same property is insufficient for exact replay");
});

test("persistent incomplete evidence stays bounded and never becomes property or rejection success", () => {
  for (const [stdout, stderr] of [["{invalid", ""], [JSON.stringify(fixture()), "unexpected"], ["é".repeat(5000), ""]]) {
    const result = checkPersistentResponse(sequence, stdout, stderr);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostic, "persistent-protocol");
    assert.deepEqual(result.diagnosticResponse!.stdout, { bytes: Buffer.byteLength(stdout), sha256: persistentDigest(stdout), prefix: stdout.slice(0, 4096), truncated: stdout.length > 4096 });
    assert.deepEqual(validatePersistentResult(sequence, result), result);
    assert.equal(Object.hasOwn(result, "observation"), false);
  }
  const corrupted = checkPersistentResponse(sequence, "broken", "");
  corrupted.diagnosticResponse!.stdout.sha256 = "f".repeat(64);
  assert.throws(() => validatePersistentResult(sequence, corrupted), /stream identity/);
  const truncated = checkPersistentResponse(sequence, "é".repeat(5000), "");
  truncated.diagnosticResponse!.stdout.bytes = 4097;
  assert.throws(() => validatePersistentResult(sequence, truncated), /truncated diagnostic/);
  const split = checkPersistentResponse(sequence, "a".repeat(4095) + "😀", "");
  assert.deepEqual(validatePersistentResult(sequence, split), split);
  assert.equal(checkPersistentResponse(sequence, "x".repeat(PERSISTENT_LIMITS.maxOutputBytes + 1), "").diagnostic, "worker-output-budget");
  const incomplete = incompletePersistentResult("worker-timeout", "timeout");
  assert.throws(() => validatePersistentResult(sequence, { ...incomplete, observation: fixture() }));
});

test("persistent saved-input reads are capped and reject non-files", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-input-"));
  try {
    const path = resolve(directory, "input.json");
    writeFileSync(path, JSON.stringify(sequence));
    assert.deepEqual(JSON.parse(readPersistentFile(path).toString("utf8")), sequence);
    truncateSync(path, PERSISTENT_FILE_BYTES + 1);
    assert.throws(() => readPersistentFile(path), /exceeds 1 MiB/);
    assert.throws(() => readPersistentFile(directory), /regular file/);
    const output = resolve(directory, "invalid-output");
    assert.equal(cli(["--sequence", path, "--output", output]).status, 2);
    assert.equal(existsSync(output), false);
    writeFileSync(path, "{malformed");
    assert.equal(cli(["--sequence", path, "--output", output]).status, 2);
    assert.equal(existsSync(output), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned compiler alongside runtime");
  assert.ok(process.env.COMPACT_RUNTIME_TEST);
  return { compiler: resolve(process.env.COMPACTC_TEST), runtime: resolve(process.env.COMPACT_RUNTIME_TEST) };
}
function cli(args: string[]) {
  return spawnSync(process.execPath, [resolve("dist/tests/generative/persistent-replay.js"), ...args], { encoding: "utf8", timeout: 90000, maxBuffer: 1048576 });
}

test("fixed-fixture persistent recording and exact replay preserve rejection, snapshots and evidence identity", qualified, () => {
  inputs();
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-replay-"));
  try {
    const input = resolve(directory, "sequence.json");
    writeFileSync(input, JSON.stringify(sequence));
    const recorded = resolve(directory, "recorded");
    const record = cli(["--sequence", input, "--output", recorded]);
    assert.equal(record.status, 0, record.stderr || record.stdout);
    const path = resolve(recorded, "case.json");
    const artifact = validatePersistentArtifact(JSON.parse(readFileSync(path, "utf8")));
    assert.equal(artifact.result.status, "passed");
    if (artifact.result.status !== "passed") throw new Error("Expected complete measured fixture");
    assert.equal(artifact.result.observation.rows[2].outcome, "evaluation-rejection");
    assert.equal(artifact.result.observation.final.count, "1");
    assert.equal(artifact.result.observation.final.next, "8");
    const replay = resolve(directory, "replay");
    const run = cli(["--replay", path, "--output", replay]);
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const summary = JSON.parse(readFileSync(resolve(replay, "summary.json"), "utf8"));
    assert.equal(summary.replay.matched, true);
    assert.equal(summary.replay.sameObservation, true);
    assert.equal(summary.replay.sameCompiledJavaScript, true);
    assert.equal(summary.replay.previousArtifactSha256, persistentDigest(readFileSync(path)));
    assert.deepEqual(summary.limits, PERSISTENT_LIMITS);
    assert.equal(cli(["--replay", path, "--output", replay]).status, 2, "evidence cannot be overwritten");
    assert.equal(cli(["--replay", path, "--output", resolve(directory, "override"), "--timeout-ms", "1"]).status, 2);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("persistent replay rejects drift and forged results; explicit comparison records changed identities", qualified, async () => {
  const { compiler, runtime } = inputs();
  const measured = await runPersistentSequenceIsolated(sequence, compiler, runtime);
  assert.equal(measured.status, "passed", JSON.stringify(measured));
  if (measured.status !== "passed") throw new Error("Expected measured fixture");
  const identity = persistentBuildIdentity(compiler, runtime);
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-drift-"));
  try {
    const original = makePersistentArtifact(sequence, identity, PERSISTENT_LIMITS, measured);
    const path = resolve(directory, "case.json");
    const save = (value: unknown) => writeFileSync(path, JSON.stringify(value));
    const drift = structuredClone(original); drift.identity.persistentWorkerBuildSha256 = "f".repeat(64);
    save(drift);
    const refused = resolve(directory, "refused");
    const refusal = cli(["--replay", path, "--output", refused]);
    assert.equal(refusal.status, 2); assert.match(refusal.stderr, /identity mismatch/); assert.equal(existsSync(refused), false);
    const compared = resolve(directory, "compared");
    const comparison = cli(["--replay", path, "--output", compared, "--compare-build"]);
    assert.equal(comparison.status, 0, comparison.stderr || comparison.stdout);
    const comparedSummary = JSON.parse(readFileSync(resolve(compared, "summary.json"), "utf8"));
    assert.deepEqual(comparedSummary.replay.changedIdentityFields, ["persistentWorkerBuildSha256"]);
    assert.equal(comparedSummary.replay.comparison, true);
    const compiled = structuredClone(original);
    if (compiled.result.status !== "incomplete") compiled.result.observation.compiledJavaScriptSha256 = "f".repeat(64);
    save(compiled);
    const compiledOutput = resolve(directory, "compiled");
    assert.equal(cli(["--replay", path, "--output", compiledOutput]).status, 2);
    const compiledSummary = JSON.parse(readFileSync(resolve(compiledOutput, "summary.json"), "utf8"));
    assert.equal(compiledSummary.replay.sameObservation, true); assert.equal(compiledSummary.replay.sameCompiledJavaScript, false); assert.equal(compiledSummary.replay.matched, false);
    const comparedCode = resolve(directory, "compiled-comparison");
    assert.equal(cli(["--replay", path, "--output", comparedCode, "--compare-build"]).status, 0);
    const codeSummary = JSON.parse(readFileSync(resolve(comparedCode, "summary.json"), "utf8"));
    assert.equal(codeSummary.replay.sameCompiledJavaScript, false); assert.equal(codeSummary.replay.comparison, true); assert.equal(codeSummary.replay.matched, true);
    // Deliberate postmeasurement corruption; this is not a discovered runtime bug.
    const wire = structuredClone(measured.observation); wire.rows[2].after.next = "99";
    const failure = checkPersistentObservation(sequence, wire, PERSISTENT_SOURCE_SHA256);
    assert.equal(failure.status, "failed");
    save(makePersistentArtifact(sequence, identity, PERSISTENT_LIMITS, failure));
    const repaired = resolve(directory, "repaired");
    assert.equal(cli(["--replay", path, "--output", repaired]).status, 2, "clean execution must expose stored property drift");
    const repairedSummary = JSON.parse(readFileSync(resolve(repaired, "summary.json"), "utf8"));
    assert.equal(repairedSummary.status, "passed"); assert.equal(repairedSummary.replay.previousStatus, "failed"); assert.equal(repairedSummary.replay.matched, false);
    save({ ...original, result: { ...failure, signature: "invented" } });
    const forged = resolve(directory, "forged");
    assert.equal(cli(["--replay", path, "--output", forged]).status, 2); assert.equal(existsSync(forged), false);
    save({ ...original, identity: { ...identity, persistentFixtureSha256: "f".repeat(64) } });
    assert.equal(cli(["--replay", path, "--output", resolve(directory, "other-source"), "--compare-build"]).status, 2);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("[timing] persistent replay preserves resource budgets and infrastructure remains incomplete", qualified, async () => {
  const { compiler, runtime } = inputs();
  const identity = persistentBuildIdentity(compiler, runtime);
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-budget-"));
  try {
    for (const [name, limits, diagnostic] of [
      ["timeout", { ...PERSISTENT_LIMITS, timeoutMs: 1 }, "worker-timeout"],
      ["output", { ...PERSISTENT_LIMITS, maxOutputBytes: 1024 }, "worker-output-budget"],
    ] as const) {
      const result = await runPersistentSequenceIsolated(sequence, compiler, runtime, limits);
      assert.equal(result.status, "incomplete"); assert.equal(result.diagnostic, diagnostic);
      const path = resolve(directory, `${name}.json`);
      writeFileSync(path, JSON.stringify(makePersistentArtifact(sequence, identity, limits, result)));
      const output = resolve(directory, name);
      assert.equal(cli(["--replay", path, "--output", output]).status, 2);
      const summary = JSON.parse(readFileSync(resolve(output, "summary.json"), "utf8"));
      assert.equal(summary.status, "incomplete"); assert.equal(summary.diagnostic, diagnostic); assert.deepEqual(summary.limits, limits);
    }
    const infrastructure = await runPersistentSequenceIsolated(sequence, "/missing-compiler", runtime);
    assert.equal(infrastructure.status, "incomplete"); assert.equal(infrastructure.diagnostic, "worker-failed");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
