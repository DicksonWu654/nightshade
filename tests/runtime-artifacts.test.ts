import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { digest } from "./generative/artifacts.js";
import { expectedFlagObservations, renderCase, validateCase, type GeneratedCase } from "./generative/model.js";
import { checkRuntimeObservation, checkRuntimeResponse, compareRuntimeResults, makeRuntimeArtifact, RUNTIME_LIMITS, runRuntimeCaseIsolated, runtimeBuildIdentity, runtimeIdentityChanges, validateRuntimeArtifact, validateRuntimeLimits, validateRuntimeResult, type RuntimeIdentity } from "./generative/runtime-artifacts.js";
import { reduceRuntimeCase } from "./generative/runtime-reduce.js";

const model = validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 3, operations: [{ kind: "write", value: 9 }, { kind: "read", key: 0 }] });
/** Schema-only values; these do not claim a runtime executed. */
function fixture(input = model) {
  return { layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: digest(renderCase(input)), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(row => row.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })) };
}
const syntheticIdentity: RuntimeIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: "0".repeat(64), runtimeInputsManifestSha256: "1".repeat(64), runtimeAdapterSourceSha256: "2".repeat(64), runtimeAdapterBuildSha256: "3".repeat(64) };

test("runtime result validation derives status, feedback and the violated property from complete observations", () => {
  const good = checkRuntimeObservation(model, fixture());
  assert.equal(good.status, "passed");
  assert.deepEqual(validateRuntimeResult(model, good), good);
  for (const field of ["status", "category", "signature"]) assert.throws(() => validateRuntimeResult(model, { ...good, [field]: "invented" }));
  const wire = fixture();
  wire.executions[0].result[0][0].value = "10";
  const bad = checkRuntimeObservation(model, wire);
  assert.equal(bad.status, "failed");
  assert.equal(bad.signature, "runtime-model|flag:false|operation:write|field:scalar|value");
  assert.equal(bad.feedback, undefined);
  assert.deepEqual(validateRuntimeResult(model, bad), bad);
  assert.throws(() => validateRuntimeResult(model, { ...good, observation: bad.observation }));
  assert.throws(() => validateRuntimeResult(model, { ...bad, signature: "runtime-model|other" }));
  const otherField = fixture();
  otherField.executions[0].result[0][2].value = "1";
  assert.notEqual(checkRuntimeObservation(model, otherField).signature, bad.signature);
});

test("complete return shape/kind violations are properties; missing execution or envelope is incomplete", () => {
  const short = fixture();
  short.executions[0].result = [];
  assert.match(checkRuntimeObservation(model, short).signature, /return-layout$/);
  const missingCell = fixture();
  missingCell.executions[0].result[0].pop();
  assert.match(checkRuntimeObservation(model, missingCell).signature, /checkpoint-layout$/);
  const kind = fixture();
  kind.executions[0].result[0][0] = { kind: "boolean", value: "true" };
  assert.match(checkRuntimeObservation(model, kind).signature, /field:scalar\|kind$/);
  for (const wire of [{ ...fixture(), executions: [] }, { ...fixture(), executions: [fixture().executions[0]] }, { ...fixture(), runtime: "0.19.104" }]) {
    const result = checkRuntimeObservation(model, wire);
    assert.equal(result.status, "incomplete");
    assert.equal(result.observation, undefined);
    assert.equal(result.feedback, undefined);
  }
});

test("runtime validation detaches evidence and refuses nested accessors and forged feedback", () => {
  const result = checkRuntimeObservation(model, fixture());
  const detached = validateRuntimeResult(model, result);
  result.observation!.executions.length = 0;
  assert.equal(detached.observation!.executions.length, 2);
  const changed = checkRuntimeObservation(model, fixture());
  changed.feedback!.features.push("invented-execution-edge");
  assert.throws(() => validateRuntimeResult(model, changed));
  const accessor = checkRuntimeObservation(model, fixture());
  Object.defineProperty(accessor.feedback, "features", { enumerable: true, get() { assert.fail("validation must not invoke nested getters"); } });
  assert.throws(() => validateRuntimeResult(model, accessor), /qualification/);
});

test("protocol failures preserve bounded response identity without producing passing feedback", () => {
  for (const [stdout, stderr] of [["{malformed", ""], [JSON.stringify(fixture()), "unexpected diagnostic"], ["x".repeat(5000), "é".repeat(5000)]]) {
    const result = checkRuntimeResponse(model, stdout, stderr);
    assert.equal(result.status, "incomplete");
    assert.equal(result.category, "runtime-protocol");
    assert.equal(result.feedback, undefined);
    assert.equal(result.observation, undefined);
    for (const [name, text] of [["stdout", stdout], ["stderr", stderr]] as const) {
      assert.deepEqual(result.diagnosticResponse![name], { bytes: Buffer.byteLength(text), sha256: digest(text), prefix: text.slice(0, 4096), truncated: text.length > 4096 });
    }
    assert.deepEqual(validateRuntimeResult(model, result), result);
  }
  const corrupt = checkRuntimeResponse(model, "{bad", "");
  corrupt.diagnosticResponse!.stdout.sha256 = "a".repeat(64);
  assert.throws(() => validateRuntimeResult(model, corrupt), /stream identity/);
  const truncated = checkRuntimeResponse(model, "é".repeat(5000), "");
  truncated.diagnosticResponse!.stdout.bytes = 4097;
  assert.throws(() => validateRuntimeResult(model, truncated), /truncated diagnostic/);
  const surrogate = checkRuntimeResponse(model, "a".repeat(4095) + "😀", "");
  assert.deepEqual(validateRuntimeResult(model, surrogate), surrogate, "a split surrogate remains a valid bounded prefix");
});

test("runtime artifacts bind owned source, exact identities and bounded execution settings", () => {
  const artifact = makeRuntimeArtifact(model, syntheticIdentity, RUNTIME_LIMITS, checkRuntimeObservation(model, fixture()));
  assert.deepEqual(validateRuntimeArtifact(JSON.parse(JSON.stringify(artifact))), artifact);
  for (const changed of [
    { ...artifact, source: artifact.source + "// arbitrary source" }, { ...artifact, schemaVersion: "nightshade-owned-runtime-case-1" },
    { ...artifact, identity: { ...artifact.identity, compilerSha256: "unknown" } },
    { ...artifact, limits: { ...artifact.limits, heapMiB: 512 } }, { ...artifact, extra: true },
  ]) assert.throws(() => validateRuntimeArtifact(changed));
  for (const limits of [{ timeoutMs: 1 }, { ...RUNTIME_LIMITS, maxOutputBytes: 1048577 }, { ...RUNTIME_LIMITS, timeoutMs: 0 }, { ...RUNTIME_LIMITS, heapMiB: undefined }]) assert.throws(() => validateRuntimeLimits(limits));
  const hiddenIdentity = structuredClone(artifact);
  Object.defineProperty(hiddenIdentity.identity, "compilerSha256", { value: "invalid", enumerable: false });
  assert.throws(() => validateRuntimeArtifact(hiddenIdentity), /hidden field/);
  const hiddenLimit = { ...RUNTIME_LIMITS };
  Object.defineProperty(hiddenLimit, "timeoutMs", { value: 1, enumerable: false });
  assert.throws(() => validateRuntimeLimits(hiddenLimit), /hidden field/);
  assert.deepEqual(runtimeIdentityChanges(syntheticIdentity, { ...syntheticIdentity, node: "v22.23.3" }), ["node"]);
  const result = artifact.result;
  const reordered = fixture();
  reordered.executions.reverse();
  assert.equal(compareRuntimeResults(result, checkRuntimeObservation(model, reordered)).sameObservation, true);
  reordered.compiledJavaScriptSha256 = "b".repeat(64);
  assert.equal(compareRuntimeResults(result, checkRuntimeObservation(model, reordered)).sameCompiledJavaScript, false);
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned compiler alongside runtime");
  assert.ok(process.env.COMPACT_RUNTIME_TEST);
  return { compiler: resolve(process.env.COMPACTC_TEST), runtime: resolve(process.env.COMPACT_RUNTIME_TEST) };
}
function cli(args: string[]) {
  return spawnSync(process.execPath, [resolve("dist/tests/generative/runtime-smoke.js"), ...args], { encoding: "utf8", timeout: 90000, maxBuffer: 1024 * 1024 });
}

test("[timing] actual runtime artifacts replay exactly; identity drift requires an explicit recorded comparison", qualified, async () => {
  const { compiler, runtime } = inputs();
  const result = await runRuntimeCaseIsolated(model, compiler, runtime);
  assert.equal(result.status, "passed", result.message);
  const identity = runtimeBuildIdentity(compiler, runtime);
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-runtime-replay-test-"));
  try {
    const artifact = makeRuntimeArtifact(model, identity, RUNTIME_LIMITS, result);
    const path = resolve(directory, "case.json");
    writeFileSync(path, JSON.stringify(artifact));
    const output = resolve(directory, "replay");
    const replay = cli(["--output", output, "--replay", path]);
    assert.equal(replay.status, 0, replay.stderr || replay.stdout);
    const summary = JSON.parse(readFileSync(resolve(output, "summary.json"), "utf8"));
    assert.equal(summary.replay.matched, true);
    assert.equal(summary.replay.sameObservation, true);
    assert.equal(summary.replay.sameCompiledJavaScript, true);
    assert.equal(summary.replay.previousArtifactSha256, digest(readFileSync(path)));
    assert.deepEqual(summary.limits, RUNTIME_LIMITS);
    assert.equal(cli(["--output", output, "--replay", path]).status, 2, "cannot overwrite evidence");
    artifact.identity.node = "v0.0.0"; // Synthetic identity drift only; underlying observations remain measured.
    writeFileSync(path, JSON.stringify(artifact));
    const refused = resolve(directory, "refused");
    const refusal = cli(["--output", refused, "--replay", path]);
    assert.equal(refusal.status, 2);
    assert.match(refusal.stderr, /identity mismatch/);
    assert.equal(existsSync(refused), false);
    const compared = resolve(directory, "compared");
    assert.equal(cli(["--output", compared, "--replay", path, "--compare-build"]).status, 0);
    const comparison = JSON.parse(readFileSync(resolve(compared, "summary.json"), "utf8")).replay;
    assert.equal(comparison.comparison, true);
    assert.deepEqual(comparison.changedIdentityFields, ["node"]);
    assert.equal(comparison.sameObservation, true);
    artifact.identity = identity;
    artifact.result.observation!.compiledJavaScriptSha256 = "f".repeat(64);
    artifact.result.feedback!.compiledJavaScriptSha256 = "f".repeat(64);
    writeFileSync(path, JSON.stringify(artifact));
    const drift = resolve(directory, "compiled-drift");
    assert.equal(cli(["--output", drift, "--replay", path]).status, 2);
    const driftSummary = JSON.parse(readFileSync(resolve(drift, "summary.json"), "utf8"));
    assert.equal(driftSummary.replay.sameObservation, true);
    assert.equal(driftSummary.replay.sameCompiledJavaScript, false);
    assert.equal(driftSummary.replay.matched, false);
    artifact.limits.timeoutMs = 1;
    artifact.result = { status: "incomplete", category: "worker-timeout", signature: "worker-timeout", message: "Synthetic timeout expectation; replay must actually time out" };
    writeFileSync(path, JSON.stringify(artifact));
    const timeout = resolve(directory, "timeout");
    assert.equal(cli(["--output", timeout, "--replay", path]).status, 2);
    const timed = JSON.parse(readFileSync(resolve(timeout, "summary.json"), "utf8"));
    assert.deepEqual(timed.counts, { passed: 0, failed: 0, incomplete: 1 });
    assert.equal(timed.rows[0].category, "worker-timeout");
    assert.equal(timed.limits.timeoutMs, 1);
    assert.equal(timed.corpus.entries.length, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("runtime reduction recompiles candidates and preserves deliberately injected observation property corruption", qualified, async () => {
  const { compiler, runtime } = inputs();
  const evaluate = async (input: GeneratedCase) => {
    const measured = await runRuntimeCaseIsolated(input, compiler, runtime);
    assert.equal(measured.status, "passed", measured.message);
    const wire = structuredClone(measured.observation!);
    const index = input.operations.findIndex(operation => operation.kind === "write" && operation.value > 0);
    if (index >= 0) {
      // Test-only postmeasurement fault injection, not a discovered runtime bug.
      const rows = wire.executions[0].result as { kind: "integer"; value: string }[][];
      rows[index][0].value = String(BigInt(rows[index][0].value) + 1n);
    }
    return checkRuntimeObservation(input, wire);
  };
  const initial = await evaluate(model);
  assert.equal(initial.status, "failed");
  const reduced = await reduceRuntimeCase(model, initial, evaluate, 16);
  assert.equal(reduced.interrupted, false);
  assert.equal(reduced.exhausted, false);
  assert.deepEqual(reduced.case.operations, [{ kind: "write", value: 1 }]);
  assert.equal(reduced.result.signature, initial.signature);
  assert.equal(reduced.attempts.length, reduced.checks);
  assert.ok(reduced.attempts.some(attempt => attempt.result.status === "passed" && !attempt.preserved));
  for (const attempt of reduced.attempts) assert.ok(attempt.result.observation, "each candidate was compiled and measured");
});
