import test from "node:test";
import assert from "node:assert/strict";
import { checkCase } from "./generative/check.js";
import { buildIdentity, makeArtifact, validateArtifact } from "./generative/artifacts.js";
import { generateCase, validateCase } from "./generative/model.js";
import { reduceCase } from "./generative/reduce.js";
import { runCaseIsolated } from "./generative/campaign.js";
import { effectiveBudgets } from "./generative/budgets.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };

test("generated checks require compiler evidence instead of reporting unqualified success", () => {
  assert.equal(checkCase(generateCase(1, 4), {}).status, "unqualified");
  assert.throws(() => checkCase(generateCase(1, 4), { maxSteps: NaN }));
});

test("typed reduction preserves an actual predicate and decreases operands as well as length", async () => {
  const input = validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 1, operations: [
    { kind: "read", key: 3 }, { kind: "write", value: 255 }, { kind: "snapshot" }, { kind: "write", value: 8 }, { kind: "read", key: 0 },
  ] });
  const predicate = async (candidate: typeof input) => {
    const snapshot = candidate.operations.findIndex(operation => operation.kind === "snapshot");
    return snapshot >= 0 && candidate.operations.slice(snapshot + 1).some(operation => operation.kind === "write" && operation.value > 0);
  };
  const first = await reduceCase(input, predicate);
  assert.ok(await predicate(first.case));
  assert.deepEqual(first.case.operations, [{ kind: "snapshot" }, { kind: "write", value: 1 }]);
  assert.equal(first.exhausted, false);
  assert.equal(first.changed, true);
  assert.deepEqual(await reduceCase(input, predicate), first);
  assert.equal(input.operations.length, 5);
  assert.equal((await reduceCase(input, async () => false, 1)).exhausted, true);
  await assert.rejects(() => reduceCase(input, predicate, 0));
  let cancelled = false;
  let executed = 0;
  const interrupted = await reduceCase(input, async () => { executed++; cancelled = true; return false; }, 64, () => cancelled);
  assert.equal(interrupted.checks, executed);
  assert.equal(executed, 1);
  assert.equal(interrupted.interrupted, true);
  assert.equal(interrupted.exhausted, false);
});

test("generated replay budgets are explicit and independent of analyzer defaults", () => {
  assert.deepEqual(effectiveBudgets(), { maxSteps: 20000, maxPaths: 256, maxValues: 50000 });
  assert.deepEqual(effectiveBudgets({ maxPaths: 4 }), { maxSteps: 20000, maxPaths: 4, maxValues: 50000 });
  assert.throws(() => effectiveBudgets({ maxPaths: Infinity }));
  assert.throws(() => effectiveBudgets({ maxPath: 1 } as never));
  assert.throws(() => effectiveBudgets({ constructor: 1 } as never));
});

test("compiler-valid generated samples exercise all engines/caches against independent concrete outcomes", qualified, () => {
  for (const [seed, steps] of [[0, 1], [42, 12], [4294967295, 32]]) {
    const result = checkCase(generateCase(seed, steps), { compiler: process.env.COMPACTC_TEST });
    assert.equal(result.status, "passed", JSON.stringify(result));
    assert.equal(result.compiler!.valid, true);
    assert.equal(result.modes.length, 4);
    assert.ok(result.modes.filter(mode => mode.cached).every(mode => mode.metrics.readSummaryHits > 0));
    assert.ok(result.modes.filter(mode => !mode.cached).every(mode => mode.metrics.summaryHits === 0));
  }
});

test("compiler-valid generated budget exhaustion stays incomplete", qualified, () => {
  for (const budget of [{ maxSteps: 1 }, { maxValues: 1 }]) {
    const result = checkCase(generateCase(42, 12), { compiler: process.env.COMPACTC_TEST, ...budget });
    assert.equal(result.status, "incomplete", JSON.stringify(result));
    assert.equal(result.category, "analysis-incomplete");
    assert.ok(result.modes.some(mode => mode.diagnosticCodes.length));
  }
});

test("[timing] isolated generated checks match direct observations and report process timeouts explicitly", qualified, async () => {
  const input = generateCase(42, 8);
  const options = { compiler: process.env.COMPACTC_TEST };
  const direct = checkCase(input, options);
  const isolated = await runCaseIsolated(input, options);
  assert.equal(isolated.status, "passed", JSON.stringify(isolated));
  assert.equal(isolated.observationSha256, direct.observationSha256);
  assert.deepEqual(isolated.modes, direct.modes);
  const timed = await runCaseIsolated(input, options, { timeoutMs: 1 });
  assert.equal(timed.status, "incomplete");
  assert.equal(timed.category, "worker-timeout");
});

test("replay artifacts bind generated source, options and executed toolchain identities", qualified, () => {
  const input = generateCase(42, 2);
  const result = checkCase(input, { compiler: process.env.COMPACTC_TEST });
  const identity = buildIdentity(process.env.COMPACTC_TEST!);
  const artifact = makeArtifact(input, identity, { maxPaths: 256 }, {}, result);
  assert.deepEqual(validateArtifact(JSON.parse(JSON.stringify(artifact))), JSON.parse(JSON.stringify(artifact)));
  assert.match(identity.parserRuntimeSha256, /^[a-f0-9]{64}$/);
  assert.notEqual(identity.compilerDistributionSha256, identity.compilerSha256);
  assert.throws(() => validateArtifact({ ...artifact, source: artifact.source + "\n" }), /integrity/);
  assert.throws(() => validateArtifact({ ...artifact, case: { ...input, source: "arbitrary source" } }), /fields/);
  assert.throws(() => validateArtifact({ ...artifact, limits: undefined }), /limits/);
  assert.throws(() => validateArtifact({ ...artifact, budgets: { maxPaths: 0 } }), /budget/);
  assert.throws(() => validateArtifact({ ...artifact, budgets: {} }), /budget/);
  assert.throws(() => validateArtifact({ ...artifact, identity: { ...identity, compilerSha256: "unverified" } }), /identity/);
  assert.throws(() => validateArtifact({ ...artifact, result: { status: "passed", category: "x", signature: "x", modes: [] } }), /qualification/);
  const duplicated = { ...result, modes: Array(4).fill(result.modes[0]) };
  assert.throws(() => validateArtifact({ ...artifact, result: duplicated }), /duplicate/);
  assert.throws(() => makeArtifact(input, identity, {}, {}, duplicated), /duplicate/);
  assert.throws(() => validateArtifact({ ...artifact, result: { ...result, compiler: { valid: true } } }), /compiler evidence/);
});
