import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { expectedFlagObservations, renderCase, validateCase, type GeneratedCase, type Operation } from "./generative/model.js";
import { checkRuntimeObservation, checkRuntimeResponse, incompleteRuntimeResult, validateRuntimeResult, type RuntimeCheckResult } from "./generative/runtime-artifacts.js";
import { reduceRuntimeCase } from "./generative/runtime-reduce.js";

const model = (operations: Operation[]): GeneratedCase => validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 17, operations });
const input = model([{ kind: "read", key: 3 }, { kind: "write", value: 255 }, { kind: "snapshot" }, { kind: "write", value: 8 }, { kind: "read", key: 0 }]);

/** Synthetic schema fixture only: no compiler or runtime execution is claimed. */
function schemaFixture(input: GeneratedCase) {
  return {
    layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0",
    runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: createHash("sha256").update(renderCase(input)).digest("hex"), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(checkpoint => checkpoint.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })),
  };
}

function syntheticResult(input: GeneratedCase, checkpoint = -1, column = 0): RuntimeCheckResult {
  const wire = schemaFixture(input);
  if (checkpoint >= 0) {
    const atom = wire.executions[0].result[checkpoint][column];
    atom.value = atom.kind === "boolean" ? String(atom.value !== "true") : String(BigInt(atom.value) + 1n);
  }
  return checkRuntimeObservation(input, wire);
}

function snapshotDisagreement(input: GeneratedCase): RuntimeCheckResult {
  const snapshot = input.operations.findIndex(operation => operation.kind === "snapshot");
  const checkpoint = snapshot < 0 ? -1 : input.operations.findIndex((operation, index) => index > snapshot && operation.kind === "write" && operation.value > 0);
  return syntheticResult(input, checkpoint);
}

test("synthetic runtime reduction preserves the checked property and records every accepted/rejected candidate", async () => {
  const original = structuredClone(input);
  const checked: GeneratedCase[] = [];
  const result = await reduceRuntimeCase(input, snapshotDisagreement(input), async candidate => {
    checked.push(structuredClone(candidate));
    return snapshotDisagreement(candidate);
  });
  assert.deepEqual(result.case.operations, [{ kind: "snapshot" }, { kind: "write", value: 1 }]);
  assert.equal(result.changed, true);
  assert.equal(result.exhausted, false);
  assert.equal(result.interrupted, false);
  assert.equal(result.checks, result.attempts.length);
  assert.deepEqual(result.attempts.map(attempt => attempt.model), checked);
  assert.ok(result.attempts.some(attempt => attempt.preserved));
  assert.ok(result.attempts.some(attempt => !attempt.preserved));
  for (const attempt of result.attempts) {
    assert.deepEqual(validateRuntimeResult(attempt.model, attempt.result), attempt.result);
    assert.equal(attempt.preserved, attempt.result.status === "failed" && attempt.result.signature === result.result.signature);
  }
  assert.deepEqual(result.result, snapshotDisagreement(result.case));
  assert.deepEqual(result.result, [...result.attempts].reverse().find(attempt => attempt.preserved)!.result);
  assert.deepEqual(input, original);
  assert.deepEqual(await reduceRuntimeCase(input, snapshotDisagreement(input), async candidate => snapshotDisagreement(candidate)), result);
});

test("synthetic runtime reduction requires validated original failure evidence before evaluating candidates", async () => {
  const failure = snapshotDisagreement(input);
  const candidates = [
    syntheticResult(input), incompleteRuntimeResult("worker-timeout", "Synthetic timeout"),
    { ...failure, category: "compiler-failed" }, { ...failure, signature: "invented" },
    { status: "failed", category: "runtime-model-disagreement", signature: failure.signature },
    syntheticResult(model([{ kind: "read", key: 0 }]), 0),
  ];
  for (const candidate of candidates) await assert.rejects(() => reduceRuntimeCase(input, candidate as RuntimeCheckResult, async () => assert.fail("Invalid original evidence must not start evaluation")));
  await assert.rejects(() => reduceRuntimeCase({ ...input, operations: [{ kind: "execute-source" }] } as never, failure, async () => assert.fail("Invalid model must not start evaluation")));
});

test("synthetic alternate failures, compiler/timeout outcomes and invalid protocol never replace original failure", async () => {
  const original = snapshotDisagreement(input);
  const callbacks: ((candidate: GeneratedCase) => unknown)[] = [
    candidate => syntheticResult(candidate),
    candidate => syntheticResult(candidate, 0, 4),
    () => incompleteRuntimeResult("worker-timeout", "Synthetic timeout"),
    () => incompleteRuntimeResult("worker-failed", "Synthetic compiler rejection"),
    candidate => checkRuntimeResponse(candidate, "malformed synthetic response", ""),
    () => original,
    candidate => ({ ...syntheticResult(candidate), status: "failed", category: original.category, signature: original.signature }),
    () => ({ status: "failed", category: original.category, signature: original.signature }),
    () => { throw new Error("Synthetic evaluator exception"); },
    () => undefined,
  ];
  let calls = 0;
  const result = await reduceRuntimeCase(input, original, async candidate => callbacks[calls++](candidate), callbacks.length);
  assert.equal(calls, callbacks.length);
  assert.equal(result.checks, callbacks.length);
  assert.equal(result.attempts.length, callbacks.length);
  assert.equal(result.exhausted, true);
  assert.equal(result.interrupted, false);
  assert.equal(result.changed, false);
  assert.deepEqual(result.case, input);
  assert.deepEqual(result.result, original);
  assert.ok(result.attempts.every(attempt => !attempt.preserved));
  assert.equal(result.attempts[1].result.status, "failed");
  assert.notEqual(result.attempts[1].result.signature, original.signature);
  assert.equal(result.attempts[2].result.category, "worker-timeout");
  assert.equal(result.attempts[3].result.category, "worker-failed");
  assert.ok(result.attempts[4].result.diagnosticResponse, "Bounded protocol response evidence is retained");
  for (const attempt of result.attempts.slice(5)) assert.equal(attempt.result.category, "runtime-protocol");
  for (const attempt of result.attempts) assert.deepEqual(validateRuntimeResult(attempt.model, attempt.result), attempt.result);
});

test("synthetic runtime reduction validates and explicitly enforces its smaller candidate budget", async () => {
  for (const budget of [0, -1, 1.5, NaN, Infinity, 257]) await assert.rejects(() => reduceRuntimeCase(input, snapshotDisagreement(input), async () => assert.fail("Invalid budget must not evaluate"), budget), /budget/);
  const large = model(Array.from({ length: 32 }, () => ({ kind: "write", value: 65535 })));
  const result = await reduceRuntimeCase(large, syntheticResult(large, 0), async candidate => syntheticResult(candidate));
  assert.equal(result.checks, 32);
  assert.equal(result.attempts.length, 32);
  assert.equal(result.exhausted, true);
  assert.equal(result.changed, false);
});

test("synthetic complete reductions and fully rejected finite candidates do not invent budget exhaustion", async () => {
  const single = model([{ kind: "read", key: 0 }]);
  const reduced = await reduceRuntimeCase(single, syntheticResult(single, 0), async candidate => syntheticResult(candidate, 0), 1);
  assert.deepEqual(reduced.case.operations, []);
  assert.equal(reduced.checks, 1);
  assert.equal(reduced.exhausted, false);
  assert.equal(reduced.changed, true);
  assert.deepEqual(reduced.result, syntheticResult(reduced.case, 0));
  const rejected = await reduceRuntimeCase(single, syntheticResult(single, 0), async candidate => syntheticResult(candidate));
  assert.equal(rejected.checks, 1);
  assert.equal(rejected.exhausted, false);
  assert.equal(rejected.changed, false);
  const empty = model([]);
  const finished = await reduceRuntimeCase(empty, syntheticResult(empty, 0), async () => assert.fail("Empty models have no shrink candidates"));
  assert.deepEqual(finished.case, empty);
  assert.deepEqual(finished.attempts, []);
  assert.equal(finished.exhausted, false);
});

test("synthetic exhaustion after partial reduction returns the accepted model and its matching evidence", async () => {
  const partial = model([{ kind: "snapshot" }, { kind: "write", value: 8 }]);
  const initial = snapshotDisagreement(partial);
  const result = await reduceRuntimeCase(partial, initial, async candidate => snapshotDisagreement(candidate), 5);
  assert.equal(result.checks, 5);
  assert.equal(result.exhausted, true);
  assert.equal(result.interrupted, false);
  assert.equal(result.changed, true);
  assert.deepEqual(result.case.operations, [{ kind: "snapshot" }, { kind: "write", value: 4 }]);
  assert.deepEqual(result.result, result.attempts[4].result);
  assert.equal(result.attempts[4].preserved, true);
  assert.deepEqual(result.result, snapshotDisagreement(result.case));
  assert.notEqual(result.result.observation!.generatedSourceSha256, initial.observation!.generatedSourceSha256);
});

test("synthetic cancellation before evaluation and during a matching failure stays explicit and rejects late acceptance", async () => {
  const single = model([{ kind: "read", key: 0 }]);
  const initial = syntheticResult(single, 0);
  const before = await reduceRuntimeCase(single, initial, async () => assert.fail("Cancelled reductions cannot evaluate"), 1, () => true);
  assert.equal(before.interrupted, true);
  assert.equal(before.exhausted, false);
  assert.equal(before.checks, 0);
  let cancelled = false;
  const during = await reduceRuntimeCase(single, initial, async candidate => {
    cancelled = true;
    return syntheticResult(candidate, 0);
  }, 1, () => cancelled);
  assert.equal(during.interrupted, true);
  assert.equal(during.exhausted, false);
  assert.equal(during.checks, 1);
  assert.equal(during.attempts[0].result.status, "failed");
  assert.equal(during.attempts[0].preserved, false);
  assert.deepEqual(during.result, initial);
  assert.deepEqual(during.case, single);
});

test("synthetic worker interruption stops immediately even without an external cancellation callback", async () => {
  let calls = 0;
  const initial = snapshotDisagreement(input);
  const result = await reduceRuntimeCase(input, initial, async () => {
    calls++;
    return incompleteRuntimeResult("worker-interrupted", "Synthetic interruption");
  }, 1);
  assert.equal(calls, 1);
  assert.equal(result.interrupted, true);
  assert.equal(result.exhausted, false);
  assert.equal(result.attempts[0].result.category, "worker-interrupted");
  assert.equal(result.attempts[0].preserved, false);
  assert.deepEqual(result.result, initial);
  assert.deepEqual(result.case, input);
});

test("synthetic candidate/result mutation cannot rewrite the reduction model or audit trail", async () => {
  const single = model([{ kind: "read", key: 0 }]);
  const initial = syntheticResult(single, 0);
  let suppliedModel: GeneratedCase | undefined;
  let suppliedResult: RuntimeCheckResult | undefined;
  const result = await reduceRuntimeCase(single, initial, async candidate => {
    suppliedModel = candidate;
    suppliedResult = syntheticResult(candidate, 0);
    candidate.operations.push({ kind: "write", value: 999 });
    initial.signature = "mutated input";
    return suppliedResult;
  });
  const before = structuredClone(result);
  suppliedModel!.operations.length = 0;
  suppliedResult!.observation!.executions.length = 0;
  suppliedResult!.signature = "mutated result";
  assert.deepEqual(result, before);
  assert.deepEqual(result.case.operations, []);
  assert.deepEqual(result.attempts[0].model.operations, []);
  assert.deepEqual(validateRuntimeResult(result.case, result.result), result.result);
  result.attempts[0].result.signature = "mutated audit snapshot";
  assert.notEqual(result.result.signature, result.attempts[0].result.signature);
});

test("synthetic thrown empty/large/unreadable errors produce bounded validated protocol records", async () => {
  for (const error of [new Error(""), new Error("x".repeat(8000)), { toString() { throw new Error("unreadable"); } }]) {
    const result = await reduceRuntimeCase(input, snapshotDisagreement(input), async () => { throw error; }, 1);
    const attempt = result.attempts[0];
    assert.equal(attempt.result.status, "incomplete");
    assert.equal(attempt.result.category, "runtime-protocol");
    assert.ok(attempt.result.message!.length > 0 && attempt.result.message!.length <= 4000);
    assert.deepEqual(validateRuntimeResult(attempt.model, attempt.result), attempt.result);
  }
});
