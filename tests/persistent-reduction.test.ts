import assert from "node:assert/strict";
import test from "node:test";
import { checkPersistentResponse, incompletePersistentResult, runPersistentSequenceIsolated, validatePersistentResult, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";
import { reducePersistentSequence, type PersistentEvaluationContext, type PersistentReductionOptions } from "./generative/persistent-reduction.js";

const sequence = (operations: PersistentOperation[]) => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 17, operations });
const input = sequence([{ kind: "inspect" }, { kind: "accept" }, { kind: "save", slot: 3 }, { kind: "accept" }, { kind: "restore", slot: 3 }, { kind: "reject" }, { kind: "inspect" }]);

/** Schema-only fixture: this does not claim that a runtime executed. */
function fixture(input: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(input);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic count:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(input)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const check = (input: PersistentSequence, wire: PersistentObservation) => checkPersistentObservation(input, wire, PERSISTENT_SOURCE_SHA256);
function rowFailure(input: PersistentSequence, index = input.operations.findIndex(op => op.kind === "reject"), field: "next" | "count" = "next") {
  const wire = fixture(input);
  if (index >= 0) wire.rows[index].after[field] = String(BigInt(wire.rows[index].after[field]) + 1n);
  return check(input, wire);
}
function globalFailure(input: PersistentSequence) {
  const wire = fixture(input); wire.final.count = String(BigInt(wire.final.count) + 1n);
  return check(input, wire);
}
/** Deliberate test fault after a restore to a nonzero historical snapshot. */
function restoreFault(input: PersistentSequence, wire = fixture(input)) {
  const index = wire.rows.findIndex((row, index) => row.operation === "reject" && wire.rows.slice(0, index).some(previous => previous.operation === "restore" && previous.before.count !== previous.after.count && previous.after.count !== "0"));
  if (index >= 0) wire.rows[index].after.next = String(BigInt(wire.rows[index].after.next) + 1n);
  return check(input, wire);
}

test("persistent reduction keeps the original failing call across deletion and reduces slot names together", async () => {
  const original = structuredClone(input);
  const initial = restoreFault(input);
  const observed: PersistentSequence[] = [];
  const evaluate = async (candidate: PersistentSequence, context: PersistentEvaluationContext) => {
    assert.ok(context.timeoutMs >= 1 && context.timeoutMs <= 60000);
    assert.equal(context.signal.aborted, false);
    observed.push(structuredClone(candidate));
    return restoreFault(candidate);
  };
  const reduced = await reducePersistentSequence(input, initial, evaluate, { maxChecks: 128 });
  assert.equal(reduced.status, "complete"); assert.deepEqual(reduced.diagnostics, []);
  assert.deepEqual(reduced.sequence.operations, [{ kind: "accept" }, { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 0 }, { kind: "reject" }]);
  assert.deepEqual(reduced.originalRows, [1, 2, 3, 4, 5]);
  assert.equal(reduced.sequence.seed, 17);
  assert.equal(reduced.reductionSignature, "persistent-reduction-property-1|original-row:5|operation:reject|field:after.next");
  assert.equal(initial.signature, "persistent-model|row:5|operation:reject|field:after.next");
  assert.equal(reduced.result.signature, "persistent-model|row:4|operation:reject|field:after.next");
  assert.equal(reduced.changed, true); assert.equal(reduced.checks, reduced.attempts.length);
  assert.deepEqual(reduced.attempts.map(attempt => attempt.sequence), observed);
  assert.ok(reduced.attempts.some(attempt => attempt.preserved)); assert.ok(reduced.attempts.some(attempt => !attempt.preserved));
  for (const attempt of reduced.attempts) {
    assert.deepEqual(validatePersistentSequence(attempt.sequence), attempt.sequence);
    assert.deepEqual(validatePersistentResult(attempt.sequence, attempt.result), attempt.result);
    assert.equal(attempt.preserved, attempt.reductionSignature === reduced.reductionSignature);
    assert.equal(attempt.originalRows.length, attempt.sequence.operations.length);
  }
  assert.deepEqual(reduced.result, restoreFault(reduced.sequence));
  assert.deepEqual(input, original);
  assert.deepEqual(await reducePersistentSequence(input, initial, evaluate, { maxChecks: 128 }), reduced, "schedule is deterministic, with no timing data in the result");
});

test("persistent reduction cannot switch between repeated calls with the same operation and property", async () => {
  const repeated = sequence([{ kind: "inspect" }, { kind: "inspect" }, { kind: "reject" }, { kind: "reject" }]);
  const reduced = await reducePersistentSequence(repeated, rowFailure(repeated, 3), async candidate => rowFailure(candidate));
  assert.equal(reduced.status, "complete");
  assert.deepEqual(reduced.sequence.operations, [{ kind: "reject" }]);
  assert.deepEqual(reduced.originalRows, [3]);
  assert.ok(reduced.attempts.some(attempt => attempt.reason === "different-property" && attempt.result.status === "failed"));
  assert.ok(reduced.attempts.every(attempt => attempt.originalRows.includes(3)), "the anchored call is never deleted");
});

test("persistent slot simplification is an injective global rename and preserves save/restore associations", async () => {
  const slots = sequence([{ kind: "save", slot: 3 }, { kind: "restore", slot: 3 }, { kind: "save", slot: 1 }, { kind: "restore", slot: 1 }, { kind: "reject" }]);
  const reduced = await reducePersistentSequence(slots, rowFailure(slots), async candidate => {
    if (candidate.operations.length !== slots.operations.length) return check(candidate, fixture(candidate));
    const values = candidate.operations.flatMap(operation => "slot" in operation ? [operation.slot] : []);
    assert.equal(values[0], values[1]); assert.equal(values[2], values[3]); assert.notEqual(values[0], values[2]);
    return rowFailure(candidate);
  });
  assert.equal(reduced.status, "complete");
  assert.deepEqual(reduced.sequence.operations, [{ kind: "save", slot: 1 }, { kind: "restore", slot: 1 }, { kind: "save", slot: 0 }, { kind: "restore", slot: 0 }, { kind: "reject" }]);
  assert.deepEqual(reduced.originalRows, [0, 1, 2, 3, 4]);
  const all = sequence([{ kind: "restore", slot: 0 }, { kind: "restore", slot: 1 }, { kind: "restore", slot: 2 }, { kind: "restore", slot: 3 }, { kind: "reject" }]);
  const unchanged = await reducePersistentSequence(all, rowFailure(all), async candidate => check(candidate, fixture(candidate)));
  assert.equal(unchanged.status, "complete");
  assert.ok(unchanged.attempts.every(attempt => attempt.sequence.operations.length < all.operations.length), "no renaming merges two used slots");
});

test("persistent reduction refuses non-failures, forged or stale original evidence and invalid options", async () => {
  const initial = restoreFault(input);
  for (const invalid of [check(input, fixture(input)), incompletePersistentResult("worker-timeout", "synthetic timeout"), { ...initial, signature: "invented" }, { ...initial, message: "invented" }, rowFailure(sequence([{ kind: "reject" }]))]) {
    await assert.rejects(() => reducePersistentSequence(input, invalid as PersistentResult, async () => assert.fail("invalid evidence must not evaluate")));
  }
  await assert.rejects(() => reducePersistentSequence({ ...input, source: "arbitrary" } as never, initial, async () => assert.fail("invalid sequence must not evaluate")));
  for (const options of [{ maxChecks: 0 }, { maxChecks: 257 }, { maxChecks: NaN }, { maxChecks: undefined }, { maxChecks: null }, { maxChecks: 1.5 }, { maxElapsedMs: 0 }, { maxElapsedMs: 60001 }, { maxElapsedMs: Infinity }, { extra: true }, { signal: {} }]) {
    await assert.rejects(() => reducePersistentSequence(input, initial, async () => assert.fail("invalid options must not evaluate"), options as PersistentReductionOptions));
  }
  const accessor = {};
  Object.defineProperty(accessor, "maxChecks", { enumerable: true, get() { assert.fail("must not invoke options getter"); } });
  await assert.rejects(() => reducePersistentSequence(input, initial, async () => initial, accessor));
});

test("incomplete evaluations, different properties, malformed responses and stale labels never replace the original failure", async () => {
  const many = sequence([...Array.from({ length: 15 }, () => ({ kind: "inspect" as const })), { kind: "reject" }]);
  const initial = rowFailure(many);
  const callbacks: ((candidate: PersistentSequence) => unknown)[] = [
    candidate => check(candidate, fixture(candidate)),
    candidate => rowFailure(candidate, candidate.operations.length - 1, "count"),
    () => incompletePersistentResult("worker-timeout", "synthetic timeout"),
    () => incompletePersistentResult("worker-failed", "synthetic infrastructure failure"),
    candidate => checkPersistentResponse(candidate, "malformed", ""),
    () => initial,
    candidate => ({ ...check(candidate, fixture(candidate)), status: "failed", signature: initial.signature }),
    () => { throw new Error("synthetic evaluator exception"); },
    () => undefined,
    candidate => { const wire = fixture(candidate); wire.compiledJavaScriptSha256 = "f".repeat(64); return rowFailureFromWire(candidate, wire); },
  ];
  function rowFailureFromWire(candidate: PersistentSequence, wire: PersistentObservation) { wire.rows.at(-1)!.after.next = "99"; return check(candidate, wire); }
  let calls = 0;
  const reduced = await reducePersistentSequence(many, initial, async candidate => callbacks[calls++](candidate), { maxChecks: callbacks.length });
  assert.equal(reduced.status, "incomplete"); assert.equal(reduced.checks, callbacks.length);
  assert.deepEqual(reduced.diagnostics, ["persistent-reduction-check-budget", "persistent-reduction-evaluation-incomplete", "persistent-reduction-build-drift"]);
  assert.deepEqual(reduced.sequence, many); assert.deepEqual(reduced.result, initial); assert.equal(reduced.changed, false);
  assert.ok(reduced.attempts.every(attempt => !attempt.preserved));
  assert.equal(reduced.attempts[1].reason, "different-property"); assert.equal(reduced.attempts[2].result.diagnostic, "worker-timeout");
  assert.equal(reduced.attempts[4].result.diagnosticResponse?.stdout.prefix, "malformed");
  assert.equal(reduced.attempts.at(-1)!.reason, "compiled-build-drift");
  for (const attempt of reduced.attempts) assert.deepEqual(validatePersistentResult(attempt.sequence, attempt.result), attempt.result);
});

test("check exhaustion retains the last accepted failure and finite local completion does not invent exhaustion", async () => {
  const many = sequence([...Array.from({ length: 12 }, () => ({ kind: "inspect" as const })), { kind: "reject" }]);
  const reduced = await reducePersistentSequence(many, rowFailure(many), async candidate => rowFailure(candidate), { maxChecks: 1 });
  assert.equal(reduced.status, "incomplete"); assert.deepEqual(reduced.diagnostics, ["persistent-reduction-check-budget"]);
  assert.equal(reduced.checks, 1); assert.equal(reduced.changed, true);
  assert.ok(reduced.sequence.operations.length < many.operations.length);
  assert.deepEqual(reduced.result, reduced.attempts[0].result); assert.deepEqual(validatePersistentResult(reduced.sequence, reduced.result), reduced.result);
  const single = sequence([{ kind: "reject" }]);
  const anchored = await reducePersistentSequence(single, rowFailure(single), async () => assert.fail("only call cannot be deleted"), { maxChecks: 1 });
  assert.equal(anchored.status, "complete"); assert.equal(anchored.checks, 0);
  const emptied = await reducePersistentSequence(single, globalFailure(single), async candidate => globalFailure(candidate), { maxChecks: 1 });
  assert.equal(emptied.status, "complete"); assert.deepEqual(emptied.sequence.operations, []); assert.equal(emptied.checks, 1);
  const empty = sequence([]);
  const done = await reducePersistentSequence(empty, globalFailure(empty), async () => assert.fail("no candidates"));
  assert.equal(done.status, "complete"); assert.equal(done.checks, 0);
  const refused = await reducePersistentSequence(single, globalFailure(single), async candidate => check(candidate, fixture(candidate)), { maxChecks: 1 });
  assert.equal(refused.status, "complete"); assert.equal(refused.changed, false);
});

test("an incomplete candidate remains visible after the finite search finishes", async () => {
  const single = sequence([{ kind: "inspect" }]);
  const reduced = await reducePersistentSequence(single, globalFailure(single), async () => incompletePersistentResult("worker-output-budget", "synthetic output exhaustion"));
  assert.equal(reduced.status, "incomplete"); assert.deepEqual(reduced.diagnostics, ["persistent-reduction-evaluation-incomplete"]);
  assert.equal(reduced.attempts[0].reason, "incomplete-evaluation"); assert.equal(reduced.changed, false);
});

test("[timing] overall time exhaustion aborts cooperatively, returns explicit incomplete and ignores late matching evidence", async () => {
  const controller = { signal: undefined as AbortSignal | undefined, finish: undefined as ((value: unknown) => void) | undefined };
  const initial = restoreFault(input);
  const reduced = await reducePersistentSequence(input, initial, (candidate, context) => {
    controller.signal = context.signal;
    return new Promise(resolve => { controller.finish = () => resolve(restoreFault(candidate)); });
  }, { maxElapsedMs: 20 });
  assert.equal(reduced.status, "incomplete"); assert.ok(reduced.diagnostics.includes("persistent-reduction-time-budget"));
  assert.equal(controller.signal!.aborted, true); assert.equal(reduced.checks, 1);
  assert.equal(reduced.attempts[0].reason, "time-budget"); assert.equal(reduced.attempts[0].result.diagnostic, "worker-timeout");
  assert.deepEqual(reduced.sequence, input); assert.deepEqual(reduced.result, initial);
  const saved = structuredClone(reduced);
  controller.finish!(undefined);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(reduced, saved);
});

test("external or worker interruption cannot accept a late property match", async () => {
  const initial = restoreFault(input);
  const before = new AbortController(); before.abort();
  const cancelled = await reducePersistentSequence(input, initial, async () => assert.fail("pre-cancelled evaluation"), { signal: before.signal });
  assert.equal(cancelled.status, "incomplete"); assert.deepEqual(cancelled.diagnostics, ["persistent-reduction-interrupted"]); assert.equal(cancelled.checks, 0);
  const during = new AbortController();
  const late = await reducePersistentSequence(input, initial, async candidate => { during.abort(); return restoreFault(candidate); }, { signal: during.signal });
  assert.equal(late.status, "incomplete"); assert.equal(late.attempts[0].preserved, false); assert.equal(late.attempts[0].reason, "interrupted"); assert.deepEqual(late.result, initial);
  const worker = await reducePersistentSequence(input, initial, async () => incompletePersistentResult("worker-interrupted", "synthetic interruption"));
  assert.equal(worker.checks, 1); assert.ok(worker.diagnostics.includes("persistent-reduction-interrupted")); assert.equal(worker.attempts[0].preserved, false);
});

test("candidate/result mutation and unreadable exceptions cannot alter accepted evidence or its audit history", async () => {
  const single = sequence([{ kind: "inspect" }]);
  const initial = globalFailure(single);
  let supplied: PersistentResult | undefined;
  let suppliedSequence: PersistentSequence | undefined;
  const reduced = await reducePersistentSequence(single, initial, async candidate => {
    suppliedSequence = candidate; supplied = globalFailure(candidate);
    candidate.operations.push({ kind: "accept" });
    initial.signature = "mutated initial";
    return supplied;
  });
  const copy = structuredClone(reduced);
  suppliedSequence!.operations.length = 0;
  if (supplied!.status !== "incomplete") supplied!.observation.rows.length = 0;
  supplied!.signature = "mutated evaluator result";
  assert.deepEqual(reduced, copy);
  reduced.attempts[0].result.signature = "mutated attempt";
  assert.notEqual(reduced.result.signature, reduced.attempts[0].result.signature);
  for (const error of [new Error(""), new Error("x".repeat(8000)), { toString() { throw new Error("unreadable"); } }]) {
    const failed = await reducePersistentSequence(single, globalFailure(single), async () => { throw error; });
    const attempt = failed.attempts[0];
    assert.equal(failed.status, "incomplete"); assert.equal(attempt.result.status, "incomplete");
    if (attempt.result.status === "incomplete") assert.ok(attempt.result.message.length > 0 && attempt.result.message.length <= 4000);
    assert.deepEqual(validatePersistentResult(attempt.sequence, attempt.result), attempt.result);
  }
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
test("[timing] compiled persistent candidates reproduce a deliberately injected restore failure and retain actual evaluation evidence", qualified, async () => {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned compiler alongside runtime");
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!;
  const evaluate = async (candidate: PersistentSequence, context?: PersistentEvaluationContext) => {
    const measured = await runPersistentSequenceIsolated(candidate, compiler, runtime, { ...PERSISTENT_LIMITS, timeoutMs: context?.timeoutMs ?? PERSISTENT_LIMITS.timeoutMs });
    assert.equal(measured.status, "passed", JSON.stringify(measured));
    if (measured.status !== "passed") throw new Error("Expected actual fixed-fixture measurement");
    // Postmeasurement fault injection is a test, not a discovered runtime bug.
    return restoreFault(candidate, structuredClone(measured.observation));
  };
  const initial = await evaluate(input);
  const reduced = await reducePersistentSequence(input, initial, evaluate, { maxChecks: 128 });
  assert.equal(reduced.status, "complete", JSON.stringify(reduced.diagnostics));
  assert.deepEqual(reduced.sequence.operations, [{ kind: "accept" }, { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 0 }, { kind: "reject" }]);
  assert.equal(reduced.result.status, "failed");
  assert.ok(reduced.attempts.every(attempt => attempt.result.status !== "incomplete"));
  assert.ok(reduced.attempts.some(attempt => attempt.result.status === "passed"));
  for (const attempt of reduced.attempts) {
    assert.deepEqual(validatePersistentResult(attempt.sequence, attempt.result), attempt.result);
    if (attempt.result.status !== "incomplete") assert.equal(attempt.result.observation.sequenceSha256, persistentDigest(JSON.stringify(attempt.sequence)));
  }
  const exhausted = await reducePersistentSequence(input, initial, candidate => runPersistentSequenceIsolated(candidate, compiler, runtime, { ...PERSISTENT_LIMITS, timeoutMs: 1 }), { maxChecks: 1 });
  assert.equal(exhausted.status, "incomplete"); assert.equal(exhausted.attempts[0].result.diagnostic, "worker-timeout");
  assert.deepEqual(exhausted.sequence, input); assert.deepEqual(exhausted.result, initial);
});
