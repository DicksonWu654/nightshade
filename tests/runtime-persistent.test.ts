import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runNodeModule, WorkerFailure } from "../src/runtime/process.js";
import { checkPersistentObservation, expectedPersistentSequence, generatePersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_REJECTION, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";

const worker = fileURLToPath(new URL("./runtime-fixtures/persistent-worker.js", import.meta.url));
const sourceSha256 = persistentDigest(readFileSync("tests/runtime-fixtures/persistent.compact"));
const sequence = (operations: PersistentOperation[]): PersistentSequence => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 1, operations });
const lifecycle = sequence([
  { kind: "inspect" }, { kind: "restore", slot: 3 }, { kind: "reject" }, { kind: "accept" },
  { kind: "save", slot: 0 }, { kind: "reject" }, { kind: "accept" }, { kind: "save", slot: 1 },
  { kind: "restore", slot: 0 }, { kind: "reject" }, { kind: "accept" }, { kind: "inspect" },
  { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 0 },
  { kind: "restore", slot: 0 }, { kind: "restore", slot: 2 }, { kind: "accept" },
  { kind: "restore", slot: 1 }, { kind: "reject" }, { kind: "inspect" },
]);

/** Schema-only evidence synthesized from the model; never execution evidence. */
function schemaFixture(input: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(input);
  const snapshot = (state: { count: string; next: string }) => ({ ...state, publicSha256: persistentDigest(`synthetic public count:${state.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(input)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}

test("persistent schema bounds owned operations, copies inputs and never invokes accessors", () => {
  const original = structuredClone(lifecycle);
  const copied = validatePersistentSequence(original);
  original.operations.length = 0;
  assert.deepEqual(copied, lifecycle);
  for (const malformed of [
    null, [], { ...lifecycle, source: "arbitrary" }, { ...lifecycle, state: {} }, { ...lifecycle, adapter: "other" },
    { ...lifecycle, operations: [{ kind: "call", name: "accept" }] },
    { ...lifecycle, operations: [{ kind: "restore", slot: 4 }] }, { ...lifecycle, operations: [{ kind: "save", slot: -0 }] },
    { ...lifecycle, seed: -1 }, { ...lifecycle, seed: 0x100000000 }, { ...lifecycle, operations: Array(2) },
    { ...lifecycle, operations: Array.from({ length: 33 }, () => ({ kind: "accept" })) },
  ]) assert.throws(() => validatePersistentSequence(malformed));
  const accessor = { ...lifecycle };
  Object.defineProperty(accessor, "operations", { get() { assert.fail("sequence getter invoked"); } });
  assert.throws(() => validatePersistentSequence(accessor), /data field/);
  const hidden = { ...lifecycle };
  Object.defineProperty(hidden, "seed", { value: 1, enumerable: false });
  assert.throws(() => validatePersistentSequence(hidden), /data field/);
  assert.deepEqual(generatePersistentSequence(42), generatePersistentSequence(42));
  assert.equal(generatePersistentSequence(0xffffffff).operations.length, 32);
  const generated = [0, 1, 42, 0xffffffff].flatMap(seed => generatePersistentSequence(seed).operations);
  assert.deepEqual(new Set(generated.map(operation => operation.kind)), new Set(["accept", "reject", "inspect", "save", "restore"]));
  assert.deepEqual(new Set(generated.flatMap(operation => "slot" in operation ? [operation.slot] : [])), new Set([0, 1, 2, 3]));
  assert.deepEqual(validatePersistentSequence(sequence([{ kind: "restore", slot: 0 }])), sequence([{ kind: "restore", slot: 0 }]));
});

test("independent persistent oracle preserves rejected accepted-state and historical witness associations", () => {
  const input = sequence([{ kind: "accept" }, { kind: "save", slot: 1 }, { kind: "reject" }, { kind: "accept" }, { kind: "restore", slot: 1 }, { kind: "accept" }]);
  const expected = expectedPersistentSequence(input);
  assert.deepEqual(expected.rows.map(row => row.witnesses), [["7"], [], ["8"], ["8"], [], ["8"]]);
  assert.deepEqual(expected.rows[2].before, { count: "1", next: "8" });
  assert.deepEqual(expected.rows[2].after, expected.rows[2].before);
  assert.deepEqual(expected.rows[4].after, { count: "1", next: "8" });
  assert.deepEqual(expected.final, { count: "2", next: "9" });
  assert.equal(checkPersistentObservation(lifecycle, schemaFixture(lifecycle), sourceSha256).status, "passed");
  for (const input of [sequence([]), generatePersistentSequence(0xffffffff), sequence(Array.from({ length: 32 }, () => ({ kind: "accept" })))]) assert.equal(checkPersistentObservation(input, schemaFixture(input), sourceSha256).status, "passed");
});

function corruptions(input: PersistentSequence, wire: PersistentObservation): void {
  const index = (operation: PersistentOperation["kind"]) => input.operations.findIndex(op => op.kind === operation);
  const changes: ((value: PersistentObservation) => void)[] = [
    value => { value.rows[index("accept")].result = "99"; },
    value => { value.rows[index("reject")].outcome = "evaluation-success"; value.rows[index("reject")].error = null; },
    value => { value.rows[index("reject")].after.next = "99"; },
    value => { value.rows[index("reject")].after.count = "99"; },
    value => { value.rows[index("accept")].witnesses = ["99"]; },
    value => { value.rows[index("inspect")].witnesses = ["7"]; },
    value => { value.rows[index("restore")].after.next = "99"; },
    value => { value.rows[index("save")].slots[0].count = "99"; },
    value => { value.rows[index("reject")].after.publicSha256 = "b".repeat(64); },
    value => { value.rows[index("restore")].after.publicSha256 = "b".repeat(64); },
    value => { value.rows[index("save")].slots[0].publicSha256 = "b".repeat(64); },
    value => { value.final.publicSha256 = "b".repeat(64); },
    value => { value.rows[index("accept")].index = 0; },
  ];
  for (const change of changes) {
    const corrupted = structuredClone(wire);
    change(corrupted);
    assert.equal(checkPersistentObservation(input, corrupted, sourceSha256).status, "failed");
  }
}

test("schema-only result/state/witness/restoration corruption cannot pass the persistent oracle", () => corruptions(lifecycle, schemaFixture(lifecycle)));

test("missing, malformed, over-budget and unexpected rejection evidence remains explicitly incomplete", () => {
  const wire = schemaFixture(lifecycle);
  const tooMany = { ...lifecycle, operations: Array.from({ length: 33 }, () => ({ kind: "inspect" as const })) };
  assert.equal(checkPersistentObservation(tooMany, wire, sourceSha256).diagnostic, "persistent-sequence-budget");
  assert.equal(checkPersistentObservation(lifecycle, { ...wire, rows: Array(33).fill(wire.rows[0]) }, sourceSha256).diagnostic, "persistent-observation-budget");
  for (const malformed of [
    { ...wire, extra: true }, { ...wire, rows: [] }, { ...wire, rows: Array(2) },
    { ...wire, runtimeLockSha256: "b".repeat(64) }, { ...wire, sequenceSha256: "b".repeat(64) },
    { ...wire, sourceSha256: "b".repeat(64) }, { ...wire, compiledJavaScriptSha256: "unknown" },
    { ...wire, runtime: "0.19.104" }, { ...wire, layer: "proof-verified" },
  ]) assert.equal(checkPersistentObservation(lifecycle, malformed, sourceSha256).status, "incomplete");
  const accessor = structuredClone(wire);
  Object.defineProperty(accessor.rows[0].before, "next", { get() { assert.fail("nested getter invoked"); } });
  assert.equal(checkPersistentObservation(lifecycle, accessor, sourceSha256).status, "incomplete");
  for (const error of [{ name: "Error", message: PERSISTENT_REJECTION }, { name: "CompactError", message: "different failure" }]) {
    const bad = structuredClone(wire);
    bad.rows[2].error = error as never;
    assert.equal(checkPersistentObservation(lifecycle, bad, sourceSha256).diagnostic, "persistent-unqualified-rejection");
  }
  const checked = checkPersistentObservation(lifecycle, wire, sourceSha256);
  assert.equal(checked.status, "passed");
  if (checked.status === "passed") { wire.rows[0].slots.length = 0; assert.equal(checked.observation.rows[0].slots.length, 4); }
});

test("persistent adapter rejects invalid models before compiler/runtime access and uses supervisor budgets", async () => {
  await assert.rejects(runNodeModule(worker, { compiler: "/missing", runtimeDirectory: "/missing", sequence: { ...lifecycle, operations: [{ kind: "source", text: "arbitrary" }] } }, PERSISTENT_LIMITS), error => error instanceof WorkerFailure && error.code === "worker-failed" && error.message.includes("persistent-protocol"));
  await assert.rejects(runNodeModule(worker, { compiler: "/missing", runtimeDirectory: "/missing", sequence: { ...lifecycle, operations: Array.from({ length: 33 }, () => ({ kind: "inspect" })) } }, PERSISTENT_LIMITS), error => error instanceof WorkerFailure && error.message.includes("persistent-sequence-budget"));
  await assert.rejects(runNodeModule(worker, { metadata: "x".repeat(1048576) }, PERSISTENT_LIMITS), error => error instanceof WorkerFailure && error.code === "worker-input-budget");
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
async function measured(input: PersistentSequence) {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned COMPACTC_TEST alongside runtime");
  const output = await runNodeModule(worker, { compiler: process.env.COMPACTC_TEST, runtimeDirectory: process.env.COMPACT_RUNTIME_TEST, sequence: input }, PERSISTENT_LIMITS);
  assert.equal(output.stderr, "");
  const checked = checkPersistentObservation(input, JSON.parse(output.stdout), sourceSha256);
  assert.equal(checked.status, "passed", JSON.stringify(checked));
  if (checked.status !== "passed") throw new Error("Unreachable failed qualification");
  return checked.observation;
}

test("compiled persistent lifecycle restores public/private snapshots and rejects speculative advancement", qualified, async () => {
  const wire = await measured(lifecycle);
  assert.deepEqual(wire.rows.flatMap(row => row.witnesses), expectedPersistentSequence(lifecycle).rows.flatMap(row => row.witnesses));
  assert.deepEqual(wire.final.count, "2");
  assert.deepEqual(wire.final.next, "9");
  corruptions(lifecycle, wire);
});

test("compiled persistent boundary schedules include empty, repeated rejection, all accepts and deterministic generated sequences", qualified, async () => {
  const schedules = [sequence([]), sequence(Array.from({ length: 32 }, () => ({ kind: "accept" }))), sequence(Array.from({ length: 32 }, () => ({ kind: "reject" }))), ...[0, 1, 42, 0xffffffff].map(seed => generatePersistentSequence(seed))];
  for (const input of schedules) {
    const wire = await measured(input);
    assert.equal(wire.rows.length, input.operations.length);
    assert.equal(wire.final.next, expectedPersistentSequence(input).final.next);
  }
});

test("[timing] persistent runtime restoration lock mismatch is infrastructure, never expected rejection", qualified, async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-lock-test-"));
  try {
    writeFileSync(resolve(directory, "package-lock.json"), "{}\n");
    await assert.rejects(runNodeModule(worker, { compiler: "/must-not-run", runtimeDirectory: directory, sequence: lifecycle }, PERSISTENT_LIMITS), error => error instanceof WorkerFailure && error.code === "worker-failed" && error.message.includes("persistent-input-identity"));
    const timeout = runNodeModule(worker, { compiler: process.env.COMPACTC_TEST, runtimeDirectory: process.env.COMPACT_RUNTIME_TEST, sequence: lifecycle }, { ...PERSISTENT_LIMITS, timeoutMs: 1 });
    await assert.rejects(timeout, error => error instanceof WorkerFailure && error.code === "worker-timeout");
    await assert.rejects(runNodeModule(worker, { compiler: process.env.COMPACTC_TEST, runtimeDirectory: process.env.COMPACT_RUNTIME_TEST, sequence: lifecycle }, { ...PERSISTENT_LIMITS, maxOutputBytes: 1024 }), error => error instanceof WorkerFailure && error.code === "worker-output-budget");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
