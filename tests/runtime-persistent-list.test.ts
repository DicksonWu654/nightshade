import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runNodeModule } from "../src/runtime/process.js";
import { checkPersistentListResponse, runPersistentListSequenceIsolated, validatePersistentListLimits } from "./generative/persistent-list-runtime.js";
import { checkPersistentListObservation, generatePersistentListSequence, PERSISTENT_LIST_LIMITS, PERSISTENT_LIST_LOCK_SHA256, PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_REJECTION, PERSISTENT_LIST_SOURCE_SHA256, persistentListDigest, validatePersistentListResult, validatePersistentListSequence, type PersistentListObservation, type PersistentListOperation, type PersistentListSequence, type PersistentListSnapshot } from "./generative/persistent-list-model.js";

const worker = fileURLToPath(new URL("./runtime-fixtures/persistent-list-worker.js", import.meta.url));
const sequence = (operations: PersistentListOperation[], seed = 1): PersistentListSequence => validatePersistentListSequence({ schemaVersion: "nightshade-persistent-list-sequence-1", seed, operations });
const state = (values: string[]) => ({ values, length: String(values.length), empty: values.length === 0, head: { is_some: values.length > 0, value: values[0] ?? "0" }, next: "7" });
const plain = ({ publicSha256: _hash, ...value }: PersistentListSnapshot) => value;
const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() {
  assert.ok(process.env.COMPACT_RUNTIME_TEST); assert.ok(process.env.COMPACTC_TEST, "Pinned COMPACT_RUNTIME_TEST requires COMPACTC_TEST");
  return { compiler: process.env.COMPACTC_TEST, runtime: process.env.COMPACT_RUNTIME_TEST };
}
async function measured(input: PersistentListSequence): Promise<PersistentListObservation> {
  const { compiler, runtime } = inputs();
  const checked = await runPersistentListSequenceIsolated(input, compiler, runtime);
  assert.equal(checked.status, "passed", JSON.stringify(checked));
  if (checked.status !== "passed") throw new Error("Fixed List runtime qualification failed");
  assert.deepEqual(validatePersistentListResult(input, checked), checked);
  return checked.observation;
}

test("persistent List uses the unchanged independently pinned guarded fixture and runtime inputs", () => {
  assert.equal(persistentListDigest(readFileSync("tests/runtime-fixtures/list-guarded.compact")), PERSISTENT_LIST_SOURCE_SHA256);
  assert.equal(persistentListDigest(readFileSync("tests/runtime-fixtures/runtime-inputs.json")), PERSISTENT_LIST_MANIFEST_SHA256);
  assert.equal(persistentListDigest(readFileSync("tests/runtime-fixtures/qualification-inputs/package-lock.json")), PERSISTENT_LIST_LOCK_SHA256);
});

test("runner refuses hostile grammar and limits before touching unavailable external inputs", async () => {
  const empty = sequence([]);
  for (const input of [
    { ...empty, source: "arbitrary" }, { ...empty, state: {} }, { ...empty, adapter: "arbitrary" },
    ...[-1, 256, -0, 0.5, NaN].map(value => ({ ...empty, operations: [{ kind: "push", value }] })),
    { ...empty, operations: [{ kind: "restore", slot: 4 }] }, { ...empty, operations: Array(2) },
    { ...empty, operations: Array.from({ length: 33 }, () => ({ kind: "inspect" })) },
  ]) {
    const checked = await runPersistentListSequenceIsolated(input as PersistentListSequence, "/must-not-read/compiler", "/must-not-read/runtime");
    assert.equal(checked.status, "incomplete"); assert.match(checked.diagnostic, /^persistent-list-(protocol|sequence-budget)$/);
  }
  let calls = 0;
  const accessor = { ...empty }; Object.defineProperty(accessor, "operations", { enumerable: true, get() { calls++; return []; } });
  assert.equal((await runPersistentListSequenceIsolated(accessor, "/must-not-read", "/must-not-read")).status, "incomplete");
  const badLimits = { ...PERSISTENT_LIST_LIMITS }; Object.defineProperty(badLimits, "timeoutMs", { enumerable: true, get() { calls++; return 1; } });
  await assert.rejects(() => runPersistentListSequenceIsolated(empty, "/must-not-read", "/must-not-read", badLimits));
  assert.equal(calls, 0);
  for (const limits of [{ ...PERSISTENT_LIST_LIMITS, timeoutMs: 60001 }, { ...PERSISTENT_LIST_LIMITS, heapMiB: 257 }, { ...PERSISTENT_LIST_LIMITS, maxOutputBytes: 1048577 }, { ...PERSISTENT_LIST_LIMITS, extra: 1 }]) assert.throws(() => validatePersistentListLimits(limits));
});

test("fixed worker request overrides are explicit protocol failures before compiler/runtime access", async () => {
  for (const [field, value] of Object.entries({ source: "arbitrary", initialState: {}, fixture: "other", adapter: "/not/accepted.js", savedCode: "arbitrary" })) {
    const output = await runNodeModule(worker, { compiler: "/must-not-read", runtimeDirectory: "/must-not-read", sequence: sequence([]), [field]: value }, { ...PERSISTENT_LIST_LIMITS, timeoutMs: 5000 });
    assert.equal(output.stderr, "");
    const checked = checkPersistentListResponse(sequence([]), output.stdout, output.stderr);
    assert.equal(checked.status, "incomplete"); assert.equal(checked.diagnostic, "persistent-list-protocol");
    assert.match(JSON.parse(output.stdout).schemaVersion, /worker-error-1$/);
  }
  const over = { schemaVersion: "nightshade-persistent-list-sequence-1", seed: 1, operations: Array.from({ length: 33 }, () => ({ kind: "inspect" })) };
  const output = await runNodeModule(worker, { compiler: "/must-not-read", runtimeDirectory: "/must-not-read", sequence: over }, { ...PERSISTENT_LIST_LIMITS, timeoutMs: 5000 });
  assert.equal(JSON.parse(output.stdout).diagnostic, "persistent-list-sequence-budget");
});

test("closed worker errors remain incomplete and never become qualified rejection observations", () => {
  const input = sequence([]);
  for (const diagnostic of ["persistent-list-input-identity", "persistent-list-compiler", "persistent-list-unqualified-rejection", "persistent-list-observation-budget", "worker-input-budget"]) {
    const checked = checkPersistentListResponse(input, JSON.stringify({ schemaVersion: "nightshade-persistent-list-worker-error-1", diagnostic, message: "Synthetic transport error" }), "");
    assert.equal(checked.status, "incomplete"); assert.equal(checked.diagnostic, diagnostic);
  }
  for (const wire of ["{", JSON.stringify({ schemaVersion: "nightshade-persistent-list-worker-error-1", diagnostic: "passed", message: "forged" }),
    JSON.stringify({ schemaVersion: "nightshade-persistent-list-worker-error-1", diagnostic: "persistent-list-protocol", message: "", extra: true }),
    JSON.stringify({ status: "passed", diagnostic: "persistent-list-model-checked", signature: "persistent-list-model-checked" })]) {
    assert.equal(checkPersistentListResponse(input, wire, "").status, "incomplete");
  }
  assert.equal(checkPersistentListResponse(input, "{}", "unexpected stderr").diagnostic, "persistent-list-protocol");
  assert.equal(checkPersistentListResponse(input, "x".repeat(1048577), "").diagnostic, "worker-output-budget");
});

test("runner preserves real supervisor input and prelaunch cancellation classes", async () => {
  const empty = sequence([]), controller = new AbortController(); controller.abort();
  const interrupted = await runPersistentListSequenceIsolated(empty, "/must-not-read", "/must-not-read", PERSISTENT_LIST_LIMITS, controller.signal);
  assert.equal(interrupted.status, "incomplete"); assert.equal(interrupted.diagnostic, "worker-interrupted");
  const oversized = await runPersistentListSequenceIsolated(empty, "x".repeat(1048576), "/must-not-read");
  assert.equal(oversized.status, "incomplete"); assert.equal(oversized.diagnostic, "worker-input-budget");
});

test("pinned compiler declares typed List payload, empty mutation results and the Boolean/Uint/Maybe inspect tuple", qualified, () => {
  const { compiler } = inputs(), directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-list-declarations-"));
  try {
    const compiled = resolve(directory, "compiled"), source = resolve("tests/runtime-fixtures/list-guarded.compact");
    assert.equal(persistentListDigest(readFileSync(source)), PERSISTENT_LIST_SOURCE_SHA256);
    const output = spawnSync(compiler, ["--skip-zk", source, compiled], { encoding: "utf8", timeout: 30000, maxBuffer: 1048576, killSignal: "SIGKILL" });
    assert.equal(output.status, 0, String(output.error ?? output.stderr)); assert.equal(output.stderr, "");
    const declarations = readFileSync(resolve(compiled, "contract/index.d.ts"), "utf8").replace(/\s+/g, " ");
    // Width constraints come from the pinned Compact source; generated TS uses bigint.
    assert.match(declarations, /push\(context: __compactRuntime\.CircuitContext<PS>, \w+: bigint\): Promise<__compactRuntime\.CircuitResults<PS, \[\]>>/);
    assert.match(declarations, /guardedPop\(context: __compactRuntime\.CircuitContext<PS>\): Promise<__compactRuntime\.CircuitResults<PS, \[\]>>/);
    // Compiler 0.34.0 expands this concrete Maybe result to its structural fields.
    assert.match(declarations, /inspect\(context: __compactRuntime\.CircuitContext<PS>\): Promise<__compactRuntime\.CircuitResults<PS, \[boolean, bigint, \{ is_some: boolean, value: bigint \}\]>>/);
    assert.match(declarations, /head\(\): \{ is_some: boolean, value: bigint \}/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("compiled empty and typed boundary sequences preserve full ordered values and duplicate payloads", qualified, async () => {
  const empty = await measured(sequence([])); assert.deepEqual(plain(empty.initial), state(["3"])); assert.deepEqual(empty.final, empty.initial); assert.deepEqual(empty.rows, []);
  const input = sequence([{ kind: "push", value: 0 }, { kind: "push", value: 255 }, { kind: "push", value: 255 }, { kind: "inspect" }, { kind: "guardedPop" }, { kind: "inspect" }]);
  const observed = await measured(input);
  assert.deepEqual(observed.rows.map(row => plain(row.after)), [["0", "3"], ["255", "0", "3"], ["255", "255", "0", "3"], ["255", "255", "0", "3"], ["255", "0", "3"], ["255", "0", "3"]].map(state));
  assert.deepEqual(observed.rows[3].result, [false, "4", { is_some: true, value: "255" }]);
  assert.deepEqual(observed.rows[5].result, [false, "3", { is_some: true, value: "255" }]);
  for (const [index, row] of observed.rows.entries()) {
    assert.deepEqual(row.operation, input.operations[index]); assert.deepEqual(row.transcript, { circuit: row.operation.kind, privateOutputs: 0, events: 0 });
    if (row.operation.kind !== "inspect") { assert.deepEqual(row.result, []); assert.notEqual(row.before.publicSha256, row.after.publicSha256); }
    else assert.equal(row.before.publicSha256, row.after.publicSha256);
  }
});

test("compiled guardedPop rejects only the measured empty state and a corrected precondition succeeds", qualified, async () => {
  const rejected = await measured(sequence([{ kind: "guardedPop" }, { kind: "guardedPop" }, { kind: "inspect" }]));
  assert.deepEqual(rejected.rows.map(row => row.outcome), ["evaluation-success", "evaluation-rejection", "evaluation-success"]);
  assert.deepEqual(rejected.rows.map(row => plain(row.after)), [state([]), state([]), state([])]);
  const row = rejected.rows[1];
  assert.deepEqual(row.error, { name: "CompactError", message: PERSISTENT_LIST_REJECTION }); assert.equal(row.result, null); assert.equal(row.transcript, null);
  assert.deepEqual(row.after, row.before); assert.deepEqual(rejected.rows[2].result, [true, "0", { is_some: false, value: "0" }]);
  const corrected = await measured(sequence([{ kind: "guardedPop" }, { kind: "push", value: 0 }, { kind: "guardedPop" }, { kind: "inspect" }]));
  assert.ok(corrected.rows.every(row => row.outcome === "evaluation-success")); assert.deepEqual(plain(corrected.final), state([]));
});

test("compiled snapshot lifecycle copies constructor slots, overwrites saved states and preserves restoration identity", qualified, async () => {
  const input = sequence([{ kind: "restore", slot: 3 }, { kind: "save", slot: 0 }, { kind: "push", value: 9 }, { kind: "save", slot: 1 },
    { kind: "guardedPop" }, { kind: "guardedPop" }, { kind: "guardedPop" }, { kind: "restore", slot: 1 }, { kind: "inspect" }, { kind: "restore", slot: 0 },
    { kind: "push", value: 255 }, { kind: "save", slot: 0 }, { kind: "restore", slot: 1 }, { kind: "restore", slot: 0 }, { kind: "restore", slot: 0 }]);
  const observed = await measured(input);
  assert.deepEqual(observed.rows.map(row => row.after.values), [["3"], ["3"], ["9", "3"], ["9", "3"], ["3"], [], [], ["9", "3"], ["9", "3"], ["3"], ["255", "3"], ["255", "3"], ["9", "3"], ["255", "3"], ["255", "3"]]);
  assert.equal(observed.rows[6].outcome, "evaluation-rejection");
  assert.deepEqual(observed.rows[0].after, observed.initial);
  assert.deepEqual(observed.rows[7].after, observed.rows[3].slots[1]); assert.deepEqual(observed.rows[9].after, observed.rows[1].slots[0]);
  assert.deepEqual(observed.rows[14].after, observed.rows[13].after); assert.deepEqual(observed.rows[14].after, observed.rows[11].slots[0]);
  assert.deepEqual(observed.rows[14].slots[1], observed.rows[3].slots[1]);
  for (const row of observed.rows) {
    assert.equal(row.before.next, "7"); assert.equal(row.after.next, "7"); assert.equal(row.slots.length, 4);
    if (row.operation.kind === "save" || row.operation.kind === "restore") { assert.equal(row.transcript, null); assert.equal(row.result, null); }
  }
});

test("compiled same-head equal-length lists retain different tail order and independently constructed identity", qualified, async () => {
  const left = await measured(sequence([{ kind: "push", value: 9 }, { kind: "push", value: 17 }, { kind: "push", value: 8 }]));
  const right = await measured(sequence([{ kind: "push", value: 17 }, { kind: "push", value: 9 }, { kind: "push", value: 8 }]));
  assert.deepEqual(left.final.values, ["8", "17", "9", "3"]); assert.deepEqual(right.final.values, ["8", "9", "17", "3"]);
  assert.deepEqual(left.final.head, right.final.head); assert.equal(left.final.length, right.final.length); assert.notDeepEqual(left.final.values, right.final.values);
  // Equal-value reconstructions have no asserted serialization-identity equivalence.
});

test("compiled 32-row boundary reaches length33 and bounded generated seeds reproduce full evidence", qualified, async () => {
  const boundary = sequence(Array.from({ length: 32 }, (_, value) => ({ kind: "push", value })));
  const full = await measured(boundary); assert.equal(full.rows.length, 32); assert.equal(full.final.length, "33");
  assert.deepEqual(full.final.values, [...Array.from({ length: 32 }, (_, index) => String(31 - index)), "3"]);
  for (const seed of [0, 1, 42, 0xffffffff]) {
    const input = generatePersistentListSequence(seed), observed = await measured(input);
    assert.equal(observed.rows.length, 32); assert.deepEqual(observed.rows.map(row => row.operation), input.operations);
    if (seed === 42) assert.deepEqual(await measured(input), observed, "Fresh worker replay must reproduce the complete observation");
  }
});

test("corruptions of measured List evidence rederive property failures and refuse unqualified rejection or forged labels", qualified, async () => {
  const input = sequence([{ kind: "push", value: 9 }, { kind: "push", value: 17 }, { kind: "save", slot: 0 }, { kind: "guardedPop" }, { kind: "restore", slot: 0 }, { kind: "inspect" }, { kind: "guardedPop" }, { kind: "guardedPop" }, { kind: "guardedPop" }, { kind: "guardedPop" }]);
  const observed = await measured(input);
  const changes: [string, (value: PersistentListObservation) => void][] = [
    ["tail", value => { value.rows[1].after.values = ["17", "3", "9"]; }],
    ["length", value => { value.rows[1].after.length = "2"; }],
    ["head", value => { value.rows[1].after.head.value = "9"; }],
    ["inspect", value => { value.rows[5].result = [false, "3", { is_some: true, value: "9" }]; }],
    ["restore", value => { value.rows[4].after.values = ["9", "3"]; }],
    ["slot", value => { value.rows[2].slots[0].values = ["9", "17", "3"]; }],
    ["private", value => { value.rows[1].after.next = "8"; }],
    ["transcript", value => { value.rows[0].transcript!.privateOutputs = 1; }],
    ["early-rejection", value => { const row = value.rows[3]; row.outcome = "evaluation-rejection"; row.error = { name: "CompactError", message: PERSISTENT_LIST_REJECTION }; row.result = null; row.transcript = null; row.after = structuredClone(row.before); }],
    ["missing-rejection", value => { const row = value.rows[9]; row.outcome = "evaluation-success"; row.error = null; row.result = []; row.transcript = { circuit: "guardedPop", privateOutputs: 0, events: 0 }; }],
    ["restored-identity", value => { value.rows[4].after.publicSha256 = "0".repeat(64); }],
  ];
  for (const [name, change] of changes) {
    // Deliberate changes to a measured copy test the checker, not a runtime defect.
    const changed = structuredClone(observed); change(changed);
    const checked = checkPersistentListObservation(input, changed);
    assert.equal(checked.status, "failed", `${name}: ${JSON.stringify(checked)}`); assert.match(checked.signature, /^persistent-list-model\|row:/);
    assert.deepEqual(validatePersistentListResult(input, checked), checked);
    assert.throws(() => validatePersistentListResult(input, { ...checked, signature: "forged" }));
  }
  for (const [name, change] of [
    ["unknown-error", (value: PersistentListObservation) => { value.rows[9].error!.message = "different runtime error"; }],
    ["wrong-source", (value: PersistentListObservation) => { value.sourceSha256 = "0".repeat(64); }],
    ["missing-row", (value: PersistentListObservation) => { value.rows.pop(); }],
    ["value-budget", (value: PersistentListObservation) => { value.rows[0].after.values = Array(65).fill("0"); }],
  ] as const) {
    const changed = structuredClone(observed); change(changed); assert.equal(checkPersistentListObservation(input, changed).status, "incomplete", name);
  }
  let invocations = 0;
  const getter = structuredClone(observed); Object.defineProperty(getter.rows[0].after, "values", { enumerable: true, get() { invocations++; return []; } });
  assert.equal(checkPersistentListObservation(input, getter).status, "incomplete"); assert.equal(invocations, 0);
});

test("[timing] runtime identity refusal and actual supervised timeout, output and cancellation remain incomplete", qualified, async () => {
  const { compiler, runtime } = inputs();
  const input = sequence(Array.from({ length: 32 }, () => ({ kind: "push", value: 255 })));
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-list-inputs-"));
  try {
    writeFileSync(resolve(directory, "package-lock.json"), "{}\n");
    const mismatch = await runPersistentListSequenceIsolated(input, "/must-not-run/compiler", directory);
    assert.equal(mismatch.status, "incomplete"); assert.equal(mismatch.diagnostic, "persistent-list-input-identity");
    const timeout = await runPersistentListSequenceIsolated(input, compiler, runtime, { ...PERSISTENT_LIST_LIMITS, timeoutMs: 1 });
    assert.equal(timeout.status, "incomplete"); assert.equal(timeout.diagnostic, "worker-timeout");
    const output = await runPersistentListSequenceIsolated(input, compiler, runtime, { ...PERSISTENT_LIST_LIMITS, maxOutputBytes: 1024 });
    assert.equal(output.status, "incomplete"); assert.equal(output.diagnostic, "worker-output-budget");
    const controller = new AbortController();
    const pending = runPersistentListSequenceIsolated(input, compiler, runtime, PERSISTENT_LIST_LIMITS, controller.signal);
    setImmediate(() => controller.abort());
    const interrupted = await pending; assert.equal(interrupted.status, "incomplete"); assert.equal(interrupted.diagnostic, "worker-interrupted");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
