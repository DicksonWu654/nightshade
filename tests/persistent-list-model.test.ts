import assert from "node:assert/strict";
import test from "node:test";
import {
  checkPersistentListObservation, expectedPersistentListSequence, generatePersistentListSequence,
  incompletePersistentListResult, persistentListDigest, PERSISTENT_LIST_GENERATOR,
  PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS, PERSISTENT_LIST_LIMITS, PERSISTENT_LIST_LOCK_SHA256,
  PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_OBSERVATION_LIMITS, PERSISTENT_LIST_REJECTION,
  PERSISTENT_LIST_SOURCE_SHA256, validatePersistentListObservation, validatePersistentListResult,
  validatePersistentListSequence, type PersistentListObservation, type PersistentListOperation,
  type PersistentListSequence, type PersistentListSnapshot,
} from "./generative/persistent-list-model.js";

const sequence = (...operations: PersistentListOperation[]): PersistentListSequence => ({ schemaVersion: "nightshade-persistent-list-sequence-1", seed: 1, operations });
const push = (value: number): PersistentListOperation => ({ kind: "push", value });
const pop = (): PersistentListOperation => ({ kind: "guardedPop" });
const inspect = (): PersistentListOperation => ({ kind: "inspect" });
const save = (slot: number): PersistentListOperation => ({ kind: "save", slot });
const restore = (slot: number): PersistentListOperation => ({ kind: "restore", slot });
const state = (values: string[]) => ({ values, length: String(values.length), empty: !values.length, head: { is_some: !!values.length, value: values[0] ?? "0" }, next: "7" });
const hash = (value: string) => persistentListDigest(value);

/** Synthetic well-shaped evidence for checker corruption tests only, not execution. */
function synthetic(input: PersistentListSequence): PersistentListObservation {
  const expected = expectedPersistentListSequence(input);
  const initialHash = hash("synthetic constructor");
  let current = initialHash;
  const slots = Array<string>(4).fill(current);
  const rows = expected.rows.map(row => {
    const beforeHash = current;
    if (row.operation.kind === "push" || row.operation.kind === "guardedPop" && row.outcome === "evaluation-success") current = hash(`synthetic mutation ${row.index}`);
    if (row.operation.kind === "save") slots[row.operation.slot] = current;
    if (row.operation.kind === "restore") current = slots[row.operation.slot];
    return { ...row, before: { ...row.before, publicSha256: beforeHash }, after: { ...row.after, publicSha256: current }, slots: row.slots.map((value, index) => ({ ...value, publicSha256: slots[index] })) };
  });
  return {
    schemaVersion: "nightshade-persistent-list-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-guarded-list",
    compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256,
    sourceSha256: PERSISTENT_LIST_SOURCE_SHA256, compiledJavaScriptSha256: hash("synthetic compiled identity"), sequenceSha256: hash(JSON.stringify(input)),
    initial: { ...expected.initial, publicSha256: initialHash }, rows, final: { ...expected.final, publicSha256: current },
  };
}
function failed(input: PersistentListSequence, evidence: unknown, signature: RegExp): void {
  const checked = checkPersistentListObservation(input, evidence);
  assert.equal(checked.status, "failed", JSON.stringify(checked));
  assert.equal(checked.diagnostic, "persistent-list-model-disagreement");
  assert.match(checked.signature, signature);
}
function incomplete(input: PersistentListSequence, evidence: unknown, diagnostic: string): void {
  const checked = checkPersistentListObservation(input, evidence);
  assert.equal(checked.status, "incomplete", JSON.stringify(checked));
  assert.equal(checked.diagnostic, diagnostic);
  assert.equal(checked.signature, diagnostic);
  assert.ok(!Object.hasOwn(checked, "observation"));
}

test("List array oracle starts from typed constructor and separates state-dependent rejection from corrected input", () => {
  const empty = expectedPersistentListSequence(sequence());
  assert.deepEqual(empty, { initial: state(["3"]), rows: [], final: state(["3"]) });
  const input = sequence(pop(), pop(), inspect(), push(0), pop(), inspect());
  const observed = expectedPersistentListSequence(input);
  assert.deepEqual(observed.rows.map(row => [row.operation, row.outcome, row.result, row.after]), [
    [pop(), "evaluation-success", [], state([])],
    [pop(), "evaluation-rejection", null, state([])],
    [inspect(), "evaluation-success", [true, "0", { is_some: false, value: "0" }], state([])],
    [push(0), "evaluation-success", [], state(["0"])],
    [pop(), "evaluation-success", [], state([])],
    [inspect(), "evaluation-success", [true, "0", { is_some: false, value: "0" }], state([])],
  ]);
  assert.deepEqual(observed.rows[1].error, { name: "CompactError", message: PERSISTENT_LIST_REJECTION });
  assert.equal(observed.rows[1].transcript, null);
  assert.deepEqual(observed.rows[0].transcript, { circuit: "guardedPop", privateOutputs: 0, events: 0 });
  for (const row of observed.rows) assert.deepEqual(row.slots, Array.from({ length: 4 }, () => state(["3"])));
});

test("List oracle preserves typed boundaries, duplicates and same-head distinct tail order", () => {
  const observed = expectedPersistentListSequence(sequence(push(0), push(255), push(255), inspect(), pop(), inspect()));
  assert.deepEqual(observed.rows.map(row => row.after.values), [
    ["0", "3"], ["255", "0", "3"], ["255", "255", "0", "3"], ["255", "255", "0", "3"], ["255", "0", "3"], ["255", "0", "3"],
  ]);
  assert.deepEqual(observed.rows[3].result, [false, "4", { is_some: true, value: "255" }]);
  const left = expectedPersistentListSequence(sequence(push(9), push(17), push(8))).final;
  const right = expectedPersistentListSequence(sequence(push(17), push(9), push(8))).final;
  assert.deepEqual(left.values, ["8", "17", "9", "3"]);
  assert.deepEqual(right.values, ["8", "9", "17", "3"]);
  assert.equal(left.length, right.length); assert.deepEqual(left.head, right.head);
  assert.notDeepEqual(left.values, right.values);
});

test("List oracle copies constructor slots, overwritten saves and repeated restores without aliasing", () => {
  const input = sequence(restore(3), save(0), push(9), save(1), pop(), pop(), pop(), restore(1), inspect(), restore(0), save(1), push(0), restore(1), restore(1));
  const observed = expectedPersistentListSequence(input);
  assert.deepEqual(observed.rows.map(row => row.after.values), [
    ["3"], ["3"], ["9", "3"], ["9", "3"], ["3"], [], [], ["9", "3"], ["9", "3"], ["3"], ["3"], ["0", "3"], ["3"], ["3"],
  ]);
  assert.equal(observed.rows[6].outcome, "evaluation-rejection");
  assert.deepEqual(observed.rows[3].slots.map(slot => slot.values), [["3"], ["9", "3"], ["3"], ["3"]]);
  assert.deepEqual(observed.rows[10].slots.map(slot => slot.values), [["3"], ["3"], ["3"], ["3"]]);
  observed.rows[3].after.values[0] = "200";
  observed.rows[3].slots[1].head.value = "201";
  observed.initial.values[0] = "202";
  assert.deepEqual(observed.rows[7].after, state(["9", "3"]));
  assert.deepEqual(observed.final, state(["3"]));
  assert.deepEqual(input.operations[2], push(9));
});

test("List generator is bounded, reproducible and uses the frozen three-word algorithm", () => {
  assert.equal(PERSISTENT_LIST_GENERATOR, "owned-persistent-list-lcg-1");
  // Derive the first three words explicitly, independently of the generator.
  let word = 1;
  const words = Array.from({ length: 3 }, () => word = (Math.imul(word, 1664525) + 1013904223) >>> 0);
  const kind = ["push", "guardedPop", "inspect", "save", "restore"][(words[0] >>> 16) % 5];
  assert.equal(generatePersistentListSequence(1, 1).operations[0].kind, kind);
  const kinds = new Set<string>(), values = new Set<number>();
  for (let seed = 0; seed < 128; seed++) {
    const generated = generatePersistentListSequence(seed);
    assert.deepEqual(generatePersistentListSequence(seed), generated);
    assert.deepEqual(validatePersistentListSequence(generated), generated);
    assert.equal(generated.operations.length, 32);
    for (const op of generated.operations) { kinds.add(op.kind); if (op.kind === "push") values.add(op.value); }
    const expected = expectedPersistentListSequence(generated);
    assert.ok(expected.rows.every(row => row.after.values.length <= 33));
  }
  assert.deepEqual([...kinds].sort(), ["guardedPop", "inspect", "push", "restore", "save"]);
  for (const boundary of [0, 1, 254, 255]) assert.ok(values.has(boundary));
  assert.deepEqual(generatePersistentListSequence(0xffffffff, 0).operations, []);
  for (const seed of [-1, -0, 0x100000000, 1.5, NaN]) assert.throws(() => generatePersistentListSequence(seed));
  for (const steps of [-1, -0, 33, 0.5]) assert.throws(() => generatePersistentListSequence(0, steps));
  const maximum = sequence(...Array.from({ length: 32 }, (_, index) => push(index)));
  assert.deepEqual(expectedPersistentListSequence(maximum).final.values, Array.from({ length: 32 }, (_, index) => String(31 - index)).concat("3"));
  assert.equal(checkPersistentListObservation(maximum, synthetic(maximum)).status, "passed");
});

test("List grammar detaches accepted data and rejects invalid payloads, schemas and unknown fields", () => {
  const input = sequence(push(255), save(3), restore(0), inspect(), pop());
  const detached = validatePersistentListSequence(input);
  input.operations[0] = push(0);
  assert.deepEqual(detached.operations[0], push(255));
  for (const value of [-1, -0, 256, NaN, Infinity, 0.5, "0", 0n, null]) assert.throws(() => validatePersistentListSequence({ ...sequence(), operations: [{ kind: "push", value }] }), /persistent-list-protocol/);
  for (const slot of [-1, -0, 4, 0.5, "0"]) assert.throws(() => validatePersistentListSequence({ ...sequence(), operations: [{ kind: "save", slot }] }), /persistent-list-protocol/);
  for (const entry of [{ kind: "push", value: 1, slot: 0 }, { kind: "inspect", value: 1 }, { kind: "pop" }, { kind: "restore" }]) assert.throws(() => validatePersistentListSequence({ ...sequence(), operations: [entry] }));
  for (const field of ["source", "state", "adapter", "fixture", "witness", "target"]) assert.throws(() => validatePersistentListSequence({ ...sequence(), [field]: null }));
  assert.throws(() => validatePersistentListSequence({ ...sequence(), schemaVersion: "nightshade-persistent-sequence-1" }));
  assert.throws(() => validatePersistentListSequence(sequence(...Array.from({ length: 33 }, inspect))), /persistent-list-sequence-budget/);
});

test("List protocol decoders reject getters, sparse arrays and hidden/symbol fields without invoking accessors", () => {
  let reads = 0;
  const getter = { enumerable: true, get() { reads++; return "push"; } };
  const kind = Object.defineProperty({}, "kind", getter);
  const payload = Object.defineProperty({ kind: "push" }, "value", getter);
  const arrayGetter = Object.defineProperty([inspect()], 0, getter);
  for (const operations of [[kind], [payload], arrayGetter, new Array(1), Object.assign([inspect()], { extra: 1 })]) {
    assert.throws(() => validatePersistentListSequence({ ...sequence(), operations }));
  }
  for (const bad of [Object.defineProperty(sequence(), "seed", getter), Object.defineProperty(sequence(), "seed", { value: 1, enumerable: false }), Object.assign(sequence(), { [Symbol("extra")]: 1 })]) assert.throws(() => validatePersistentListSequence(bad));
  const input = sequence(inspect()), evidence = synthetic(input);
  Object.defineProperty(evidence.rows[0].before, "values", getter);
  incomplete(input, evidence, "persistent-list-protocol");
  const result = Object.defineProperty({}, "status", getter);
  assert.throws(() => validatePersistentListResult(input, result));
  assert.equal(reads, 0);
});

test("List evidence decodes to detached bounded data and does not assert execution authenticity", () => {
  const input = sequence(push(9), save(1), pop(), restore(1), inspect());
  const evidence = synthetic(input), decoded = validatePersistentListObservation(input, evidence);
  assert.deepEqual(decoded, evidence);
  assert.equal(checkPersistentListObservation(input, decoded).status, "passed");
  evidence.rows[0].after.values[0] = "99";
  evidence.rows[0].operation = push(99);
  assert.deepEqual(decoded.rows[0].after.values, ["9", "3"]);
  assert.deepEqual(decoded.rows[0].operation, push(9));
  assert.ok(Object.isFrozen(PERSISTENT_LIST_LIMITS));
  assert.ok(Object.isFrozen(PERSISTENT_LIST_OBSERVATION_LIMITS));
  assert.ok(Object.isFrozen(PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS));
});

test("List checker reports readable ordering, scalar, result, transcript and private-state disagreements as failures", () => {
  const input = sequence(push(9), push(17), push(8), inspect());
  const corruptions: [string, (value: PersistentListObservation) => void, RegExp][] = [
    ["tail order", value => { value.rows[2].after.values = ["8", "9", "17", "3"]; }, /row:2\|operation:push\|field:after.values.1$/],
    ["length", value => { value.rows[2].after.length = "999"; }, /field:after.length$/],
    ["empty", value => { value.rows[2].after.empty = true; }, /field:after.empty$/],
    ["head presence", value => { value.rows[2].after.head.is_some = false; }, /field:after.head.is_some$/],
    ["head value", value => { value.rows[2].after.head.value = "-1"; }, /field:after.head.value$/],
    ["out-of-range readable payload", value => { value.rows[2].after.values[0] = "256"; }, /field:after.values.0$/],
    ["private state", value => { value.rows[2].after.next = "8"; }, /field:after.next$/],
    ["inspection result", value => { value.rows[3].result = [false, "3", { is_some: true, value: "8" }]; }, /row:3\|operation:inspect\|field:result.1$/],
    ["wrong result kind", value => { value.rows[0].result = null; }, /row:0\|operation:push\|field:result$/],
    ["transcript private output", value => { value.rows[0].transcript!.privateOutputs = 1; }, /field:transcript.privateOutputs$/],
    ["transcript event", value => { value.rows[0].transcript!.events = 1; }, /field:transcript.events$/],
    ["wrong circuit", value => { value.rows[0].transcript!.circuit = "inspect"; }, /field:transcript.circuit$/],
    ["wrong circuit at representation bound", value => { value.rows[0].transcript!.circuit = "x".repeat(PERSISTENT_LIST_OBSERVATION_LIMITS.maxCircuitChars); }, /field:transcript.circuit$/],
    ["wrong scalar at representation bound", value => { value.rows[0].after.length = "1".repeat(PERSISTENT_LIST_OBSERVATION_LIMITS.maxScalarChars); }, /field:after.length$/],
    ["missing transcript", value => { value.rows[0].transcript = null; }, /field:transcript$/],
    ["valid but wrong argument", value => { value.rows[0].operation = push(8); }, /field:operation.value$/],
  ];
  for (const [label, corrupt, signature] of corruptions) {
    const evidence = synthetic(input); corrupt(evidence);
    assert.doesNotThrow(() => validatePersistentListObservation(input, evidence), label);
    failed(input, evidence, signature);
  }
});

test("List checker distinguishes exact rejection on wrong state from unknown errors and unexpected success", () => {
  const accepted = sequence(pop()), acceptedEvidence = synthetic(accepted);
  acceptedEvidence.rows[0].outcome = "evaluation-rejection";
  acceptedEvidence.rows[0].error = { name: "CompactError", message: PERSISTENT_LIST_REJECTION };
  acceptedEvidence.rows[0].result = null; acceptedEvidence.rows[0].transcript = null;
  failed(accepted, acceptedEvidence, /row:0\|operation:guardedPop\|field:outcome$/);
  const rejected = sequence(pop(), pop()), rejectedEvidence = synthetic(rejected);
  rejectedEvidence.rows[1].outcome = "evaluation-success";
  rejectedEvidence.rows[1].error = null; rejectedEvidence.rows[1].result = [];
  rejectedEvidence.rows[1].transcript = { circuit: "guardedPop", privateOutputs: 0, events: 0 };
  failed(rejected, rejectedEvidence, /row:1\|operation:guardedPop\|field:outcome$/);
  for (const message of ["wrong message", "failed assert: other guard", `${PERSISTENT_LIST_REJECTION} `]) {
    const evidence = synthetic(rejected); evidence.rows[1].error!.message = message;
    incomplete(rejected, evidence, "persistent-list-unqualified-rejection");
  }
  const otherCall = synthetic(sequence(inspect()));
  otherCall.rows[0].outcome = "evaluation-rejection"; otherCall.rows[0].error = { name: "CompactError", message: PERSISTENT_LIST_REJECTION };
  incomplete(sequence(inspect()), otherCall, "persistent-list-unqualified-rejection");
  const missing = synthetic(rejected); missing.rows[1].error = null;
  incomplete(rejected, missing, "persistent-list-protocol");
});

test("List checker enforces copied snapshot identities without equating independent equal-value states", () => {
  const input = sequence(save(0), push(9), pop(), inspect(), restore(0), save(1), pop(), pop(), restore(1));
  const evidence = synthetic(input);
  assert.deepEqual(evidence.rows[2].after.values, evidence.initial.values);
  assert.notEqual(evidence.rows[2].after.publicSha256, evidence.initial.publicSha256);
  assert.equal(checkPersistentListObservation(input, evidence).status, "passed");
  for (const index of [0, 3, 4, 5, 7, 8]) {
    const bad = structuredClone(evidence); bad.rows[index].after.publicSha256 = hash(`wrong after ${index}`);
    failed(input, bad, new RegExp(`row:${index}\\|.*field:after.publicSha256$`));
  }
  const noMutation = structuredClone(evidence); noMutation.rows[1].after.publicSha256 = noMutation.rows[1].before.publicSha256;
  failed(input, noMutation, /row:1\|operation:push\|field:after.publicSha256$/);
  const predecessor = structuredClone(evidence); predecessor.rows[1].before.publicSha256 = hash("wrong predecessor");
  failed(input, predecessor, /row:1\|operation:push\|field:before.publicSha256$/);
  const slot = structuredClone(evidence); slot.rows[1].slots[0].publicSha256 = hash("wrong slot");
  failed(input, slot, /row:1\|operation:push\|field:slots.0.publicSha256$/);
  const final = structuredClone(evidence); final.final.publicSha256 = hash("wrong final");
  failed(input, final, /field:final.publicSha256$/);
  const wrongRestore = structuredClone(evidence); wrongRestore.rows[4].after.values = [];
  failed(input, wrongRestore, /row:4\|operation:restore\|field:after.values/);
});

test("List observation identities are independently pinned and incomplete evidence cannot become passed", () => {
  const input = sequence(inspect());
  for (const field of ["sourceSha256", "runtimeLockSha256", "runtimeInputsManifestSha256", "sequenceSha256"] as const) {
    const evidence = synthetic(input); evidence[field] = hash(`wrong ${field}`);
    incomplete(input, evidence, "persistent-list-input-identity");
  }
  const raw = synthetic(input) as unknown as Record<string, unknown>;
  for (const [field, value] of [["schemaVersion", "nightshade-persistent-observation-1"], ["compiler", "0.35.0"], ["runtime", "0.19.104"], ["fixedTime", 1]] as const) incomplete(input, { ...raw, [field]: value }, "persistent-list-input-identity");
  const missing = synthetic(input); missing.rows = [];
  incomplete(input, missing, "persistent-list-protocol");
  const missingSlot = synthetic(input); missingSlot.rows[0].slots.pop();
  incomplete(input, missingSlot, "persistent-list-protocol");
  incomplete(input, { ...synthetic(input), extra: "ignored?" }, "persistent-list-protocol");
  for (const scalar of ["00", "+1", "-0", "1.0", " 1", "1e2"]) {
    const evidence = synthetic(input); evidence.initial.length = scalar;
    incomplete(input, evidence, "persistent-list-protocol");
  }
});

test("List observation structural and reconstructed-byte budgets produce explicit incomplete diagnostics", () => {
  const input = sequence(inspect()), values = synthetic(input);
  const scalar = synthetic(input); scalar.initial.length = "1".repeat(PERSISTENT_LIST_OBSERVATION_LIMITS.maxScalarChars + 1);
  incomplete(input, scalar, "persistent-list-observation-budget");
  const circuit = synthetic(input); circuit.rows[0].transcript!.circuit = "x".repeat(PERSISTENT_LIST_OBSERVATION_LIMITS.maxCircuitChars + 1);
  incomplete(input, circuit, "persistent-list-observation-budget");
  values.initial.values = Array<string>(65).fill("1");
  incomplete(input, values, "persistent-list-observation-budget");
  const rows = synthetic(input); rows.rows = Array.from({ length: 33 }, () => structuredClone(rows.rows[0]));
  incomplete(input, rows, "persistent-list-observation-budget");
  // Fully bounded arrays/scalars can still exceed the aggregate wire cap.
  const maximum = sequence(...Array.from({ length: 32 }, inspect)), wire = synthetic(maximum);
  const large = (view: PersistentListSnapshot) => { view.values = Array<string>(64).fill("1".repeat(80)); };
  large(wire.initial); large(wire.final);
  for (const row of wire.rows) { large(row.before); large(row.after); for (const view of row.slots) large(view); }
  assert.ok(Buffer.byteLength(JSON.stringify(wire)) > 1048576);
  incomplete(maximum, wire, "persistent-list-observation-budget");
});

test("List saved result qualification recomputes full evidence and rejects forged signatures, labels and extras", () => {
  const input = sequence(push(9), inspect()), evidence = synthetic(input);
  const passed = checkPersistentListObservation(input, evidence);
  assert.deepEqual(validatePersistentListResult(input, passed), passed);
  const detached = validatePersistentListResult(input, passed);
  if (passed.status !== "incomplete" && detached.status !== "incomplete") {
    passed.observation.rows[0].after.values[0] = "1";
    assert.equal(detached.observation.rows[0].after.values[0], "9");
  }
  evidence.rows[0].after.values[0] = "255";
  const failure = checkPersistentListObservation(input, evidence);
  assert.equal(failure.status, "failed");
  assert.deepEqual(validatePersistentListResult(input, failure), failure);
  assert.throws(() => validatePersistentListResult(input, { ...failure, signature: "persistent-list-model|forged" }));
  assert.throws(() => validatePersistentListResult(input, { ...failure, message: "forged" }));
  assert.throws(() => validatePersistentListResult(input, { status: "passed", diagnostic: "persistent-list-model-checked", signature: "persistent-list-model-checked", observation: evidence }));
  assert.throws(() => validatePersistentListResult(input, { ...failure, ignored: true }));
  for (const code of PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS) {
    const value = incompletePersistentListResult(code, "bounded reason");
    assert.deepEqual(validatePersistentListResult(input, value), value);
    assert.throws(() => validatePersistentListResult(input, { ...value, observation: evidence }));
  }
  assert.equal(incompletePersistentListResult("not-known", "reason").diagnostic, "persistent-list-protocol");
  assert.equal(incompletePersistentListResult("worker-timeout", "x".repeat(5000)).message.length, 4000);
  assert.ok(incompletePersistentListResult("worker-timeout", "").message.length > 0);
  assert.throws(() => validatePersistentListResult(input, { status: "incomplete", diagnostic: "not-known", signature: "not-known", message: "reason" }));
  assert.throws(() => validatePersistentListResult(input, { ...incompletePersistentListResult("worker-timeout", "reason"), signature: "worker-failed" }));
});
