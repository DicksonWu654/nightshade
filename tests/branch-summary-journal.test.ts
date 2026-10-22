import assert from "node:assert/strict";
import test from "node:test";
import { BranchRecording, branchJournalEvents, branchJournalNodes, type BranchJournalNode } from "../src/dataflow/summaries.js";

const marker = (node: number) => ({ kind: "node" as const, node, previous: node - 1 });

test("branch journals preserve an immutable shared prefix without combining arm effects", () => {
  const recording = new BranchRecording(), initial = recording.begin();
  const prefix = recording.append(initial, marker(1));
  const left = recording.append(prefix, marker(2)), right = recording.append(prefix, marker(3));
  assert.strictEqual(left.tail!.previous, prefix.tail); assert.strictEqual(right.tail!.previous, prefix.tail);
  assert.strictEqual(branchJournalNodes(left.tail!)![0], branchJournalNodes(right.tail!)![0]);
  assert.deepEqual(branchJournalEvents(left.tail!), [marker(1), marker(2)]);
  assert.deepEqual(branchJournalEvents(right.tail!), [marker(1), marker(3)]);
  assert.deepEqual(branchJournalEvents(prefix.tail!), [marker(1)]);
  assert.equal(initial.tail, null); assert.equal(recording.effects, 3);
  assert.ok(Object.isFrozen(left)); assert.ok(Object.isFrozen(left.tail)); assert.ok(Object.isFrozen(left.tail!.effect));
});

test("branch recorder saturation invalidates both arms while retaining bounded historical cursors", () => {
  const recording = new BranchRecording(); let cursor = recording.begin();
  for (let index = 0; index < 255; index++) cursor = recording.append(cursor, marker(index));
  const first = recording.append(cursor, marker(255));
  assert.equal(recording.complete, true); assert.equal(recording.effects, 256);
  const refused = recording.append(cursor, marker(256));
  assert.strictEqual(refused, cursor); assert.equal(recording.complete, false); assert.equal(first.recording.complete, false);
  assert.equal(recording.effects, 256); assert.equal(branchJournalEvents(first.tail!)!.length, 256);
  assert.strictEqual(recording.append(first, marker(257)), first);
});

test("cross-candidate cursor misuse and explicit invalidation cannot create qualified journals", () => {
  const one = new BranchRecording(), two = new BranchRecording();
  const cursor = one.append(one.begin(), marker(1));
  assert.strictEqual(two.append(cursor, marker(2)), cursor);
  assert.equal(two.complete, false); assert.equal(two.effects, 0); assert.equal(one.complete, true);
  one.invalidate(); assert.strictEqual(one.append(cursor, marker(3)), cursor);
  assert.equal(one.complete, false); assert.deepEqual(branchJournalEvents(cursor.tail!), [marker(1)]);
});

test("journal expansion refuses a cycle or oversized fabricated chain rather than returning a prefix", () => {
  const cyclic = { effect: marker(0), previous: null as BranchJournalNode | null }; cyclic.previous = cyclic;
  assert.equal(branchJournalEvents(cyclic), undefined);
  let tail: BranchJournalNode = { effect: marker(0), previous: null };
  for (let index = 1; index < 257; index++) tail = { effect: marker(index), previous: tail };
  assert.equal(branchJournalEvents(tail), undefined);
});

test("foreign completions and extra choice sites invalidate the whole candidate", () => {
  const location = { file: "owned.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
  const value = { flows: [], ledger: new Set<string>() };
  for (const effect of [
    { kind: "completion" as const, circuit: "other" },
    { kind: "choice" as const, node: 3, owner: "other", selected: true, value, location, until: -1 },
    { kind: "choice" as const, node: 4, owner: "callee", selected: true, value, location, until: -1 },
  ]) {
    const recording = new BranchRecording("callee", 3), cursor = recording.begin();
    assert.strictEqual(recording.append(cursor, effect), cursor); assert.equal(recording.complete, false); assert.equal(recording.effects, 0);
  }
  const recording = new BranchRecording("callee", 3), prefix = recording.begin();
  const left = recording.append(prefix, { kind: "choice", node: 3, owner: "callee", selected: true, value, location, until: -1 });
  const right = recording.append(prefix, { kind: "choice", node: 3, owner: "callee", selected: false, value, location, until: -1 });
  assert.equal(recording.complete, true); assert.equal(recording.observedChoices, 2);
  assert.equal(branchJournalEvents(left.tail!)!.length, 1); assert.equal(branchJournalEvents(right.tail!)!.length, 1);
});
