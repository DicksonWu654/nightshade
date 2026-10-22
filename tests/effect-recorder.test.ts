import test from "node:test";
import assert from "node:assert/strict";
import { EffectRecorder, MutationEffect, ReadonlyEffect } from "../src/dataflow/summaries.js";
import { Span } from "../src/model.js";

const location: Span = { file: "main.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
const value = { flows: [], ledger: new Set<string>(), type: "Field" };
const region = { root: "stored", path: [], type: "Field" };
const sink: ReadonlyEffect = { kind: "public-sink", sink: { kind: "ledger-operation", name: "stored.read", location, value } };

const unexpected: MutationEffect[] = [
  { kind: "assignment", region, value, location },
  { kind: "ledger-operation", region, expression: { kind: "member", name: "write", value: "call", args: [], span: location }, args: [value] },
];

test("branching invalidates active linear recordings without poisoning later independent recordings", () => {
  const recorder = new EffectRecorder();
  const outer = recorder.begin(1), inner = recorder.begin(2, "readonly");
  recorder.record(sink, ["entry", "outer", "inner"]);
  recorder.invalidateActive();
  recorder.record(unexpected[0], ["entry", "outer", "inner"]);
  recorder.end(inner); recorder.end(outer);
  for (const recording of [outer, inner]) { assert.equal(recording.complete, false); assert.deepEqual(recording.effects, []); }
  const later = recorder.begin(1);
  recorder.record(unexpected[0], ["entry", "later"]);
  recorder.end(later);
  assert.equal(later.complete, true);
  assert.deepEqual(later.effects, [{ effect: unexpected[0], callSuffix: ["later"], locationSuffix: [] }]);
});

for (const effect of unexpected) test(`unexpected ${effect.kind} invalidates readonly recording without dropping its parent's effects`, () => {
  const recorder = new EffectRecorder();
  const outer = recorder.begin(1);
  const inner = recorder.begin(2, "readonly");
  const stack = ["entry", "outer", "inner"];
  const completion: MutationEffect = { kind: "completion", circuit: "inner" };
  recorder.record(sink, stack);
  recorder.record(effect, stack);
  recorder.record(completion, stack);
  recorder.end(inner);
  recorder.end(outer);

  assert.equal(inner.complete, false);
  assert.deepEqual(inner.effects, []);
  assert.equal(outer.complete, true);
  assert.deepEqual(outer.effects, [
    { effect, callSuffix: ["outer", "inner"], locationSuffix: [] },
    { effect: completion, callSuffix: ["outer", "inner"], locationSuffix: [] },
  ]);
});

test("nested readonly recordings preserve sink and completion order with independent caller suffixes", () => {
  const recorder = new EffectRecorder();
  const outerSite = { ...location, start: 10, end: 11, column: 11, endColumn: 12 };
  const innerSite = { ...location, start: 20, end: 21, column: 21, endColumn: 22 };
  const outer = recorder.begin(1, "readonly");
  const inner = recorder.begin(2, "readonly");
  const innerCompletion: ReadonlyEffect = { kind: "completion", circuit: "inner" };
  const outerCompletion: ReadonlyEffect = { kind: "completion", circuit: "outer" };
  recorder.record(sink, ["entry", "outer", "inner"], [location, outerSite, innerSite]);
  recorder.record(innerCompletion, ["entry", "outer", "inner"], [location, outerSite, innerSite]);
  recorder.end(inner);
  recorder.record(outerCompletion, ["entry", "outer"], [location, outerSite]);
  recorder.end(outer);

  assert.equal(inner.complete, true);
  assert.equal(outer.complete, true);
  assert.deepEqual(inner.effects, [
    { effect: sink, callSuffix: ["inner"], locationSuffix: [] },
    { effect: innerCompletion, callSuffix: ["inner"], locationSuffix: [] },
  ]);
  assert.deepEqual(outer.effects, [
    { effect: sink, callSuffix: ["outer", "inner"], locationSuffix: [innerSite] },
    { effect: innerCompletion, callSuffix: ["outer", "inner"], locationSuffix: [innerSite] },
    { effect: outerCompletion, callSuffix: ["outer"], locationSuffix: [] },
  ]);
});

test("exhausting an outer recording preserves a smaller nested recording", () => {
  const recorder = new EffectRecorder();
  const outer = recorder.begin(1, "readonly");
  for (let index = 0; index < 255; index++) recorder.record(sink, ["entry", "outer"]);
  const inner = recorder.begin(2, "readonly");
  for (let index = 0; index < 3; index++) recorder.record(sink, ["entry", "outer", "inner"]);
  recorder.end(inner);
  recorder.end(outer);

  assert.equal(outer.complete, false);
  assert.deepEqual(outer.effects, []);
  assert.equal(inner.complete, true);
  assert.deepEqual(inner.effects, Array.from({ length: 3 }, () => ({ effect: sink, callSuffix: ["inner"], locationSuffix: [] })));
});

test("readonly sink exhaustion leaves a parent mutation recording usable", () => {
  const recorder = new EffectRecorder();
  const outer = recorder.begin(1);
  const inner = recorder.begin(2, "readonly");
  for (let index = 0; index < 257; index++) recorder.record(sink, ["entry", "outer", "inner"]);
  const completion: ReadonlyEffect = { kind: "completion", circuit: "inner" };
  recorder.record(completion, ["entry", "outer", "inner"]);
  recorder.end(inner);
  recorder.end(outer);

  assert.equal(inner.complete, false);
  assert.deepEqual(inner.effects, []);
  assert.equal(outer.complete, true);
  assert.deepEqual(outer.effects, [{ effect: completion, callSuffix: ["outer", "inner"], locationSuffix: [] }]);
});
