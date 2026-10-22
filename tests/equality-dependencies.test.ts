import assert from "node:assert/strict";
import test from "node:test";
import type { AbstractValue, SuccessfulPredicate } from "../src/dataflow/index.js";
import { createEqualityDependencyIndex, equalityDependencies } from "../src/dataflow/equality-dependencies.js";

const location = { file: "test", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
function input(id: string, type = "Field", witness = false): AbstractValue {
  const source = { id, kind: witness ? "witness" as const : "entry-parameter" as const, name: "sameDeclaration", location,
    ...(witness ? { invocation: { site: "sameSite", occurrence: id === "first" ? 0 : 1, leaf: 0 } } : {}) };
  return { type, identity: id, flows: [{ source, form: "raw", trace: [] }], ledger: new Set() };
}
function equal(left: AbstractValue, right: AbstractValue): SuccessfulPredicate {
  return { value: { type: "Boolean", flows: [], ledger: new Set(), comparison: { operator: "==", left, right } },
    truth: true, location, callPath: [], callSites: [], writesBefore: 0, operationsBefore: 0 };
}
const inspect = (value: AbstractValue, predicates: SuccessfulPredicate[]) =>
  equalityDependencies(value, predicates, flow => flow.source.id, 1000, { writes: 0, operations: 0 });

test("derived operands sharing a source do not identify that source", () => {
  const a = input("a"), b = input("b");
  const derived = { ...a, identity: "hash-of-a", flows: a.flows.map(flow => ({ ...flow, form: "hash" as const })) };
  const result = inspect(a, [equal(derived, b)]);
  assert.equal(result.complete, true);
  assert.deepEqual([...result.dependencies], ["a"]);
});

test("cross-type identity aliases do not propagate equality dependencies", () => {
  const a = input("a"), b = { ...input("b", "Uint<8>"), identity: a.identity };
  const result = inspect(a, [equal(a, b)]);
  assert.equal(result.complete, true);
  assert.deepEqual([...result.dependencies], ["a"]);
});

test("transitive required equalities terminate cycles and preserve all dependencies", () => {
  const a = input("a"), b = input("b"), c = input("c");
  const result = inspect(a, [equal(b, c), equal(a, b), equal(c, a)]);
  assert.equal(result.complete, true);
  assert.deepEqual([...result.dependencies].sort(), ["a", "b", "c"]);
  const exhausted = equalityDependencies(a, [equal(a, b)], flow => flow.source.id, 1, { writes: 0, operations: 0 });
  assert.equal(exhausted.complete, false);
  assert.deepEqual([...exhausted.dependencies], []);
});

test("same-declaration witness invocations retain distinct immutable identities", () => {
  const first = input("first", "Field", true), second = input("second", "Field", true), c = input("c");
  const result = inspect(second, [equal(first, c)]);
  assert.equal(result.complete, true);
  assert.deepEqual([...result.dependencies], ["second"]);
});

test("missing or invalid predicate positions never establish ordered equality closure", () => {
  const a = input("a"), b = input("b");
  assert.equal(equalityDependencies(a, undefined, flow => flow.source.id, 1000, { writes: 0, operations: 0 }).complete, false);
  for (const operations of [undefined, NaN, -1, 0.5]) {
    const before = { writes: 0, operations } as { writes: number; operations: number };
    const result = equalityDependencies(a, [equal(a, b)], flow => flow.source.id, 1000, before);
    assert.equal(result.complete, false);
    assert.deepEqual([...result.dependencies], []);
  }
  for (const index of [undefined, NaN, -1, 0.5]) for (const field of ["writesBefore", "operationsBefore"] as const) {
    const predicate = { ...equal(a, b), [field]: index } as SuccessfulPredicate;
    const result = inspect(a, [predicate]);
    assert.equal(result.complete, false);
    assert.deepEqual([...result.dependencies], []);
  }
  const after = { ...equal(a, b), writesBefore: 1, operationsBefore: 1 };
  assert.deepEqual([...inspect(a, [after]).dependencies], ["a"]);
});

test("a shared immutable index filters every reachable edge by both ordering counters", () => {
  const a = input("a"), b = input("b"), c = input("c");
  const predicates = [{ ...equal(a, b), operationsBefore: 1 }, { ...equal(b, c), writesBefore: 1 }];
  const index = createEqualityDependencyIndex(predicates, flow => flow.source.id, 1000, true);
  assert.equal(index.complete, true);
  for (const [before, expected] of [
    [{ writes: 0, operations: 1 }, ["a", "b"]],
    [{ writes: 1, operations: 0 }, ["a"]],
    [{ writes: 1, operations: 1 }, ["a", "b", "c"]],
  ] as const) {
    const actual = index.query(a, before, 1000);
    assert.equal(actual.complete, true);
    assert.deepEqual([...actual.dependencies].sort(), expected);
    const wrapper = equalityDependencies(a, predicates, flow => flow.source.id, 1000, before);
    assert.deepEqual([...wrapper.dependencies].sort(), expected);
  }
});
