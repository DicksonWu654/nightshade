import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
import { expectedObservations, generateCase, GeneratedCase, Operation, renderCase, shrinkCandidates, validateCase } from "./generative/model.js";

const make = (operations: Operation[]): GeneratedCase => ({ schemaVersion: "nightshade-generated-case-1", seed: 0, operations });

test("generated cases are deterministic, detached and bounded at uint32 seeds", () => {
  assert.deepEqual(generateCase(0, 4), make([
    { kind: "read", key: 0 }, { kind: "unrelated", value: 43769 },
    { kind: "remove", key: 6 }, { kind: "read", key: 1 },
  ]));
  const kinds = new Set<string>();
  for (const seed of [0, 1, 2, 42, 0x7fffffff, 0x80000000, 0xffffffff]) {
    const original = generateCase(seed, 32);
    assert.deepEqual(original, generateCase(seed, 32));
    assert.deepEqual(original.operations.slice(0, 4), generateCase(seed, 4).operations);
    const copy = validateCase(JSON.parse(JSON.stringify(original)));
    assert.deepEqual(copy, original);
    copy.operations.pop();
    assert.equal(original.operations.length, 32);
    for (const operation of original.operations) kinds.add(operation.kind);
    assert.equal(renderCase(original), renderCase(generateCase(seed, 32)));
  }
  assert.deepEqual([...kinds].sort(), ["conditional", "insert", "read", "remove", "reset", "snapshot", "unrelated", "write"]);
  for (const seed of [-1, -0, 0x100000000, Infinity, NaN, 0.5]) assert.throws(() => generateCase(seed, 1));
  for (const steps of [-1, 0, -0, 33, Infinity, NaN, 1.5]) assert.throws(() => generateCase(0, steps));
});

test("generated-case validation rejects malformed replay data and source injection", () => {
  const valid = make([{ kind: "read", key: 0 }]);
  for (const invalid of [
    null, [], "source", {}, { ...valid, schemaVersion: "future" }, { ...valid, seed: "0" },
    { ...valid, source: "export circuit entry(): [] {}" }, { ...valid, operations: Array(1) },
    { ...valid, operations: Array.from({ length: 33 }, () => ({ kind: "reset" })) },
    { ...valid, operations: [{ kind: "insert", key: 8 }] },
    { ...valid, operations: [{ kind: "remove", key: -1 }] },
    { ...valid, operations: [{ kind: "read", key: "0 as Field); abort();" }] },
    { ...valid, operations: [{ kind: "write", value: 65536 }] },
    { ...valid, operations: [{ kind: "unrelated", value: null }] },
    { ...valid, operations: [{ kind: "conditional", key: 0 }] },
    { ...valid, operations: [{ kind: "snapshot", value: 0 }] },
    { ...valid, operations: [{ kind: "reset", [Symbol("hidden")]: true }] },
    { ...valid, operations: [{ kind: "arbitrary", source: "abort();" }] },
    { ...valid, operations: [Object.create({ kind: "reset" })] },
  ]) assert.throws(() => validateCase(invalid));
  let getterCalls = 0;
  assert.throws(() => validateCase({ ...valid, operations: [{ get kind() { getterCalls++; return "reset"; } }] }));
  assert.throws(() => validateCase({ ...valid, get seed() { getterCalls++; return 0; } }));
  const accessorArray: Operation[] = [];
  Object.defineProperty(accessorArray, 0, { get() { getterCalls++; return { kind: "reset" }; }, enumerable: true });
  assert.throws(() => validateCase({ ...valid, operations: accessorArray }));
  assert.throws(() => validateCase({ ...valid, operations: Object.assign([{ kind: "reset" }], { extra: true }) }));
  assert.equal(getterCalls, 0);
});

test("independent concrete oracle preserves snapshots, unrelated roots and Set replacement", () => {
  const item = make([
    { kind: "write", value: 7 }, { kind: "snapshot" }, { kind: "write", value: 9 },
    { kind: "insert", key: 2 }, { kind: "insert", key: 2 }, { kind: "unrelated", value: 65535 },
    { kind: "read", key: 2 }, { kind: "remove", key: 2 }, { kind: "remove", key: 2 },
    { kind: "insert", key: 0 }, { kind: "reset" },
  ]);
  assert.deepEqual(expectedObservations(item), [[
    ["7", "false", "0", "0", "0"], ["7", "false", "0", "7", "0"], ["9", "false", "0", "7", "0"],
    ["9", "true", "1", "7", "0"], ["9", "true", "1", "7", "0"], ["9", "false", "1", "7", "65535"],
    ["9", "true", "1", "7", "65535"], ["9", "false", "0", "7", "65535"], ["9", "false", "0", "7", "65535"],
    ["9", "true", "1", "7", "65535"], ["9", "false", "0", "7", "65535"],
  ]]);
  assert.deepEqual(expectedObservations(make([])), [[["0", "false", "0", "0", "0"]]]);
});

test("independent concrete oracle correlates repeated branches on the same flag", () => {
  const item = make([
    { kind: "conditional", key: 1, value: 3 }, { kind: "snapshot" },
    { kind: "conditional", key: 2, value: 5 }, { kind: "read", key: 1 },
  ]);
  assert.deepEqual(expectedObservations(item), [
    [["0", "false", "0", "0", "0"], ["0", "false", "0", "0", "0"], ["0", "false", "0", "0", "0"], ["0", "false", "0", "0", "0"]],
    [["3", "true", "1", "0", "0"], ["3", "false", "1", "3", "0"], ["5", "true", "2", "3", "0"], ["5", "true", "2", "3", "0"]],
  ]);
});

test("shrink proposals are unique, deterministic, valid and strictly smaller", () => {
  const item = generateCase(42, 32);
  const before = JSON.stringify(item);
  const candidates = shrinkCandidates(item);
  assert.deepEqual(candidates, shrinkCandidates(item));
  assert.equal(new Set(candidates.map(candidate => JSON.stringify(candidate))).size, candidates.length);
  const magnitude = (candidate: GeneratedCase): number => candidate.operations.reduce((total, operation) => total
    + ("key" in operation ? operation.key : 0) + ("value" in operation ? operation.value : 0), 0);
  for (const candidate of candidates) {
    assert.deepEqual(validateCase(candidate), candidate);
    assert.ok(candidate.operations.length < item.operations.length || magnitude(candidate) < magnitude(item));
    assert.ok(renderCase(candidate).includes("export circuit entry(flag: Boolean)"));
    assert.ok(expectedObservations(candidate).every(path => path.length >= 1));
  }
  assert.equal(JSON.stringify(item), before);
  assert.deepEqual(shrinkCandidates(make([])), []);
  assert.deepEqual(candidates[0].operations, []);
});

test("owned generated programs and representative shrinks compile with the pinned compiler", { skip: !process.env.COMPACTC_TEST }, () => {
  const complete = make([
    { kind: "insert", key: 7 }, { kind: "snapshot" }, { kind: "write", value: 65535 },
    { kind: "conditional", key: 0, value: 256 }, { kind: "unrelated", value: 255 },
    { kind: "read", key: 7 }, { kind: "remove", key: 7 }, { kind: "reset" },
  ]);
  const cases = [make([]), complete, generateCase(0, 1), generateCase(0xffffffff, 32), ...shrinkCandidates(complete).slice(0, 4)];
  for (const item of cases) withFiles({ "main.compact": renderCase(item) }, directory => {
    const result = validateWithCompiler(process.env.COMPACTC_TEST!, resolve(directory, "main.compact"));
    assert.equal(result.valid, true, `${JSON.stringify(item)}\n${result.error}`);
  });
});
