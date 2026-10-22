import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runNodeModule } from "../src/runtime/process.js";
import { expectedFlagObservations, generateCase, renderCase, validateCase, type GeneratedCase } from "./generative/model.js";
import { runtimeFeedback, RuntimeModelMismatch, RuntimeTransitionCorpus } from "./generative/runtime-feedback.js";

const model = validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 1, operations: [
  { kind: "insert", key: 1 }, { kind: "remove", key: 1 }, { kind: "insert", key: 2 },
  { kind: "read", key: 1 }, { kind: "write", value: 8 }, { kind: "snapshot" },
  { kind: "conditional", key: 2, value: 5 },
] });
const oneWrite = (value: number) => validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 0, operations: [{ kind: "write", value }] });

/** Schema-only fixture. This object is not evidence that a runtime was executed. */
function schemaFixture(input: GeneratedCase) {
  return {
    layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0",
    runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: createHash("sha256").update(renderCase(input)).digest("hex"), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(checkpoint => checkpoint.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })),
  };
}

test("runtime feedback schema binds source, versions, scalar kinds and both input observations", () => {
  const wire = schemaFixture(model);
  const accepted = runtimeFeedback(model, wire);
  assert.equal(accepted.coverageKind, "observed-checkpoint-transitions");
  assert.equal(accepted.checkpoints.length, 14);
  assert.deepEqual(new Set(accepted.checkpoints.map(checkpoint => checkpoint.flag)), new Set([false, true]));
  for (const [key, value] of [["compiler", "0.33.0"], ["runtime", "0.19.104"], ["layer", "proof-verified"], ["fixedTime", 0], ["compiledJavaScriptSha256", "unverified"]]) assert.throws(() => runtimeFeedback(model, { ...wire, [String(key)]: value }));
  assert.throws(() => runtimeFeedback(oneWrite(1), wire), /source\/model/);
  assert.throws(() => runtimeFeedback(model, { ...wire, executions: [wire.executions[0], wire.executions[0]] }), /distinct/);
  const wrongKind = structuredClone(wire);
  wrongKind.executions[0].result[0][1] = { kind: "integer", value: "1" };
  assert.throws(() => runtimeFeedback(model, wrongKind), RuntimeModelMismatch);
  const missingCell = structuredClone(wire);
  missingCell.executions[0].result[0].pop();
  assert.throws(() => runtimeFeedback(model, missingCell), RuntimeModelMismatch);
  assert.deepEqual(runtimeFeedback(model, { ...wire, executions: [...wire.executions].reverse() }), accepted);
});

test("runtime feedback rejects sparse/accessor evidence and exhausted representation bounds", () => {
  const wire = schemaFixture(model);
  assert.throws(() => runtimeFeedback(model, { ...wire, executions: Array(2) }));
  assert.throws(() => runtimeFeedback(model, { ...wire, extra: "unqualified" }));
  const accessor = { ...wire };
  Object.defineProperty(accessor, "executions", { get() { assert.fail("getter must not execute"); } });
  assert.throws(() => runtimeFeedback(model, accessor), /accessor/);
  const wide = structuredClone(wire);
  wide.executions[0].result = Array(32).fill(Array(32).fill({ kind: "integer", value: "0" }));
  assert.throws(() => runtimeFeedback(model, wide), /budget/);
});

test("corpus retains novel observed categories rather than every distinct value or seed", () => {
  const corpus = new RuntimeTransitionCorpus();
  assert.equal(corpus.consider(oneWrite(1), schemaFixture(oneWrite(1))).status, "retained");
  assert.equal(corpus.consider(oneWrite(2), schemaFixture(oneWrite(2))).status, "redundant");
  assert.equal(corpus.consider(oneWrite(0), schemaFixture(oneWrite(0))).status, "retained");
  assert.equal(corpus.snapshot().entries.length, 2);
  const before = corpus.snapshot();
  const corrupt = schemaFixture(model);
  corrupt.executions[0].result[0][2].value = "7";
  assert.throws(() => corpus.consider(model, corrupt), RuntimeModelMismatch);
  assert.deepEqual(corpus.snapshot(), before, "failed properties cannot seed the retained corpus");
  const snapshot = corpus.snapshot();
  snapshot.entries[0].features.length = 0;
  snapshot.entries[0].model.operations.length = 0;
  snapshot.features.length = 0;
  assert.deepEqual(corpus.snapshot(), before, "external snapshots cannot mutate retained evidence");
});

test("runtime corpus capacity is explicit, sticky and never partially admits a case", () => {
  for (const limits of [[1, 512], [128, 1]]) {
    const corpus = new RuntimeTransitionCorpus(...limits as [number, number]);
    assert.equal(corpus.consider(oneWrite(1), schemaFixture(oneWrite(1))).status, "retained");
    const before = corpus.snapshot();
    assert.deepEqual(corpus.consider(oneWrite(0), schemaFixture(oneWrite(0))), { status: "incomplete", newFeatures: [], diagnostic: "runtime-corpus-budget" });
    assert.deepEqual(corpus.snapshot(), { ...before, exhausted: true });
    assert.equal(corpus.consider(oneWrite(1), schemaFixture(oneWrite(1))).status, "incomplete");
  }
  for (const limits of [[0, 1], [1, 0], [257, 1], [1, 4097], [NaN, 1]]) assert.throws(() => new RuntimeTransitionCorpus(...limits as [number, number]));
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
let measured: Promise<ReturnType<typeof schemaFixture>> | undefined;
function actual() {
  assert.ok(process.env.COMPACTC_TEST, "Runtime qualification also requires COMPACTC_TEST");
  return measured ??= runNodeModule(fileURLToPath(new URL("./runtime-fixtures/generated-worker.js", import.meta.url)),
    { case: model, compiler: process.env.COMPACTC_TEST, runtimeDirectory: process.env.COMPACT_RUNTIME_TEST },
    { timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1048576 }).then(output => {
    assert.equal(output.stderr, "");
    return JSON.parse(output.stdout) as ReturnType<typeof schemaFixture>;
  });
}

test("compiled feedback distinguishes a membership transition from changing the queried key", qualified, async () => {
  const measured = await actual();
  const feedback = runtimeFeedback(model, measured);
  assert.equal(feedback.checkpoints.length, 14);
  for (const flag of [false, true]) {
    const checkpoints = feedback.checkpoints.filter(checkpoint => checkpoint.flag === flag);
    assert.equal(checkpoints[0].features.length, 1, "first measured checkpoint has no invented preceding observation");
    assert.match(checkpoints[1].features[1], /member:true->false$/);
    assert.match(checkpoints[2].features[1], /member:different-query-keys$/);
    assert.match(checkpoints[3].features[1], /member:different-query-keys$/);
    assert.match(checkpoints[6].features[1], flag ? /scalar:down/ : /scalar:same/);
  }
  const corpus = new RuntimeTransitionCorpus();
  assert.equal(corpus.consider(model, measured).status, "retained");
  assert.equal(corpus.consider(model, measured).status, "redundant");
});

test("corruption of actual compiled outcomes or their input association cannot produce feedback", qualified, async () => {
  const source = await actual();
  const wrong = structuredClone(source);
  wrong.executions[0].result[0][2].value = "7";
  assert.throws(() => runtimeFeedback(model, wrong), RuntimeModelMismatch);
  const swapped = structuredClone(source);
  for (const execution of swapped.executions) execution.flag = !execution.flag;
  assert.throws(() => runtimeFeedback(model, swapped), RuntimeModelMismatch);
});

test("full-size and empty owned models fit the explicit feedback representation bound", () => {
  for (const input of [generateCase(0xffffffff, 32), validateCase({ ...model, operations: [] })]) {
    const feedback = runtimeFeedback(input, schemaFixture(input));
    assert.equal(feedback.checkpoints.length, 2 * Math.max(1, input.operations.length));
  }
});
