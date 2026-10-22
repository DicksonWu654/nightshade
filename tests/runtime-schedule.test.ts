import assert from "node:assert/strict";
import test from "node:test";
import { digest } from "./generative/artifacts.js";
import { expectedFlagObservations, renderCase, validateCase, type GeneratedCase } from "./generative/model.js";
import { checkRuntimeObservation, incompleteRuntimeResult } from "./generative/runtime-artifacts.js";
import { DEFAULT_SCHEDULE, mutateRuntimeModel, RuntimeSchedule, validateScheduleOptions, type ScheduleOptions } from "./generative/runtime-schedule.js";

/** Synthetic schema fixture only; no runtime was executed to create this data. */
function fixture(input: GeneratedCase) {
  return checkRuntimeObservation(input, {
    layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: digest(renderCase(input)), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(row => row.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })),
  });
}

function transcript(options: ScheduleOptions) {
  const schedule = new RuntimeSchedule(options);
  const retained = new Map<number, string>();
  const decisions = [];
  let decision;
  while ((decision = schedule.next())) {
    if (decision.parent) assert.equal(decision.parent.artifactSha256, retained.get(decision.parent.ordinal), "only retained checked parents are eligible");
    const hash = digest(JSON.stringify(decision));
    const row = schedule.record(fixture(decision.case), hash);
    if (row.admission?.status === "retained") retained.set(row.ordinal, hash);
    decisions.push(decision);
  }
  return { decisions, state: schedule.snapshot() };
}

test("guided schedule reproduces all decisions and uses retained descendants as parents", () => {
  const options = { ...DEFAULT_SCHEDULE, mutations: 64, maxFeatures: 4096 };
  const first = transcript(options);
  assert.deepEqual(transcript(options), first);
  assert.deepEqual(first.state.outcome, { status: "passed", category: "scheduled-slots-complete" });
  assert.equal(first.state.completed, 68);
  assert.ok(first.decisions.some(decision => (decision.parent?.ordinal ?? 0) > 4), "new retained mutations must influence future parents");
  assert.ok(first.state.rows.some(row => row.admission?.status === "redundant"), "the transcript includes nonretained candidates");
  assert.deepEqual(first.decisions.slice(0, 4).map(decision => [decision.case.seed, decision.case.operations.length, decision.parent]), [[1, 24, null], [2, 24, null], [3, 24, null], [4, 24, null]]);
  assert.ok(first.decisions.slice(4).every(decision => decision.random.words.length === 6 && decision.random.after === decision.random.words[5]));
  assert.notDeepEqual(transcript({ ...options, seed: 2 }).decisions.slice(4), first.decisions.slice(4));
});

test("typed mutations stay bounded at empty/full and key/value boundaries without retry loops", () => {
  const base = validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 0, operations: [{ kind: "conditional", key: 7, value: 65535 }] });
  for (let family = 0; family < 4; family++) {
    const words = [0, family << 16, 0, 0xffffffff, 0xffffffff, 0xffffffff];
    const mutated = mutateRuntimeModel(base, words);
    assert.equal(mutated.mutation.kind, ["insert", "delete", "replace", "operand"][family]);
    assert.deepEqual(validateCase(mutated.model), mutated.model);
    assert.deepEqual(mutateRuntimeModel(base, words), mutated);
  }
  for (const operations of [[], Array.from({ length: 32 }, () => ({ kind: "conditional" as const, key: 7, value: 65535 }))]) {
    for (const word of [0, 1 << 16, 2 << 16, 3 << 16, 0xffffffff]) {
      const result = mutateRuntimeModel({ ...base, operations }, [word, word, word, word, word, word]);
      assert.ok(result.model.operations.length <= 32);
      assert.deepEqual(validateCase(result.model), result.model);
      if (!operations.length) assert.equal(result.mutation.kind, "insert");
      else assert.notEqual(result.mutation.kind, "insert");
    }
  }
  for (const field of [0, 1]) {
    const result = mutateRuntimeModel(base, [0, 3 << 16, field << 16, 0, 0, 0]);
    assert.equal(result.mutation.kind, "operand");
    if (result.mutation.kind === "operand") assert.notEqual(result.mutation.before, result.mutation.after);
  }
  assert.deepEqual(base.operations, [{ kind: "conditional", key: 7, value: 65535 }], "mutations must not alias retained parents");
});

test("schedule inputs reject sparse/accessor data, invalid numbers and unknown controls", () => {
  for (const raw of [{ ...DEFAULT_SCHEDULE, seed: -0 }, { ...DEFAULT_SCHEDULE, seed: 0x100000000 }, { ...DEFAULT_SCHEDULE, mutations: 65 }, { ...DEFAULT_SCHEDULE, maxEvaluations: 0 }, { ...DEFAULT_SCHEDULE, maxFeatures: 4097 }, { ...DEFAULT_SCHEDULE, adapter: "anything" }]) assert.throws(() => validateScheduleOptions(raw));
  const accessor = { ...DEFAULT_SCHEDULE };
  Object.defineProperty(accessor, "seed", { enumerable: true, get() { assert.fail("getter must not execute"); } });
  assert.throws(() => validateScheduleOptions(accessor), /data field/);
  const input = validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 0, operations: [] });
  for (const words of [Array(6), [0, 0, 0, 0, 0, NaN], [0, 0, 0, 0, 0, -0]]) assert.throws(() => mutateRuntimeModel(input, words));
  const words = [0, 0, 0, 0, 0, 0];
  Object.defineProperty(words, "3", { enumerable: true, get() { assert.fail("word getter must not execute"); } });
  assert.throws(() => mutateRuntimeModel(input, words));
});

test("pending decisions and admitted evidence are detached and invalid evidence cannot advance state", () => {
  const schedule = new RuntimeSchedule();
  const decision = schedule.next()!;
  const before = schedule.snapshot();
  const result = fixture(decision.case);
  const corrupt = structuredClone(result);
  corrupt.feedback!.features.push("invented-edge");
  assert.throws(() => schedule.record(corrupt, "b".repeat(64)));
  assert.deepEqual(schedule.snapshot(), before);
  assert.deepEqual(schedule.next(), decision);
  decision.case.operations.length = 0;
  assert.notDeepEqual(schedule.next(), decision);
  const copied = schedule.next()!;
  schedule.record(result, "b".repeat(64));
  const admitted = schedule.snapshot();
  result.observation!.executions.length = 0;
  copied.case.operations.length = 0;
  schedule.snapshot().corpus.entries[0].model.operations.length = 0;
  assert.deepEqual(schedule.snapshot(), admitted);
  assert.throws(() => schedule.record(result, "b".repeat(64)), /pending/);
});

test("checked property failures and incomplete workers never enter the corpus or produce another proposal", () => {
  for (const category of ["runtime-model-disagreement", "runtime-protocol", "worker-timeout", "worker-interrupted", "worker-output-budget"]) {
    const schedule = new RuntimeSchedule();
    const decision = schedule.next()!;
    let result = incompleteRuntimeResult(category, "Synthetic incomplete fixture; no execution");
    if (category === "runtime-model-disagreement") {
      const wire = fixture(decision.case).observation!;
      const row = wire.executions[0].result as { kind: "integer"; value: string }[][];
      row[0][0].value = String(BigInt(row[0][0].value) + 1n);
      result = checkRuntimeObservation(decision.case, wire);
      assert.equal(result.status, "failed");
    }
    schedule.record(result, "a".repeat(64));
    assert.equal(schedule.next(), undefined);
    assert.equal(schedule.snapshot().corpus.entries.length, 0);
    assert.equal(schedule.snapshot().outcome.category, category);
  }
});

test("declared slot completion differs from evaluation/corpus exhaustion and between-worker interruption", () => {
  const bounded = transcript({ ...DEFAULT_SCHEDULE, mutations: 0 });
  assert.equal(bounded.state.completed, 4);
  assert.equal(bounded.state.outcome.status, "passed");
  const exhausted = transcript({ ...DEFAULT_SCHEDULE, mutations: 0, maxEvaluations: 3 });
  assert.equal(exhausted.state.completed, 3);
  assert.deepEqual(exhausted.state.outcome, { status: "incomplete", category: "runtime-evaluation-budget" });
  const corpus = transcript({ ...DEFAULT_SCHEDULE, maxFeatures: 1 });
  assert.equal(corpus.state.completed, 1);
  assert.deepEqual(corpus.state.outcome, { status: "incomplete", category: "runtime-corpus-budget" });
  assert.equal(corpus.state.rows[0].resultStatus, "passed");
  assert.equal(corpus.state.corpus.entries.length, 0);
  const interrupted = new RuntimeSchedule();
  interrupted.interrupt();
  assert.equal(interrupted.next(), undefined);
  assert.deepEqual(interrupted.snapshot().outcome, { status: "incomplete", category: "runtime-campaign-interrupted" });
  const pending = new RuntimeSchedule();
  pending.next();
  assert.throws(() => pending.interrupt(), /pending/);
});
