import assert from "node:assert/strict";
import test from "node:test";
import { validateCheckResult } from "./generative/results.js";
import { checkCase, type CheckResult } from "./generative/check.js";
import { generateCase } from "./generative/model.js";

/** Structural evidence fixture, not a claim that this object ran a compiler. */
function passing(): CheckResult {
  return {
    status: "passed", category: "equivalent-and-model-checked", signature: "equivalent-and-model-checked",
    compiler: { valid: true, version: "0.34.0", languageVersion: "0.26.0" }, observationSha256: "a".repeat(64),
    modes: (["instructions", "expressions"] as const).flatMap(engine => [true, false].map(cached => ({
      engine, cached, completedEntries: 1, diagnosticCodes: [],
      metrics: { steps: 20, sources: 1, paths: 2, abstractValues: 30, summaryHits: cached ? 3 : 0, summaryEntries: cached ? 2 : 0, statefulSummaryHits: cached ? 1 : 0, readSummaryHits: cached ? 2 : 0, summaryEffects: cached ? 4 : 0, guardSubsumptions: 0 },
    }))),
  };
}

test("passing result validation requires all four distinct qualified modes and returns a detached copy", () => {
  const input = passing();
  const output = validateCheckResult(input);
  assert.deepEqual(output, input);
  output.modes[0].metrics.steps++;
  output.modes[0].diagnosticCodes.push("changed");
  output.compiler!.version = "changed";
  assert.equal(input.modes[0].metrics.steps, 20);
  assert.deepEqual(input.modes[0].diagnosticCodes, []);
  assert.equal(input.compiler!.version, "0.34.0");
  assert.deepEqual(validateCheckResult({ ...input, message: undefined }), { ...input, message: undefined });
});

test("nonpassing results retain absent qualification and meaningful partial evidence", () => {
  const qualified = passing();
  const outcomes: CheckResult[] = [
    { status: "unqualified", category: "compiler-required", signature: "compiler-required", modes: [] },
    { status: "unqualified", category: "compiler-validation-failed", signature: "compiler-validation-failed", modes: [], compiler: { valid: false, version: "", languageVersion: "", error: "Process failed" } },
    { status: "unqualified", category: "compiler-validation-failed", signature: "compiler-validation-failed", modes: [], compiler: { valid: false, version: "0.33.0", languageVersion: "0.25.0", error: "Version mismatch" } },
    { status: "incomplete", category: "worker-timeout", signature: "worker-timeout", message: "Wall budget exhausted", modes: [] },
    { status: "incomplete", category: "analysis-incomplete", signature: "analysis-incomplete", compiler: qualified.compiler, modes: qualified.modes.map(mode => ({ ...mode, completedEntries: 0, diagnosticCodes: ["path-budget"] })) },
    { status: "failed", category: "analyzer-exception", signature: `analyzer-exception:${"b".repeat(64)}`, compiler: qualified.compiler, modes: qualified.modes.slice(0, 1) },
    { status: "failed", category: "cache-exercise-missing", signature: "cache-exercise-missing:instructions:readSummaryHits", compiler: qualified.compiler, modes: qualified.modes.map(mode => ({ ...mode, metrics: { ...mode.metrics, readSummaryHits: 0 } })) },
  ];
  for (const outcome of outcomes) assert.deepEqual(validateCheckResult(outcome), outcome);
  assert.equal(Object.hasOwn(validateCheckResult(outcomes[0]), "compiler"), false);
  assert.equal(Object.hasOwn(validateCheckResult(outcomes[3]), "observationSha256"), false);
});

test("missing and duplicate engine/cache evidence cannot produce a passing result", () => {
  const complete = passing();
  for (const modes of [[], complete.modes.slice(0, 3), [...complete.modes, complete.modes[0]], Array(4).fill(complete.modes[0]), Array(4).fill({ completedEntries: 1, diagnosticCodes: [] })]) {
    assert.throws(() => validateCheckResult({ ...complete, modes }));
  }
  for (const modify of [
    (mode: Record<string, unknown>) => { mode.engine = "unknown"; },
    (mode: Record<string, unknown>) => { mode.cached = "true"; },
    (mode: Record<string, unknown>) => { mode.completedEntries = 2; },
    (mode: Record<string, unknown>) => { mode.completedEntries = 0; },
    (mode: Record<string, unknown>) => { mode.diagnosticCodes = ["value-budget"]; },
    (mode: Record<string, unknown>) => { mode.additional = true; },
  ]) {
    const input = passing();
    modify(input.modes[0] as unknown as Record<string, unknown>);
    assert.throws(() => validateCheckResult(input));
  }
});

test("passing evidence requires exact compiler versions, category, signature and observation digest", () => {
  const input = passing();
  for (const compiler of [undefined, null, { valid: true }, { ...input.compiler, valid: false }, { ...input.compiler, valid: "true" }, { ...input.compiler, version: "0.33.0" }, { ...input.compiler, languageVersion: "0.25.0" }, { ...input.compiler, error: "Compilation failed" }, { ...input.compiler, extra: true }]) {
    assert.throws(() => validateCheckResult({ ...input, compiler }));
  }
  for (const observationSha256 of [undefined, null, "", "f".repeat(63), "G".repeat(64), 42]) assert.throws(() => validateCheckResult({ ...input, observationSha256 }));
  for (const category of ["", " ", "equivalent", "worker-timeout"]) assert.throws(() => validateCheckResult({ ...input, category }));
  for (const signature of ["", "different", "equivalent-and-model-checked:suffix"]) assert.throws(() => validateCheckResult({ ...input, signature }));
});

test("all metric fields are required finite nonnegative counts and passing cache evidence is consistent", () => {
  for (const key of Object.keys(passing().modes[0].metrics)) {
    for (const invalid of [undefined, null, -1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1"]) {
      const input = passing();
      (input.modes[0].metrics as unknown as Record<string, unknown>)[key] = invalid;
      assert.throws(() => validateCheckResult(input), `${key}=${String(invalid)}`);
    }
    const missing = passing();
    delete (missing.modes[0].metrics as unknown as Record<string, unknown>)[key];
    assert.throws(() => validateCheckResult(missing), `missing ${key}`);
  }
  for (const key of ["summaryHits", "summaryEntries", "statefulSummaryHits", "readSummaryHits", "summaryEffects"] as const) {
    const input = passing();
    input.modes[1].metrics[key] = 1;
    assert.throws(() => validateCheckResult(input), `uncached ${key}`);
  }
  for (const key of ["readSummaryHits", "summaryEntries", "summaryHits", "steps", "paths", "abstractValues"] as const) {
    const input = passing();
    input.modes[0].metrics[key] = 0;
    assert.throws(() => validateCheckResult(input), `passing zero ${key}`);
  }
  const badCount = passing();
  badCount.modes[0].metrics.summaryHits = 2;
  assert.throws(() => validateCheckResult(badCount), "read and stateful hits exceed total hits");
  assert.throws(() => validateCheckResult({ ...passing(), modes: passing().modes.map(mode => ({ ...mode, metrics: { ...mode.metrics, extra: 0 } })) }));
});

test("result schema rejects unknown, inherited, sparse and accessor evidence without invoking getters", () => {
  const input = passing();
  for (const malformed of [null, [], "passed", { ...input, status: "unknown" }, { ...input, extra: true }, { ...input, [Symbol("evidence")]: true }, Object.create(input), { ...input, message: 42 }]) assert.throws(() => validateCheckResult(malformed));
  const hidden = { ...input };
  Object.defineProperty(hidden, "hidden", { value: true });
  assert.throws(() => validateCheckResult(hidden));
  const accessor = { ...input };
  Object.defineProperty(accessor, "category", { get() { assert.fail("result getter must not run"); } });
  assert.throws(() => validateCheckResult(accessor), /accessor/);
  const sparse = Array(4);
  assert.throws(() => validateCheckResult({ ...input, modes: sparse }));
  const modes = [...input.modes];
  Object.defineProperty(modes, "0", { get() { assert.fail("mode getter must not run"); } });
  assert.throws(() => validateCheckResult({ ...input, modes }), /data fields/);
  for (const diagnosticCodes of [["duplicate", "duplicate"], [""], [42], Array(2)]) assert.throws(() => validateCheckResult({ ...input, status: "incomplete", modes: input.modes.map(mode => ({ ...mode, diagnosticCodes })) }));
});

test("actual compiler-qualified, incomplete and unqualified checker results satisfy the result schema", { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false }, () => {
  const input = generateCase(42, 4);
  const options = { compiler: process.env.COMPACTC_TEST };
  const passed = checkCase(input, options);
  assert.equal(passed.status, "passed", JSON.stringify(passed));
  assert.deepEqual(validateCheckResult(passed), passed);
  const incomplete = checkCase(input, { ...options, maxSteps: 1 });
  assert.equal(incomplete.status, "incomplete");
  assert.deepEqual(validateCheckResult(incomplete), incomplete);
  assert.deepEqual(validateCheckResult(checkCase(input, {})), checkCase(input, {}));
});
