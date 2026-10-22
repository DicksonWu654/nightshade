import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { AnalysisFacts } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { AnalysisError } from "../src/model.js";
import { checkObservations, exceptionIdentity } from "./generative/check.js";
import { expectedFlagObservations, expectedObservations, GeneratedCase, renderCase } from "./generative/model.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const input: GeneratedCase = { schemaVersion: "nightshade-generated-case-1", seed: 42, operations: [
  { kind: "conditional", key: 1, value: 3 }, { kind: "snapshot" },
  { kind: "conditional", key: 2, value: 5 }, { kind: "read", key: 1 },
] };

function withFacts(item: GeneratedCase, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": renderCase(item) }, directory => {
    const path = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, path);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, undefined, undefined, undefined, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(checkObservations(item, facts), undefined);
      check(facts);
    }
  });
}

function copyFacts(facts: AnalysisFacts): AnalysisFacts {
  return { ...facts, paths: structuredClone(facts.paths), failedAssertions: structuredClone(facts.failedAssertions) };
}

test("concrete oracle preserves flag association even for coincident outcomes", () => {
  const empty: GeneratedCase = { ...input, operations: [] };
  assert.deepEqual(expectedFlagObservations(empty), [
    { flag: false, observations: [["0", "false", "0", "0", "0"]] },
    { flag: true, observations: [["0", "false", "0", "0", "0"]] },
  ]);
  assert.equal(expectedObservations(empty).length, 1);
  assert.equal(expectedFlagObservations(input).length, 2);
  assert.notDeepEqual(expectedFlagObservations(input)[0].observations, expectedFlagObservations(input)[1].observations);
});

test("compiler-grounded oracle rejects inverted or inconsistent branch facts in all four modes", qualified, () => {
  withFacts(input, facts => {
    const inverted = copyFacts(facts);
    for (const path of inverted.paths) for (const step of path.path) if (step.kind === "branch") {
      step.label = step.label.replace(/true|false$/, value => value === "true" ? "false" : "true");
    }
    // The unordered returned values are unchanged: only the input association
    // detects this corruption, which could be shared across all four modes.
    assert.deepEqual(inverted.paths.map(path => path.sinks), facts.paths.map(path => path.sinks));
    assert.equal(checkObservations(input, inverted)?.property, "constant-value");

    const inconsistent = copyFacts(facts);
    const decisions = inconsistent.paths[0].path.filter(step => step.kind === "branch");
    decisions[0].label = decisions[0].label.replace(/true|false$/, value => value === "true" ? "false" : "true");
    assert.equal(checkObservations(input, inconsistent)?.property, "branch-correlation");

    const missingDecision = copyFacts(facts);
    const index = missingDecision.paths[0].path.findIndex(step => step.kind === "branch");
    missingDecision.paths[0].path.splice(index, 1);
    assert.equal(checkObservations(input, missingDecision)?.property, "branch-count");

    const missingInput = copyFacts(facts);
    missingInput.paths.pop();
    assert.equal(checkObservations(input, missingInput)?.property, "missing-input-path");
  });
});

test("compiler-grounded oracle rejects wrong scalar kinds, values and tuple shapes", qualified, () => {
  withFacts(input, facts => {
    const wrongKind = copyFacts(facts);
    const member = wrongKind.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.items![0].items![1];
    member.constantKind = "integer";
    assert.equal(checkObservations(input, wrongKind)?.property, "constant-kind");
    assert.equal(checkObservations(input, wrongKind)?.field, "membership");

    const wrongValue = copyFacts(facts);
    wrongValue.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.items![0].items![4].constant = "1";
    assert.equal(checkObservations(input, wrongValue)?.property, "constant-value");
    assert.equal(checkObservations(input, wrongValue)?.field, "unrelated");

    const wrongShape = copyFacts(facts);
    wrongShape.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.items![0].items!.pop();
    assert.equal(checkObservations(input, wrongShape)?.property, "return-shape");
  });
});

test("compiler-grounded oracle rejects spurious failures and default findings", qualified, () => {
  withFacts(input, facts => {
    const spuriousFailure = copyFacts(facts);
    spuriousFailure.failedAssertions.push({
      location: facts.program.rootSource.ast.span, condition: { flows: [], ledger: new Set(), constantKind: "boolean", constant: "false" },
      message: "injected incorrect failure fact", callPath: [facts.program.entries[0]], path: [],
    });
    assert.equal(checkObservations(input, spuriousFailure)?.property, "unexpected-failure");

    const spuriousFinding = copyFacts(facts);
    const sink = spuriousFinding.paths[0].sinks.find(sink => sink.kind === "exported-return")!;
    const flow = spuriousFinding.paths.flatMap(path => path.sinks.flatMap(sink => sink.value.flows)).find(flow => flow.source.name === "flag");
    assert.ok(flow);
    sink.value.commitments = [{
      primitive: "transientCommit", location: sink.location,
      input: { flows: [flow], ledger: new Set() }, randomness: { flows: [], ledger: new Set(), constantKind: "integer", constant: "0" },
    }];
    assert.equal(checkObservations(input, spuriousFinding)?.property, "unexpected-finding");
    assert.equal(checkObservations(input, spuriousFinding)?.field, "predictable-commitment-randomness");
  });
});

test("compiler-grounded oracle accepts branchless and empty generated cases", qualified, () => {
  withFacts({ ...input, operations: [] }, () => {});
  withFacts({ ...input, operations: [{ kind: "write", value: 7 }, { kind: "snapshot" }, { kind: "write", value: 9 }] }, () => {});
});

test("exception signatures normalize fixture paths while distinguishing error identities", () => {
  const before = exceptionIdentity(new TypeError("Cannot read /tmp/nightshade-test-first/main.compact"), "/tmp/nightshade-test-first");
  const after = exceptionIdentity(new TypeError("Cannot read /tmp/nightshade-test-second/main.compact"), "/tmp/nightshade-test-second");
  assert.deepEqual(before, after);
  assert.equal(before.message, "Cannot read <fixture>/main.compact");
  assert.notEqual(before.signature, exceptionIdentity(new Error("Cannot read /tmp/nightshade-test-first/main.compact"), "/tmp/nightshade-test-first").signature);
  assert.notEqual(before.signature, exceptionIdentity(new TypeError("Different failure"), "/tmp/nightshade-test-first").signature);
  const location = { file: "main.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
  assert.notEqual(exceptionIdentity(new AnalysisError({ code: "first", message: "same", location }), "/fixture").signature,
    exceptionIdentity(new AnalysisError({ code: "second", message: "same", location }), "/fixture").signature);
});
