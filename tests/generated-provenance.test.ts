import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";
import { checkProvenance } from "./generative/provenance-check.js";
import { expectedProvenance, generateProvenanceCase, renderProvenanceCase, validateProvenanceCase, type ProvenanceCase } from "./generative/provenance-model.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const input: ProvenanceCase = {
  schemaVersion: "nightshade-provenance-case-1", seed: 42, operations: [
    { kind: "put", value: "first", route: "nested" }, { kind: "snapshot" }, { kind: "guard" },
    { kind: "put", value: "second", route: "direct" }, { kind: "unrelated" },
    { kind: "put", value: "sum", route: "nested" }, { kind: "refresh" },
    { kind: "put", value: "first", route: "nested" }, { kind: "guard" },
    { kind: "put", value: "zero", route: "direct" }, { kind: "snapshot" }, { kind: "read" },
  ],
};

function withFacts(value: ProvenanceCase, check: (modes: AnalysisFacts[]) => void = () => {}): void {
  withFiles({ "main.compact": renderProvenanceCase(value) }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiler.valid, true, compiler.error);
    const program = new Program(file);
    const modes: AnalysisFacts[] = [];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, undefined, undefined, undefined, engine, cached, cached).analyze();
      assert.equal(checkProvenance(value, facts), undefined, JSON.stringify(checkProvenance(value, facts)));
      if (cached) assert.ok(facts.metrics.readSummaryHits > 0, "repeated nested reads must actually reuse summaries");
      else assert.equal(facts.metrics.summaryHits, 0);
      modes.push(facts);
    }
    assert.deepEqual(modes[0].paths, modes[1].paths);
    assert.deepEqual(modes[2].paths, modes[3].paths);
    for (const facts of modes.slice(1)) assert.deepEqual(semanticPaths(facts), semanticPaths(modes[0]));
    check(modes);
  });
}

function copy(facts: AnalysisFacts): AnalysisFacts {
  return { ...facts, diagnostics: structuredClone(facts.diagnostics), completedEntries: [...facts.completedEntries], paths: structuredClone(facts.paths), failedAssertions: structuredClone(facts.failedAssertions) };
}

test("independent linear provenance expectations retain source forms, snapshots and guard epochs", () => {
  const expected = expectedProvenance(input);
  assert.equal(expected.writes.length, 10);
  assert.deepEqual(expected.writes.map(write => write.guarded), [false, false, false, false, true, true, true, true, false, true]);
  assert.deepEqual(expected.checkpoints[3], [[{ source: "second", form: "raw" }], [{ source: "first", form: "raw" }], []]);
  assert.deepEqual(expected.checkpoints[9], [[], [{ source: "first", form: "raw" }], []]);
  assert.deepEqual(expected.checkpoints[10], [[], [], []]);
  expected.checkpoints[0][0][0].form = "derived";
  assert.equal(expected.checkpoints[1][0][0].form, "raw", "model checkpoint copies must not alias");
  assert.equal(expected.writes[3].after[0].form, "raw");
  assert.deepEqual(input.operations[0], { kind: "put", value: "first", route: "nested" });
});

test("owned provenance grammar is deterministic, bounded and rejects source or target injection", () => {
  for (const seed of [0, 1, 42, 0xffffffff]) {
    assert.deepEqual(generateProvenanceCase(seed, 12), generateProvenanceCase(seed, 12));
    assert.equal(generateProvenanceCase(seed, 12).operations.length, 12);
    assert.deepEqual(validateProvenanceCase(generateProvenanceCase(seed, 12)), generateProvenanceCase(seed, 12));
    assert.equal(renderProvenanceCase(generateProvenanceCase(seed, 12)), renderProvenanceCase(generateProvenanceCase(seed, 12)));
  }
  const empty = { ...input, operations: [] };
  assert.deepEqual(expectedProvenance(empty).checkpoints, [[[], [], []]]);
  assert.match(renderProvenanceCase(empty), /nestedRead\(\);\n  const checkpoint0 = \[nestedRead\(\), snapshot0, unrelated\];/);
  for (const bad of [null, [], { ...input, schemaVersion: "nightshade-generated-case-1" }, { ...input, source: "anything" }, { ...input, seed: -1 }, { ...input, seed: -0 }, { ...input, operations: Array(1) }, { ...input, operations: Array(13).fill({ kind: "read" }) }, { ...input, operations: [{ kind: "put", value: "first", route: "external" }] }, { ...input, operations: [{ kind: "put", value: "arbitrary source", route: "direct" }] }, { ...input, operations: [{ kind: "read", source: "anything" }] }]) assert.throws(() => validateProvenanceCase(bad));
  assert.throws(() => generateProvenanceCase(1, 13));
  assert.throws(() => generateProvenanceCase(NaN, 1));
  const accessor = { ...input };
  Object.defineProperty(accessor, "operations", { get() { assert.fail("untrusted accessor must not execute"); } });
  assert.throws(() => validateProvenanceCase(accessor), /data fields/);
});

test("compiler-grounded linear provenance grammar agrees with independent expectations in all four modes", qualified, () => {
  withFacts(input);
  withFacts({ ...input, operations: [] });
  for (const seed of [0, 42, 0xffffffff]) withFacts(generateProvenanceCase(seed, 12));
  withFacts({ ...input, operations: [
    { kind: "put", value: "first", route: "nested" },
    { kind: "put", value: "first", route: "nested" },
    { kind: "guard" }, { kind: "put", value: "first", route: "direct" },
  ] }, modes => assert.ok(modes.filter((_, index) => index % 2 === 0).every(facts => facts.metrics.statefulSummaryHits > 0)));
});

test("independent provenance oracle rejects missing, swapped, invented and changed-form flows shared by all engines", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) for (const corruption of ["missing", "swapped", "invented", "form"] as const) {
      const changed = copy(facts);
      const write = changed.paths[0].writes[3];
      const second = changed.paths[0].writes[4].after.flows[0];
      if (corruption === "missing") write.after.flows = [];
      if (corruption === "swapped") write.after.flows = [second];
      if (corruption === "invented") write.after.flows.push(second);
      if (corruption === "form") write.after.flows[0].form = "hash";
      assert.equal(checkProvenance(input, changed)?.property, "provenance", corruption);
    }
    // Corrupt both cached and uncached copies identically. Differential equality
    // alone remains green, while the separately computed property rejects both.
    const equallyWrong = modes.map(facts => {
      const changed = copy(facts);
      changed.paths[0].writes[3].after.flows = [];
      return changed;
    });
    assert.deepEqual(equallyWrong[0].paths, equallyWrong[1].paths);
    assert.deepEqual(equallyWrong[2].paths, equallyWrong[3].paths);
    equallyWrong.forEach(facts => assert.equal(checkProvenance(input, facts)?.property, "provenance"));
  });
});

test("independent provenance oracle rejects refreshed snapshots, stale strong updates and aggregate pollution", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const refreshed = copy(facts);
      const checkpoints = refreshed.paths[0].sinks.at(-1)!.value.items!;
      checkpoints[3].items![1] = structuredClone(checkpoints[3].items![0]);
      assert.deepEqual(checkProvenance(input, refreshed)?.field, "checkpoints/3/saved");
      const stale = copy(facts);
      stale.paths[0].writes[9].after.flows = structuredClone(stale.paths[0].writes[8].after.flows);
      assert.deepEqual(checkProvenance(input, stale)?.field, "writes/9/after");
      const polluted = copy(facts);
      polluted.paths[0].sinks.at(-1)!.value.items![11].flows = structuredClone(polluted.paths[0].writes[3].after.flows);
      assert.deepEqual(checkProvenance(input, polluted)?.field, "checkpoints/11");
      const clean = copy(facts);
      clean.paths[0].sinks.at(-1)!.value.items![0].items![2].flows = structuredClone(clean.paths[0].writes[3].after.flows);
      assert.deepEqual(checkProvenance(input, clean)?.field, "checkpoints/0/unrelated");
    }
  });
});

test("independent guard oracle rejects stale, missing and unrelated-write invalidations", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const guard = [...facts.program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
      for (const index of [4, 5, 6, 7, 9]) {
        const missing = copy(facts);
        missing.paths[0].writes[index].guards = missing.paths[0].writes[index].guards.filter(id => id !== guard);
        assert.equal(checkProvenance(input, missing)?.property, "guard", `missing guard at write ${index}`);
      }
      for (const index of [0, 3, 8]) {
        const stale = copy(facts);
        stale.paths[0].writes[index].guards.push(guard);
        assert.equal(checkProvenance(input, stale)?.property, "guard", `invented guard at write ${index}`);
      }
    }
  });
});

test("independent effect oracle rejects dropped, duplicated, reordered and incorrectly nested histories", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const missing = copy(facts);
      missing.paths[0].writes.splice(3, 1);
      assert.equal(checkProvenance(input, missing)?.property, "write-count");
      const duplicated = copy(facts);
      duplicated.paths[0].sinks.push(duplicated.paths[0].sinks[0]);
      assert.equal(checkProvenance(input, duplicated)?.property, "sink-count");
      const reordered = copy(facts);
      [reordered.paths[0].writes[4], reordered.paths[0].writes[5]] = [reordered.paths[0].writes[5], reordered.paths[0].writes[4]];
      assert.equal(checkProvenance(input, reordered)?.property, "write-order");
      const nested = copy(facts);
      nested.paths[0].writes[3].callPath.splice(1, 1);
      assert.equal(checkProvenance(input, nested)?.property, "call-path");
      const sinkOrder = copy(facts);
      [sinkOrder.paths[0].sinks[4], sinkOrder.paths[0].sinks[5]] = [sinkOrder.paths[0].sinks[5], sinkOrder.paths[0].sinks[4]];
      assert.equal(checkProvenance(input, sinkOrder)?.property, "sink-order");
      const origin = copy(facts);
      origin.paths[0].writes[3].after.flows[0].source.kind = "witness";
      assert.equal(checkProvenance(input, origin)?.property, "source-origin");
    }
  });
});

test("independent oracle refuses missing paths, unfinished analysis and spurious assertion failures", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const incomplete = copy(facts);
      incomplete.completedEntries = [];
      assert.equal(checkProvenance(input, incomplete)?.property, "incomplete");
      const missing = copy(facts);
      missing.paths = [];
      assert.equal(checkProvenance(input, missing)?.property, "path-count");
      const missingConstraint = copy(facts);
      missingConstraint.paths[0].path.pop();
      assert.equal(checkProvenance(input, missingConstraint)?.property, "unexpected-constraint");
      const wrongConstraint = copy(facts);
      wrongConstraint.paths[0].path[0].location.start++;
      assert.equal(checkProvenance(input, wrongConstraint)?.property, "unexpected-constraint");
      const wrongLabel = copy(facts);
      wrongLabel.paths[0].path[0].label = "invented branch";
      assert.equal(checkProvenance(input, wrongLabel)?.property, "unexpected-constraint");
      const failed = copy(facts);
      failed.failedAssertions.push({ location: facts.program.rootSource.ast.span, condition: { flows: [], ledger: new Set(), constantKind: "boolean", constant: "false" }, message: "invented failure", callPath: [facts.program.entries[0]], path: [] });
      assert.equal(checkProvenance(input, failed)?.property, "unexpected-failure");
    }
  });
});

test("compiler-valid provenance fixtures with exhausted analysis budgets remain explicitly incomplete", qualified, () => {
  withFacts(input, ([complete]) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      for (const [maxSteps, maxValues] of [[1, 50000], [20000, 1]]) {
        const exhausted = new Dataflow(complete.program, maxSteps, 256, maxValues, engine, cached, cached).analyze();
        assert.ok(exhausted.diagnostics.some(diagnostic => diagnostic.code === (maxSteps === 1 ? "analysis-budget" : "value-budget")));
        assert.deepEqual(exhausted.completedEntries, []);
        assert.equal(checkProvenance(input, exhausted)?.property, "incomplete");
      }
    }
  });
});
