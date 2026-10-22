import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";
import { branchProvenanceExpectation, checkBranchProvenance, renderBranchProvenanceCase, validateBranchProvenanceCase, type BranchProvenanceCase } from "./generative/provenance-branches.js";

const input: BranchProvenanceCase = { schemaVersion: "nightshade-branch-provenance-case-1", guardArm: true, invalidate: "before-copy", swapped: false };
const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
function withFacts(value: BranchProvenanceCase, check: (modes: AnalysisFacts[]) => void = () => {}) {
  withFiles({ "main.compact": renderBranchProvenanceCase(value) }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file);
    const modes = [];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, undefined, undefined, undefined, engine, cached, cached).analyze();
      const problem = checkBranchProvenance(value, facts);
      assert.equal(problem, undefined, JSON.stringify({ engine, cached, problem, paths: facts.paths.map(path => path.path) }));
      if (cached) assert.ok(facts.metrics.readSummaryHits > 0);
      else assert.equal(facts.metrics.summaryHits, 0);
      modes.push(facts);
    }
    assert.deepEqual(modes[0].paths, modes[1].paths);
    assert.deepEqual(modes[2].paths, modes[3].paths);
    for (const facts of modes.slice(1)) assert.deepEqual(semanticPaths(facts), semanticPaths(modes[0]));
    check(modes);
  });
}
const copy = (facts: AnalysisFacts): AnalysisFacts => ({ ...facts, paths: structuredClone(facts.paths), diagnostics: structuredClone(facts.diagnostics), completedEntries: [...facts.completedEntries], failedAssertions: structuredClone(facts.failedAssertions) });

test("branch property family validates its finite options and independently associates sources and guards with input", () => {
  assert.deepEqual(validateBranchProvenanceCase(input), input);
  assert.deepEqual(branchProvenanceExpectation(input, true).returned[0], [{ source: "first", form: "raw" }, { source: "flag", form: "derived" }]);
  assert.deepEqual(branchProvenanceExpectation(input, false).returned[0], [{ source: "second", form: "raw" }, { source: "flag", form: "derived" }]);
  const before = branchProvenanceExpectation(input, true);
  assert.deepEqual(before.writes.map(write => write.guarded), [false, false, false, true, true, true, false, false]);
  const source = renderBranchProvenanceCase(input);
  assert.equal(source.slice(before.writes[4].site.start, before.writes[4].site.end), "unrelated = 0 as Field");
  assert.notDeepEqual(before.writes[2].site, before.writes[4].site, "Repeated identical assignments have distinct source sites");
  assert.deepEqual(before.writes[3].site, before.writes[6].site, "Direct and nested calls identify the same helper assignment");
  assert.equal(source.slice(before.returnSite.start, before.returnSite.end), "return [current, saved, stored];");
  assert.deepEqual(before.writes[4].after, [{ source: "flag", form: "derived" }], "Structural control tags remain even on a constant overwrite; they do not assert information leakage");
  assert.deepEqual(branchProvenanceExpectation({ ...input, invalidate: "none" }, true).writes.map(write => write.guarded), [false, false, false, true, true, true, true]);
  for (const bad of [null, [], { ...input, source: "arbitrary" }, { ...input, guardArm: "true" }, { ...input, invalidate: "external-write" }, { ...input, swapped: 0 }]) assert.throws(() => validateBranchProvenanceCase(bad));
  const accessor = { ...input };
  Object.defineProperty(accessor, "guardArm", { get() { assert.fail("untrusted getter must not execute"); } });
  assert.throws(() => validateBranchProvenanceCase(accessor), /accessor/);
});

test("compiler-valid branch histories preserve exclusive private data, implicit control and branch-local guards", qualified, () => {
  for (const guardArm of [false, true]) for (const swapped of [false, true]) for (const invalidate of ["before-copy", "after-copy", "none"] as const) withFacts({ ...input, guardArm, swapped, invalidate });
});

test("independent branch properties reject unioned mutually exclusive sources and missing implicit control", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) for (const corruption of ["control", "union", "swap", "form"] as const) {
      const changed = copy(facts);
      const first = changed.paths[0].writes[3].after;
      const opposite = changed.paths[1].writes[3].after.flows.find(flow => flow.source.name !== "flag")!;
      if (corruption === "control") first.flows = first.flows.filter(flow => flow.source.name !== "flag");
      if (corruption === "union") first.flows.push(opposite);
      if (corruption === "swap") first.flows = first.flows.map(flow => flow.source.name === "flag" ? flow : opposite);
      if (corruption === "form") first.flows.find(flow => flow.source.name === "flag")!.form = "raw";
      assert.equal(checkBranchProvenance(input, changed)?.property, "provenance", corruption);
    }
    const sharedError = modes.map(facts => {
      const changed = copy(facts);
      changed.paths.forEach(path => { path.writes[3].after.flows = path.writes[3].after.flows.filter(flow => flow.source.name !== "flag"); });
      return changed;
    });
    assert.deepEqual(sharedError[0].paths, sharedError[1].paths);
    assert.deepEqual(sharedError[2].paths, sharedError[3].paths);
    sharedError.forEach(facts => assert.equal(checkBranchProvenance(input, facts)?.property, "provenance"));
  });
});

test("branch guard properties reject opposite-arm guards, premature loss and stale relevant-write guards", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const guard = [...facts.program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
      const guardedIndex = facts.paths.findIndex(path => path.path.some(step => step.kind === "branch" && step.label.endsWith("true")));
      const opposite = copy(facts);
      opposite.paths[1 - guardedIndex].writes[3].guards.push(guard);
      assert.equal(checkBranchProvenance(input, opposite)?.property, "guard");
      const lost = copy(facts);
      lost.paths[guardedIndex].writes[4].guards = lost.paths[guardedIndex].writes[4].guards.filter(id => id !== guard);
      assert.equal(checkBranchProvenance(input, lost)?.property, "guard");
      const stale = copy(facts);
      stale.paths[guardedIndex].writes[6].guards.push(guard);
      assert.equal(checkBranchProvenance(input, stale)?.property, "guard");
    }
  });
});

test("branch oracle detects changed input association, dropped histories and copied snapshots from the wrong arm", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      const relabeled = copy(facts);
      relabeled.paths.forEach(path => {
        const decision = path.path.find(step => step.kind === "branch")!;
        decision.label = decision.label.endsWith("true") ? "condition may be false" : "condition may be true";
      });
      assert.ok(checkBranchProvenance(input, relabeled), "identical relabeling across engines cannot change the oracle input association");
      const duplicated = copy(facts);
      duplicated.paths[1] = structuredClone(duplicated.paths[0]);
      assert.equal(checkBranchProvenance(input, duplicated)?.property, "input-coverage");
      const wrongSite = copy(facts);
      wrongSite.paths[0].path.find(step => step.kind === "branch")!.location.start++;
      assert.equal(checkBranchProvenance(input, wrongSite)?.property, "branch-origin");
      const wrongSnapshot = copy(facts);
      wrongSnapshot.paths[0].sinks.at(-1)!.value.items![1] = structuredClone(wrongSnapshot.paths[1].sinks.at(-1)!.value.items![1]);
      assert.equal(checkBranchProvenance(input, wrongSnapshot)?.property, "provenance");
      const refreshed = copy(facts);
      refreshed.paths[0].sinks.at(-1)!.value.items![1] = structuredClone(refreshed.paths[0].sinks.at(-1)!.value.items![2]);
      assert.equal(checkBranchProvenance(input, refreshed)?.property, "provenance");
      const missing = copy(facts);
      missing.paths.pop();
      assert.equal(checkBranchProvenance(input, missing)?.property, "path-count");
      const incomplete = copy(facts);
      incomplete.completedEntries = [];
      assert.equal(checkBranchProvenance(input, incomplete)?.property, "incomplete");
    }
  });
});

test("branch provenance property checking refuses actual path-budget exhaustion in every mode", qualified, () => {
  withFacts(input, ([complete]) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(complete.program, 20000, 1, 50000, engine, cached, cached).analyze();
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
      assert.equal(checkBranchProvenance(input, facts)?.property, "incomplete");
    }
  });
});

test("fixed assignment and export sites reject matching corrupted spans even when cached modes agree", qualified, () => {
  withFacts(input, modes => {
    for (const facts of modes) {
      for (let index = 0; index < facts.paths[0].writes.length; index++) {
        for (const field of ["file", "start", "end", "line", "column", "endLine", "endColumn"] as const) {
          const changed = copy(facts);
          const write = changed.paths[0].writes[index];
          const wrong = { ...write.location, [field]: field === "file" ? `${write.location.file}.wrong` : write.location[field] + 1 };
          write.location = wrong;
          changed.paths[0].sinks[index].location = { ...wrong };
          assert.equal(checkBranchProvenance(input, changed)?.property, "effect-site", `${index}/${field}`);
        }
      }
      const wrongOccurrence = copy(facts);
      wrongOccurrence.paths[0].writes[4].location = { ...wrongOccurrence.paths[0].writes[2].location };
      wrongOccurrence.paths[0].sinks[4].location = { ...wrongOccurrence.paths[0].writes[2].location };
      assert.equal(checkBranchProvenance(input, wrongOccurrence)?.property, "effect-site", "Same source text at another assignment is not the expected occurrence");
      for (const field of ["file", "start", "end", "line", "column", "endLine", "endColumn"] as const) {
        const changed = copy(facts);
        const returned = changed.paths[0].sinks.at(-1)!;
        returned.location = { ...returned.location, [field]: field === "file" ? `${returned.location.file}.wrong` : returned.location[field] + 1 };
        assert.equal(checkBranchProvenance(input, changed)?.property, "return-site", field);
      }
    }
    for (const kind of ["assignment", "return"] as const) {
      const equallyWrong = modes.map(facts => {
        const changed = copy(facts);
        if (kind === "assignment") {
          const wrong = { ...changed.paths[0].writes[3].location, start: 0 };
          changed.paths[0].writes[3].location = wrong;
          changed.paths[0].sinks[3].location = { ...wrong };
        } else changed.paths[0].sinks.at(-1)!.location = { ...changed.paths[0].sinks.at(-1)!.location, start: 0 };
        return changed;
      });
      assert.deepEqual(equallyWrong[0].paths, equallyWrong[1].paths);
      assert.deepEqual(equallyWrong[2].paths, equallyWrong[3].paths);
      equallyWrong.forEach(facts => assert.equal(checkBranchProvenance(input, facts)?.property, kind === "assignment" ? "effect-site" : "return-site"));
    }
  });
});
