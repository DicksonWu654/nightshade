import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { BranchMutationEligibility, MutationCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program } from "../src/index.js";
import { withFiles } from "./helpers.js";

const globals = "export ledger first: Field; export ledger second: Field; export ledger enabled: Boolean;";
function source(body: string, extra = ""): string {
  return `${globals} ${extra} circuit select(flag: Boolean, value: Field): [] { ${body} } export circuit entry(flag: Boolean, value: Field): [] { select(flag,value); }`;
}
function qualified(text: string, check: (program: Program, id: string) => void): void {
  withFiles({ "main.compact": text }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(path), helper = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    assert.ok(helper); check(program, helper.symbol.id);
  });
}

for (const [name, body, count] of [
  ["two arms", "if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); }", 2],
  ["empty false arm", "if (disclose(flag)) { first = disclose(value); }", 1],
  ["empty true arm", "if (disclose(flag)) {} else { first = disclose(value); }", 1],
  ["prefix and suffix", "first = default<Field>; if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); } enabled = false; return [];", 4],
  ["Boolean operand and ordinary named parameter pattern", "if (disclose(flag)) { enabled = disclose(flag); } else { enabled = false; }", 2],
  ["ordered repeated root writes", "if (disclose(flag)) { first = disclose(value); second = default<Field>; first = default<Field>; } else { second = disclose(value); }", 4],
] as const) test(`branch summary structural admission: ${name}`, () => qualified(source(body), (program, id) => {
  const eligibility = new BranchMutationEligibility(program), plan = eligibility.plan(id)!;
  assert.ok(plan); assert.equal(eligibility.allows(id), true); assert.strictEqual(eligibility.plan(id), plan);
  assert.equal(plan.assignments, count); assert.equal(plan.circuit, id);
  assert.equal(new MutationCircuitEligibility(program).allows(id), false, "The legacy linear recorder must remain ineligible");
  const fn = program.functions.get(id)!;
  for (const [graph, admitted] of [[fn.cfg, plan.expressions], [program.instructionCFG(id), plan.instructions]] as const) {
    assert.equal(admitted.conditionParameter, fn.declaration.parameters[0].symbol);
    assert.equal(admitted.controlUntil, graph.nodes[admitted.branch].join);
    assert.equal(admitted.suffix[0], admitted.convergence);
    assert.ok(admitted.whenTrue.every(node => !admitted.whenFalse.includes(node)));
    for (const arm of [admitted.whenTrue, admitted.whenFalse]) {
      const path = [...admitted.prefix, admitted.branch, ...arm, ...admitted.suffix];
      assert.equal(path[0], graph.entry); assert.equal(path.at(-1), graph.exit);
      for (let index = 1; index < path.length; index++) assert.ok(graph.nodes[path[index - 1]].edges.some(edge => edge.target === path[index]));
    }
    assert.ok(Object.isFrozen(admitted)); assert.ok(Object.isFrozen(admitted.whenTrue));
  }
  assert.ok(Object.isFrozen(plan));
  assert.equal(eligibility.allows(program.entries[0]), false);
}));

test("admission preserves actual abort-sensitive control lifetime beyond syntactic convergence", () => qualified(source("if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); } enabled = false;"), (program, id) => {
  const plan = new BranchMutationEligibility(program).plan(id)!;
  assert.ok(plan);
  for (const graph of [plan.expressions, plan.instructions]) {
    assert.equal(graph.controlUntil, -1);
    assert.notEqual(graph.convergence, graph.controlUntil);
  }
  const facts = new Dataflow(program).analyze();
  assert.deepEqual(facts.diagnostics, []);
  assert.ok(facts.paths.every(path => path.writes.at(-1)!.after.flows.some(flow => flow.source.name === "flag")));
  assert.equal(facts.metrics.statefulSummaryHits, 0, "Structural admission alone never enables summary replay");
}));

for (const [name, body, extra] of [
  ["no writes", "if (disclose(flag)) {} else {}", ""],
  ["no branch", "first = disclose(value);", ""],
  ["negated parameter", "if (disclose(!flag)) { first = disclose(value); }", ""],
  ["second diamond", "if (disclose(flag)) { first = disclose(value); } if (disclose(flag)) { second = disclose(value); }", ""],
  ["nested diamond", "if (disclose(flag)) { if (disclose(flag)) { first = disclose(value); } }", ""],
  ["local binding", "if (disclose(flag)) { const copy = value; first = disclose(copy); }", ""],
  ["assertion", 'if (disclose(flag)) { assert(true,"owned"); first = disclose(value); }', ""],
  ["storage-derived operand", "if (disclose(flag)) { first = second; }", ""],
  ["arithmetic operand", "if (disclose(flag)) { first = disclose(value + default<Field>); }", ""],
  ["ordinary nested call", "if (disclose(flag)) { put(value); }", "circuit put(value: Field): [] { first = disclose(value); }"],
  ["witness call", "if (disclose(flag)) { first = disclose(sample()); }", "witness sample(): Field;"],
  ["ordinary same-role condition helper", "if (choose(disclose(flag))) { first = disclose(value); }", "circuit choose(flag: Boolean): Boolean { return flag; }"],
  ["early return", "if (disclose(flag)) { return []; } else { first = disclose(value); }", ""],
  ["loop", "if (disclose(flag)) { for (const i of 0..2) { first = disclose(value); } }", ""],
  ["ADT mutation", "if (disclose(flag)) { counter.increment(1); }", "import CompactStandardLibrary; ledger counter: Counter;"],
] as const) test(`compiler-valid branch summary fallback: ${name}`, () => qualified(source(body, extra), (program, id) => {
  assert.equal(new BranchMutationEligibility(program).plan(id), undefined);
  const cached = new Dataflow(program).analyze(), expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
  assert.deepEqual(cached.diagnostics, expanded.diagnostics);
  assert.deepEqual(cached.paths, expanded.paths);
  assert.deepEqual(cached.completedEntries, expanded.completedEntries);
}));

test("destructured parameters remain outside the scalar helper boundary", () => qualified(`${globals} circuit select([flag,value]: [Boolean,Field]): [] { if (disclose(flag)) { first = disclose(value); } } export circuit entry(flag: Boolean,value: Field): [] { select([flag,value]); }`, (program, id) => {
  assert.equal(new BranchMutationEligibility(program).allows(id), false);
}));

test("admission work bounds refuse optimization without changing the ordinary analysis", () => qualified(source("if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); }"), (program, id) => {
  assert.equal(new BranchMutationEligibility(program, 1).allows(id), false);
  assert.equal(new BranchMutationEligibility(program, 4096).allows(id), true);
  const facts = new Dataflow(program).analyze(); assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 2);
  for (const bound of [0, -1, 4097, Infinity, 0.5]) assert.throws(() => new BranchMutationEligibility(program, bound));
  assert.equal(new BranchMutationEligibility(program).allows("not-a-circuit"), false);
}));

test("oversized structural input refuses before requesting an instruction CFG", () => {
  withFiles({ "main.compact": source(`if (disclose(flag)) { ${"first = disclose(value);".repeat(1100)} }`) }, directory => {
    const program = new Program(resolve(directory, "main.compact")), helper = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    program.instructionCFG = () => assert.fail("Eligibility must stop before instruction lowering when its structural work bound is exhausted");
    assert.equal(new BranchMutationEligibility(program).allows(helper.symbol.id), false);
  });
});


test("instruction lowering is reserved within the admission work budget", () => {
  withFiles({ "main.compact": source(`if (disclose(flag)) { ${"first = disclose(value);".repeat(250)} }`) }, directory => {
    const program = new Program(resolve(directory, "main.compact")), helper = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    program.instructionCFG = () => assert.fail("The remaining work cannot cover lowering and both routes");
    assert.equal(new BranchMutationEligibility(program).allows(helper.symbol.id), false);
  });
});
