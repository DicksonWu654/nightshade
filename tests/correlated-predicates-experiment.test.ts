import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, type SuccessfulPath } from "../src/dataflow/index.js";
import type { Span } from "../src/model.js";
import { Program } from "../src/semantic/index.js";
import { construct, project, type Graph, type Input, type Op, type Observation } from "./experiments/correlated-predicates.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const ref = (name: string): Input => ({ ref: name });
const integer = (n: number): Input => ({ constant: { kind: "integer", value: String(n) } });
const compare = (left: Input, operator: "==" | "!=", right: Input): Input => ({ left, operator, right });
function fixture(source: string, run: (program: Program, at: (text: string, after?: number) => Span) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiler = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiler.valid, true, compiler.error);
    run(new Program(file), (text, after = 0) => {
      const start = source.indexOf(text, after); assert.ok(start >= 0, text); const end = start + text.length;
      return { file, start, end, line: source.slice(0, start).split("\n").length, column: start - source.lastIndexOf("\n", start - 1), endLine: source.slice(0, end).split("\n").length, endColumn: end - source.lastIndexOf("\n", end - 1) };
    });
  });
}
function built(parameters: string[], roots: string[], operations: Op[], indexed = false): Graph {
  const result = construct(parameters, roots, operations, {}, indexed); if (result.status !== "complete") assert.fail(JSON.stringify(result));
  assert.ok(result.graph.work.steps <= 20000 && result.graph.work.frames <= 256 && result.graph.work.nodes <= 50000);
  return result.graph;
}
function writes(program: Program, path: SuccessfulPath): Observation[] {
  const key = (value: { constant?: string; constantKind?: string }) => value.constantKind && value.constant !== undefined ? `${value.constantKind}:${value.constant}` : undefined;
  return path.writes.map(write => ({ root: program.symbols.get(write.ledger)!.name, before: key(write.before), after: key(write.after), excludedBefore: [...write.excludedBefore].sort(), dependencies: [...new Set(write.after.flows.map(flow => flow.source.name))].sort(), location: write.location }));
}

test("whole constraint-map experiment constructs ten independent Field comparisons without history expansion", qualified, t => {
  const parameters = Array.from({ length: 10 }, (_, index) => `value${index}`);
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${parameters.map(name => `${name}: Field`).join(",")}): [] { ${parameters.map(name => `if (disclose(${name}) == (0 as Field)) { count.increment(1); }`).join(" ")} }`;
  fixture(source, (program, at) => {
    assert.ok(program.functions.get(program.entries[0])!.cfg.nodes.filter(node => node.kind === "branch").every(node => node.join === -1), "Manual experiment retains only CFG-qualified abort-sensitive control");
    const ops: Op[] = parameters.map(name => ({ kind: "branch", name, condition: compare(ref(name), "==", integer(0)), yes: [{ kind: "increment", root: "count", location: at("count.increment(1)", source.indexOf(`if (disclose(${name})`)) }], no: [] }));
    const exact = new Dataflow(program, 20000, 2048, 50000).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 1024);
    for (const indexed of [false, true]) {
    const graph = built(parameters, ["count"], ops, indexed);
    let maximum = 0;
    for (const path of exact.paths) {
      const decisions = Object.fromEntries(path.path.filter(step => step.kind === "branch").map((step, index) => [parameters[index], step.label.endsWith("true")]));
      const selected = project(graph, decisions); if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(selected.writes, writes(program, path)); maximum = Math.max(maximum, selected.work);
    }
    const decisions = Object.fromEntries(parameters.map(name => [name, true]));
    const demand = parameters.map(name => ({ name, ...project(graph, decisions, name) }));
    assert.ok(demand.every(item => item.status === "selected"));
    assert.equal(demand.at(-1)!.choices.length, indexed ? 0 : 9, "Support indexing only skips provably untouched original inputs");
    t.diagnostic(JSON.stringify({ indexed, construction: graph.work, reference: exact.metrics, maxProjection: maximum, independentConditionDemand: demand.map(item => ({ name: item.name, work: item.work, terms: item.terms, priorChoices: item.choices.length })) }));
    for (const limits of [{ maxSteps: 1 }, { maxFrames: 1 }, { maxNodes: 1 }]) assert.equal(construct(parameters, ["count"], ops, limits, indexed).status, "incomplete");
    if (indexed) for (const limits of [{ maxSteps: graph.work.steps - 1 }, { maxNodes: graph.work.nodes - 1 }]) {
      assert.equal(construct(parameters, ["count"], ops, limits, true).status, "incomplete", "Support-index work and allocations consume the shared allowance");
    }
    assert.equal(project(graph, decisions, undefined, 1).status, "incomplete");
    }
  });
});

test("whole constraint maps preserve snapshots, negation and reversed comparisons across a common suffix", qualified, t => {
  for (const negated of [false, true]) {
  const source = `export ledger state: Field; export ledger seen: Field;
export circuit entry(input: Field, replacement: Field): [] {
  state = disclose(input); const old = state;
  if (disclose(old == (1 as Field))) {
    state = disclose(replacement);
    if (disclose(${negated ? "!(old == (1 as Field))" : "old != (1 as Field)"})) { seen = 99 as Field; }
    if (disclose(state != (1 as Field))) { seen = state; }
  } else {
    state = 1 as Field;
    if (disclose(state == (1 as Field))) { seen = old; }
  }
  if (disclose(${negated ? "(1 as Field) == old" : "old == (1 as Field)"})) { seen = disclose(replacement); }
}`;
  fixture(source, (program, at) => {
    const write = (root: string, value: Input, text: string): Op => ({ kind: "write", root, value, location: at(text) });
    const eq = (name: string): Input => compare(ref(name), "==", integer(1));
    const ops: Op[] = [write("state", ref("input"), "state = disclose(input)"), { kind: "bind", name: "old", value: ref("state") },
      { kind: "branch", name: "outer", condition: eq("old"), no: [write("state", integer(1), "state = 1 as Field"),
        { kind: "branch", name: "overwritten", condition: eq("state"), yes: [write("seen", ref("old"), "seen = old")], no: [] }], yes: [
        write("state", ref("replacement"), "state = disclose(replacement)"),
        { kind: "branch", name: "contradiction", condition: negated ? { not: eq("old") } : compare(ref("old"), "!=", integer(1)), yes: [write("seen", integer(99), "seen = 99 as Field")], no: [] },
        { kind: "branch", name: "fresh", condition: compare(ref("state"), "!=", integer(1)), yes: [write("seen", ref("state"), "seen = state")], no: [] },
      ] },
      { kind: "branch", name: "suffix", condition: negated ? compare(integer(1), "==", ref("old")) : eq("old"), yes: [write("seen", ref("replacement"), "seen = disclose(replacement)")], no: [] },
    ];
    for (const indexed of [false, true]) {
    const graph = built(["input", "replacement"], ["state", "seen"], ops, indexed), observed = new Map<string, Observation[]>();
    for (let bits = 0; bits < 1 << graph.choices.length; bits++) {
      const decisions = Object.fromEntries(graph.choices.map((name, index) => [name, Boolean(bits & 1 << index)]));
      const selected = project(graph, decisions); assert.notEqual(selected.status, "incomplete");
      if (selected.status !== "selected") continue;
      assert.equal(decisions.contradiction && decisions.outer, false);
      assert.equal(decisions.suffix, decisions.outer);
      assert.ok(selected.writes.every(write => write.after !== "integer:99"));
      observed.set(JSON.stringify(selected.writes), selected.writes);
    }
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze(); assert.deepEqual(exact.diagnostics, []);
      const expected = new Set(exact.paths.map(path => JSON.stringify(writes(program, path))));
      assert.deepEqual(new Set(observed.keys()), expected, `${engine}/${cached}`);
    }
    assert.equal(observed.size, 3);
    t.diagnostic(JSON.stringify({ indexed, negatedAndReversed: negated, construction: graph.work, distinctReducedSuccessfulHistories: observed.size }));
    }
  });
  }
});
