import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { Dataflow, type AbstractValue, type SuccessfulPath } from "../src/dataflow/index.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import type { Span } from "../src/model.js";
import { withFiles } from "./helpers.js";
import { construct, eager, LIMITS, select, value, type Graph, type Op, type SelectedEvent, type Value } from "./experiments/correlated-state.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const names = (input: AbstractValue): readonly string[] => [...new Set(input.flows.map(flow => flow.source.name))].sort();
const abstract = (input: AbstractValue): Value => value(input.constant, names(input));
function span(source: string, file: string, text: string, after = 0): Span {
  const start = source.indexOf(text, after); assert.ok(start >= 0, text);
  const end = start + text.length;
  return { file, start, end, line: source.slice(0, start).split("\n").length, column: start - source.lastIndexOf("\n", start - 1), endLine: source.slice(0, end).split("\n").length, endColumn: end - source.lastIndexOf("\n", end - 1) };
}
function fixture(source: string, run: (program: Program, at: (text: string, after?: number) => Span) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(compiled.valid, true, compiled.error);
    run(new Program(file), (text, after = 0) => span(source, file, text, after));
  });
}
function built(initial: Record<string, Value>, ops: Op[]): Graph {
  const result = construct(initial, ops);
  if (result.status !== "complete") throw new Error(result.diagnostic);
  assert.ok(result.graph.work.steps <= LIMITS.maxSteps && result.graph.work.nodes <= LIMITS.maxNodes && result.graph.work.frames <= LIMITS.maxFrames);
  return result.graph;
}
function normalizedWrites(path: SuccessfulPath, program: Program) {
  return path.writes.map(write => ({ kind: "write" as const, root: program.symbols.get(write.ledger)!.name, before: abstract(write.before), after: abstract(write.after), guards: write.guards.map(id => program.symbols.get(id)!.name).sort(), location: write.location }));
}
function retainedBranches(program: Program, count: number): void {
  for (const graph of [program.instructionCFG(program.entries[0]), program.functions.get(program.entries[0])!.cfg]) {
    const branches = graph.nodes.filter(node => node.kind === "branch");
    assert.equal(branches.length, count);
    assert.ok(branches.every(node => node.join === -1), "Both actual CFGs must justify retained abort-sensitive control in the owned grammar");
  }
}
const selectedWrites = (events: SelectedEvent[]) => events.filter((event): event is Extract<SelectedEvent, { kind: "write" }> => event.kind === "write");
function conservative(graph: Graph, paths: SelectedEvent[][]): void {
  for (const write of eager(graph).writes) {
    const executions = paths.flatMap(events => selectedWrites(events).filter(event => event.location.start === write.location.start));
    assert.ok(executions.length);
    for (const observed of executions) {
      for (const dependency of observed.before.dependencies) assert.ok(write.before.dependencies.includes(dependency));
      for (const dependency of observed.after.dependencies) assert.ok(write.after.dependencies.includes(dependency));
      for (const guard of write.guards) assert.ok(observed.guards.includes(guard), "May-guard must never be promoted to a must-guard");
    }
  }
}

test("factored current state constructs the unchanged ten-choice workload and agrees with every ordinary selected witness", qualified, () => {
  const size = 10;
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  // Pin the original workload independently of external benchmark results.
  assert.equal(createHash("sha256").update(source).digest("hex"), "842ba6df0df0b6c1e85c9c6e52f4e2f26105f271f796cf64399048bec57a1039", "Preserve exact ten-choice workload bytes");
  fixture(source, (program, at) => {
    retainedBranches(program, size);
    const ops: Op[] = Array.from({ length: size }, (_, index) => ({ kind: "branch", choice: `flag${index}`, retainControl: true, no: [], yes: [{ kind: "increment", root: "count", amount: 1, location: at("count.increment(1)", source.indexOf(`if (disclose(flag${index}))`)) }] }));
    const graph = built({ count: value() }, ops);
    assert.equal(graph.work.transfers, 20, "Each syntactic branch and increment transfers once");
    assert.equal(graph.work.frames, 21, "Two syntactic arms per diamond, never 1,024 assignment states");
    assert.ok(graph.work.nodes < 200 && graph.work.steps < 300);
    assert.deepEqual(eager(graph).roots.count.dependencies, Array.from({ length: size }, (_, i) => `flag${i}`));
    const flow = new Dataflow(program, 20000, 256, 50000);
    const ordinary = flow.analyze();
    assert.ok(ordinary.diagnostics.some(item => item.code === "analysis-budget")); assert.deepEqual(ordinary.completedEntries, []);
    const observations: SelectedEvent[][] = [];
    for (let bits = 0; bits < 1024; bits++) {
      const decisions = Array.from({ length: size }, (_, index) => Boolean(bits & (1 << index)));
      const projected = select(graph, Object.fromEntries(decisions.map((chosen, index) => [`flag${index}`, chosen])));
      const witness = flow.selectCounterWitness(program.entries[0], decisions);
      assert.equal(projected.status, "selected"); assert.equal(witness.status, "selected");
      if (projected.status !== "selected" || witness.status !== "selected") throw new Error("Missing selected oracle evidence");
      assert.deepEqual(projected.events, normalizedWrites(witness.path, program)); observations.push(projected.events);
      assert.deepEqual(projected.roots!.count, projected.events.length ? selectedWrites(projected.events).at(-1)!.after : value());
      assert.equal(witness.metrics.paths, 1); assert.ok(projected.work < 1000);
    }
    conservative(graph, observations);
    assert.equal(graph.work.transfers, 20, "Selection cannot execute or mutate joined-state construction");
    assert.ok(flow.analyze().diagnostics.some(item => item.code === "analysis-budget"), "Test enumeration does not complete scanner coverage");
  });
});

const mixed = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger first: Field;
export ledger second: Field;
circuit guard(): Field { return first; }
export circuit entry(flag: Boolean, invalidate: Boolean, x: Field, y: Field): [Field,Field] {
  const initial = guard();
  if (disclose(flag)) {
    first = disclose(x); second = disclose(y);
    const saved = guard();
  } else { first = disclose(y); second = disclose(x); }
  if (disclose(invalidate)) { first = second; }
  else { second = first; }
  first = second;
  second = first;
  return [first,second];
}
`;
test("mixed current values, conditional guards and shared suffix writes retain joint correlation", qualified, () => {
  fixture(mixed, (program, at) => {
    retainedBranches(program, 2);
    const assign = (text: string, root: string, input: Value | { root: string }, after = 0): Op => ({ kind: "write", root, value: input, location: at(text, after) });
    const operations = (concrete: boolean): Op[] => [
      { kind: "guard", name: "guard", reads: ["first"] },
      { kind: "branch", choice: "flag", retainControl: true,
        yes: [assign("first = disclose(x)", "first", value(concrete ? "11" : undefined, ["x"])), assign("second = disclose(y)", "second", value(concrete ? "29" : undefined, ["y"])), { kind: "guard", name: "guard", reads: ["first"] }],
        no: [assign("first = disclose(y)", "first", value(concrete ? "29" : undefined, ["y"])), assign("second = disclose(x)", "second", value(concrete ? "11" : undefined, ["x"]))] },
      { kind: "branch", choice: "invalidate", retainControl: true, yes: [assign("first = second", "first", { root: "second" })], no: [assign("second = first", "second", { root: "first" })] },
      assign("first = second", "first", { root: "second" }, mixed.indexOf("  first = second;")),
      assign("second = first", "second", { root: "first" }, mixed.indexOf("  second = first;")),
      { kind: "publish", values: [{ root: "first" }, { root: "second" }], location: at("return [first,second];") },
    ];
    const graph = built({ first: value(), second: value() }, operations(false));
    const concrete = built({ first: value(), second: value() }, operations(true));
    assert.equal(graph.work.frames, 5); assert.equal(graph.work.transfers, 13);
    const observations: SelectedEvent[][] = [];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const ordinary = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(ordinary.diagnostics, []); assert.equal(ordinary.paths.length, 4);
      for (const path of ordinary.paths) {
        const branches = path.path.filter(step => step.kind === "branch").map(step => step.label.endsWith("true"));
        assert.equal(branches.length, 2);
        const decisions = { flag: branches[0], invalidate: branches[1] };
        const projected = select(graph, decisions), exact = select(concrete, decisions);
        assert.equal(projected.status, "selected"); assert.equal(exact.status, "selected");
        if (projected.status !== "selected" || exact.status !== "selected") throw new Error("Missing mixed selection");
        assert.deepEqual(selectedWrites(projected.events), normalizedWrites(path, program));
        const publication = projected.events.at(-1)!; assert.equal(publication.kind, "publish");
        if (publication.kind !== "publish") throw new Error("Missing publication");
        assert.deepEqual(publication.values, path.sinks.at(-1)!.value.items!.map(abstract));
        assert.deepEqual(publication.location, path.sinks.at(-1)!.location);
        const expected = decisions.flag !== decisions.invalidate ? "11" : "29";
        assert.deepEqual([exact.roots!.first.constant, exact.roots!.second.constant], [expected, expected], "Independent per-root arm selection would fabricate impossible pairs");
        const writes = selectedWrites(projected.events);
        assert.deepEqual(writes[2].guards, decisions.flag ? ["guard"] : []);
        assert.deepEqual(writes[3].guards, decisions.flag && !decisions.invalidate ? ["guard"] : []);
        assert.deepEqual(writes[4].guards, []); observations.push(projected.events);
      }
    }
    conservative(graph, observations);
    assert.deepEqual(eager(graph).guards, []);
    const views = eager(graph).writes;
    assert.deepEqual(views.filter(write => write.location.start === at("first = disclose(x)").start || write.location.start === at("first = disclose(y)").start).map(write => write.guards), [["guard"], ["guard"]]);
    assert.ok(views.filter(write => write.location.start >= mixed.indexOf("  if (disclose(invalidate))")).every(write => write.guards.length === 0), "Conditional completion is not unconditional authorization");
  });
});

test("scalar and Counter tuples share one choice; selected rejection retains no successful suffix", qualified, () => {
  const source = `import CompactStandardLibrary; export ledger first: Field; export ledger second: Field; export ledger count: Counter;
export circuit entry(flag: Boolean, stop: Boolean): [Field,Field,Uint<64>] {
 first = 3 as Field; second = 7 as Field; count.resetToDefault();
 if (disclose(flag)) { first = 11 as Field; count.increment(2); } else { second = 13 as Field; count.increment(5); }
 if (disclose(stop)) { assert(false,"selected rejection"); }
 return [first,second,count.read()];
}`;
  fixture(source, (program, at) => {
    retainedBranches(program, 2);
    const write = (root: string, constant: string): Op => ({ kind: "write", root, value: value(constant), location: at(`${root} = ${constant} as Field`) });
    const graph = built({ first: value(), second: value(), count: value() }, [write("first", "3"), write("second", "7"), { kind: "write", root: "count", value: value("0"), location: at("count.resetToDefault()") },
      { kind: "branch", choice: "flag", retainControl: true, yes: [write("first", "11"), { kind: "increment", root: "count", amount: 2, location: at("count.increment(2)") }], no: [write("second", "13"), { kind: "increment", root: "count", amount: 5, location: at("count.increment(5)") }] },
      { kind: "branch", choice: "stop", retainControl: true, yes: [{ kind: "reject", location: at('assert(false,"selected rejection")') }], no: [] },
      { kind: "publish", values: [{ root: "first" }, { root: "second" }, { root: "count" }], location: at("return [first,second,count.read()];") }]);
    const ordinary = new Dataflow(program).analyze();
    assert.deepEqual(ordinary.diagnostics, []); assert.equal(ordinary.paths.length, 2); assert.equal(ordinary.failedAssertions.length, 2);
    for (const flag of [false, true]) {
      const projected = select(graph, { flag, stop: false }); assert.equal(projected.status, "selected");
      if (projected.status !== "selected") throw new Error("Missing tuple");
      const path = ordinary.paths.find(path => path.path[0].label.endsWith(String(flag)))!;
      assert.deepEqual(selectedWrites(projected.events), normalizedWrites(path, program));
      const publication = projected.events.at(-1)!; assert.equal(publication.kind, "publish");
      if (publication.kind !== "publish") throw new Error("Missing tuple publication");
      assert.deepEqual(publication.values, path.sinks.at(-1)!.value.items!.map(abstract));
      assert.deepEqual(publication.values.map(item => item.constant), flag ? ["11", "7", "2"] : ["3", "13", "5"]);
      assert.ok(publication.values.every(item => item.dependencies.includes("stop")));
      const rejected = select(graph, { flag, stop: true }); assert.equal(rejected.status, "rejected");
      if (rejected.status !== "rejected") throw new Error("Missing rejection");
      assert.equal(rejected.roots, undefined); assert.ok(rejected.events.every(event => event.kind !== "publish"));
      assert.deepEqual(rejected.events.at(-1)!.location, ordinary.failedAssertions.find(failure => failure.path[0].label.endsWith(String(flag)))!.location);
    }
  });
});

test("construction and projection exhaustion stay incomplete; unsupported effects never produce a graph", () => {
  const location: Span = { file: "owned.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
  const ops: Op[] = [{ kind: "branch", choice: "flag", retainControl: false, yes: [{ kind: "write", root: "a", value: value("1"), location }], no: [] }];
  for (const limit of ["maxSteps", "maxNodes", "maxFrames"] as const) {
    const result = construct({ a: value() }, ops, { [limit]: 1 }); assert.equal(result.status, "incomplete"); assert.equal("graph" in result, false);
  }
  const graph = built({ a: value() }, ops);
  const projected = select(graph, { flag: true }, 1); assert.equal(projected.status, "incomplete"); assert.equal("events" in projected, false);
  assert.equal(construct({ a: value() }, [{ kind: "increment", root: "a", amount: 65536, location }]).status, "incomplete");
  assert.equal(construct({ a: value() }, [{ kind: "unknown" } as unknown as Op]).status, "incomplete");
  assert.throws(() => select(graph, {}));
  assert.throws(() => construct({ a: value() }, ops, { maxNodes: NaN }));
});

test("immutable Counter operands and deferred unsupported overflow cannot become selected success", () => {
  const location: Span = { file: "owned.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
  const increment: Op & { kind: "increment" } = { kind: "increment", root: "count", amount: 1, location };
  const graph = built({ count: value("0") }, [increment]); increment.amount = 9;
  const selected = select(graph, {}); assert.equal(selected.status, "selected");
  if (selected.status !== "selected") throw new Error("Missing Counter selection");
  assert.equal(selected.roots!.count.constant, "1"); assert.equal(eager(graph).roots.count.constant, "1");
  const joined = built({ count: value("0") }, [{ kind: "branch", choice: "flag", retainControl: false, yes: [{ kind: "write", root: "count", value: value(((1n << 64n) - 1n).toString()), location }], no: [] }, { ...increment, amount: 1 }]);
  assert.equal(select(joined, { flag: false }).status, "selected");
  const overflow = select(joined, { flag: true }); assert.equal(overflow.status, "incomplete"); assert.equal("events" in overflow, false);
});
