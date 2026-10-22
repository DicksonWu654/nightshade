import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, type AbstractValue, type SuccessfulPath } from "../src/dataflow/index.js";
import { analyzeCorrelatedEntry } from "../src/dataflow/correlated.js";
import { queryCorrelatedGraph, type CorrelatedPredicate } from "../src/dataflow/correlated-queries.js";
import { Program } from "../src/semantic/index.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const key = (value: AbstractValue): string | undefined => value.constant !== undefined && value.constantKind ? `${value.constantKind}:${value.constant}` : undefined;
function matches(path: SuccessfulPath, predicate: CorrelatedPredicate): { index: number; location: number }[] {
  if (predicate.kind === "public-flow") return path.sinks.flatMap((sink, index) => sink.value.flows.some(flow => flow.source.symbol === predicate.source && predicate.forms.includes(flow.form)) ? [{ index, location: sink.location.start }] : []);
  return path.writes.flatMap((write, index) => {
    if (write.ledger !== predicate.ledger) return [];
    if (predicate.kind === "missing-guard") return write.guards.includes(predicate.guard) ? [] : [{ index, location: write.location.start }];
    const before = key(write.before), after = key(write.after);
    return (predicate.from === "*" || (before === undefined || before === predicate.from) && !write.excludedBefore.includes(predicate.from))
      && (predicate.to === "*" || after === undefined || after === predicate.to) ? [{ index, location: write.location.start }] : [];
  });
}
function fixture(source: string, predicates: (program: Program) => CorrelatedPredicate[], check?: (result: Extract<ReturnType<typeof queryCorrelatedGraph>, { status: "complete" }>, program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file), construction = analyzeCorrelatedEntry(program, program.entries[0]);
    if (construction.status !== "complete") assert.fail(JSON.stringify(construction));
    const requested = predicates(program), result = queryCorrelatedGraph(construction.graph, requested);
    if (result.status !== "complete") assert.fail(JSON.stringify(result));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      for (const [index, predicate] of requested.entries()) {
        const expected = new Set(exact.paths.flatMap(path => matches(path, predicate).map(match => match.location)));
        const observed: number[] = result.evidence.filter(item => item.predicate === index).map(item => {
          const witness = result.witnesses[item.witness], matched = matches(witness.path, predicate).find(match => match.index === item.eventIndex);
          assert.ok(matched, "Every reported observation must hold on its complete successful witness");
          assert.ok(exact.paths.some(path => JSON.stringify(path.path) === JSON.stringify(witness.path.path)), "Witness branch history must survive ordinary analysis");
          return matched.location;
        });
        assert.deepEqual(new Set(observed), expected, `${engine}/${cached}/${predicate.kind}`);
        assert.equal(result.absent.includes(index), expected.size === 0);
      }
    }
    check?.(result, program);
  });
}
function symbol(program: Program, name: string): string {
  const found = [...program.symbols.values()].filter(symbol => symbol.name === name && ["ledger", "parameter", "circuit"].includes(symbol.kind));
  assert.equal(found.length, 1, name); return found[0].id;
}

test("paired transition queries never combine the before and after of exclusive histories", qualified, () => {
  fixture(`export ledger first: Field; export ledger second: Field;
export circuit entry(flag: Boolean): [] {
  if (disclose(flag)) { first = 0 as Field; second = 1 as Field; }
  else { first = 2 as Field; second = 3 as Field; }
  first = second;
}`, program => [
    { kind: "transition", ledger: symbol(program, "first"), from: "integer:0", to: "integer:3" },
    { kind: "transition", ledger: symbol(program, "first"), from: "integer:2", to: "integer:3" },
  ], result => { assert.deepEqual(result.absent, [0]); assert.ok(result.evidence.some(item => item.predicate === 1)); });
});

test("scalar inequality constraints rule out excluded before-values without discarding possible transitions", qualified, () => {
  fixture(`export ledger first: Field;
export circuit entry(): [] {
  const old = first;
  if (old != (1 as Field)) { first = 2 as Field; }
}`, program => [
    { kind: "transition", ledger: symbol(program, "first"), from: "integer:1", to: "integer:2" },
    { kind: "transition", ledger: symbol(program, "first"), from: "integer:3", to: "integer:2" },
  ], result => { assert.deepEqual(result.absent, [0]); assert.ok(result.evidence.some(item => item.predicate === 1)); });
});

test("conditional guard completion and invalidation queries retain real missing-guard witnesses", qualified, () => {
  fixture(`export ledger first: Field; export ledger second: Field;
circuit guard(): [] { const read = first; }
export circuit entry(flag: Boolean, invalidate: Boolean, x: Field, y: Field): [] {
  if (disclose(flag)) { first = disclose(x); guard(); }
  else { first = disclose(y); }
  if (disclose(invalidate)) { first = 0 as Field; }
  second = first;
}`, program => [
    { kind: "missing-guard", ledger: symbol(program, "second"), guard: symbol(program, "guard") },
    { kind: "public-flow", source: symbol(program, "x"), forms: ["raw", "derived"] },
    { kind: "public-flow", source: symbol(program, "y"), forms: ["raw", "derived"] },
  ]);
});

test("publication preceding definite Counter rejection never establishes successful evidence", qualified, () => {
  fixture(`import CompactStandardLibrary; export ledger count: Counter; export ledger first: Field;
export circuit entry(flag: Boolean, x: Field): [] {
  count.resetToDefault();
  if (disclose(flag)) { first = disclose(x); count.decrement(1); }
  else { first = 3 as Field; }
}`, program => [{ kind: "public-flow", source: symbol(program, "x"), forms: ["raw", "derived"] }], result => {
    assert.deepEqual(result.absent, [0]); assert.deepEqual(result.evidence, []);
  });
});

test("rejecting suffix absence is proved without enumerating unrelated earlier choices", qualified, () => {
  const size = 9;
  const source = `import CompactStandardLibrary; export ledger count: Counter; export ledger first: Field; export ledger scratch: Field;
export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}, stop: Boolean, x: Field): [] {
  count.resetToDefault();
  ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { scratch = ${index} as Field; }`).join("\n")}
  if (disclose(stop)) { first = disclose(x); count.decrement(1); }
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file), construction = analyzeCorrelatedEntry(program, program.entries[0]);
    if (construction.status !== "complete") assert.fail(JSON.stringify(construction));
    const result = queryCorrelatedGraph(construction.graph, [{ kind: "public-flow", source: symbol(program, "x"), forms: ["raw", "derived"] }], {
      maxWork: 20000 - construction.graph.work.steps, maxValues: 50000 - construction.graph.work.values, maxWitnesses: 256,
    });
    if (result.status !== "complete") assert.fail(JSON.stringify(result));
    assert.deepEqual(result.absent, [0]); assert.deepEqual(result.evidence, []);
    assert.ok(result.work.witnesses <= 2, "Only stop determines rejection; earlier choices must not require whole-path expansion");
  });
});

test("late correlated transition choices take precedence over unrelated earlier histories", qualified, () => {
  const source = `export ledger first: Field; export ledger second: Field; export ledger scratch: Field;
export circuit entry(${Array.from({ length: 9 }, (_, index) => `flag${index}: Boolean`).join(",")}, selected: Boolean): [] {
  ${Array.from({ length: 9 }, (_, index) => `if (disclose(flag${index})) { scratch = ${index} as Field; }`).join("\n")}
  if (disclose(selected)) { first = 0 as Field; second = 1 as Field; }
  else { first = 2 as Field; second = 3 as Field; }
  first = second;
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file), construction = analyzeCorrelatedEntry(program, program.entries[0]);
    if (construction.status !== "complete") assert.fail(JSON.stringify(construction));
    const result = queryCorrelatedGraph(construction.graph, [{ kind: "transition", ledger: symbol(program, "first"), from: "integer:0", to: "integer:3" }], {
      maxWork: 20000 - construction.graph.work.steps, maxValues: 50000 - construction.graph.work.values, maxWitnesses: 256,
    });
    if (result.status !== "complete") assert.fail(JSON.stringify(result));
    assert.deepEqual(result.absent, [0]); assert.deepEqual(result.evidence, []);
    assert.ok(result.work.witnesses <= 2, "Earlier scratch writes cannot influence the queried transition tuple");
  });
});

test("construction-only no-policy coverage requires no expanded whole histories; predicate exhaustion is explicit", qualified, () => {
  const n = 10;
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: n }, (_, i) => `flag${i}: Boolean`).join(",")}): [] { ${Array.from({ length: n }, (_, i) => `if (disclose(flag${i})) { count.increment(1); }`).join(" ")} }`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file), construction = analyzeCorrelatedEntry(program, program.entries[0]);
    if (construction.status !== "complete") assert.fail(JSON.stringify(construction));
    const graph = construction.graph, none = queryCorrelatedGraph(graph, []);
    if (none.status !== "complete") assert.fail(JSON.stringify(none));
    assert.deepEqual(none.witnesses, []);
    assert.deepEqual([...none.structuralAbsence].sort(), ["commitments", "failed-assertions", "hash-bindings"]);
    const requested: CorrelatedPredicate[] = [{ kind: "public-flow", source: symbol(program, "flag0"), forms: ["raw", "derived"] }];
    const queried = queryCorrelatedGraph(graph, requested, { maxWork: 20000 - graph.work.steps, maxValues: 50000 - graph.work.values, maxWitnesses: 256 });
    if (queried.status !== "complete") assert.fail(JSON.stringify(queried));
    assert.equal(queried.evidence.length, 10); assert.ok(queried.witnesses.length <= 10);
    assert.ok(queried.work.query + queried.work.projections + graph.work.steps <= 20000);
    for (const limits of [{ maxWork: 1 }, { maxProjectionWork: 1 }, { maxValues: 1 }, { maxWitnesses: 1 }]) {
      const exhausted = queryCorrelatedGraph(graph, requested, limits);
      assert.equal(exhausted.status, "incomplete"); assert.equal("evidence" in exhausted, false);
    }
  });
});
