import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, type SuccessfulPath } from "../src/dataflow/index.js";
import { queryCounterRegion, type CounterQuery, type CounterQueryResult } from "../src/dataflow/counter-queries.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const source = (size: number, reset = true, returned = true) => `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export ledger unrelated: Counter;
export circuit earlier(unused: Field): [] {}
circuit guard(): [] {}
circuit wrongGuard(): Boolean { return true; }
export circuit entry(unused: Field, ${Array.from({ length: size }, (_, i) => `flag${i}: Boolean`).join(", ")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, i) => `if (disclose(flag${i})) { count.increment(${i % 3 === 0 ? 0 : i + 1} as Uint<16>); }`).join("\n")}
${returned ? "return [];" : ""}}
`;
function fixture(text: string, compile: boolean, check: (program: Program) => void): void {
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    if (compile) { const result = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(result.valid, true, result.error); }
    check(new Program(file));
  });
}
const symbol = (program: Program, name: string, kind: string) => [...program.symbols.values()].find(item => item.kind === kind && item.name === name)!.id;
const entry = (program: Program) => program.entries.find(id => program.functions.get(id)!.symbol.name === "entry")!;
const parameter = (program: Program, name: string) => program.functions.get(entry(program))!.declaration.parameters.find(item => item.name === name)!.symbol!;
const site = (location: { file: string; start: number; end: number }) => `${location.file}:${location.start}:${location.end}`;
function observations(paths: SuccessfulPath[], query: CounterQuery): string[] {
  const keys = new Set<string>();
  for (const path of paths) {
    if (query.kind === "public-flow") {
      for (const sink of path.sinks) for (const flow of sink.value.flows) if (flow.source.symbol === query.source) keys.add(`${site(sink.location)}:${sink.kind}:${flow.source.symbol}:${flow.form}`);
    } else for (const write of path.writes) if (write.ledger === query.root && !write.guards.includes(query.guard)) keys.add(`${site(write.location)}:${write.ledger}:${query.guard}`);
  }
  return [...keys].sort();
}
function evidence(result: CounterQueryResult): string[] {
  assert.equal(result.status, "complete", result.status === "incomplete" ? JSON.stringify(result.diagnostics) : result.status);
  assert.ok(result.status === "complete");
  assert.equal("completedEntries" in result, false);
  assert.equal("paths" in result, false);
  assert.equal("program" in result, false);
  assert.equal(result.coverage.scope, "requested-existential-observations");
  return result.evidence.map(item => {
    const witness = result.witnesses[item.witness];
    assert.ok(witness);
    assert.equal(witness.path.entry, result.entry);
    assert.equal(witness.decisions.filter(Boolean).length, 1);
    assert.deepEqual(witness.path.path.filter(step => step.kind === "branch").map(step => step.label === "condition may be true"), witness.decisions);
    if (item.kind === "public-flow") {
      assert.ok(result.query.kind === "public-flow");
      const sink = witness.path.sinks[item.sink];
      const flow = sink.value.flows[item.flow];
      assert.equal(flow.source.symbol, result.query.source);
      assert.equal(flow.form, "derived");
      assert.ok(flow.trace.some(step => step.kind === "disclose"));
      assert.ok(flow.trace.some(step => step.kind === "implicit-flow"));
      return `${site(sink.location)}:${sink.kind}:${flow.source.symbol}:${flow.form}`;
    }
    assert.ok(result.query.kind === "missing-guard-write");
    const write = witness.path.writes[item.write];
    assert.equal(write.ledger, result.query.root);
    assert.equal(write.guards.includes(result.query.guard), false);
    return `${site(write.location)}:${write.ledger}:${result.query.guard}`;
  }).sort();
}

for (let size = 1; size <= 8; size++) test(`${size}-choice query evidence exhaustively matches exact histories in both engines/cache modes`, qualified, () => {
  fixture(source(size, size % 2 === 0, size % 2 !== 0), true, program => {
    const id = entry(program);
    const queries: CounterQuery[] = [
      ...Array.from({ length: size }, (_, i): CounterQuery => ({ kind: "public-flow", source: parameter(program, `flag${i}`) })),
      { kind: "public-flow", source: parameter(program, "unused") },
      { kind: "missing-guard-write", root: symbol(program, "count", "ledger"), guard: symbol(program, "guard", "circuit") },
      { kind: "missing-guard-write", root: symbol(program, "count", "ledger"), guard: id },
      { kind: "missing-guard-write", root: symbol(program, "unrelated", "ledger"), guard: id },
    ];
    let baseline: string[][] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine, cached, cached);
      const exact = flow.analyze();
      assert.deepEqual(exact.diagnostics, []);
      const paths = exact.paths.filter(path => path.entry === id);
      assert.equal(paths.length, 2 ** size);
      const found = queries.map(query => {
        const result = queryCounterRegion(flow, id, query);
        const actual = evidence(result);
        assert.deepEqual(actual, observations(paths, query));
        assert.equal(new Set(actual).size, actual.length);
        assert.ok(result.status === "complete");
        assert.equal(result.coverage.assignments, BigInt(2 ** size));
        assert.ok(result.work.transferSteps <= 20000);
        assert.ok(result.work.transferValues <= 50000);
        return actual;
      });
      if (baseline) assert.deepEqual(found, baseline);
      baseline = found;
      assert.deepEqual(flow.analyze().paths, exact.paths, "Queries do not mutate the caller's analysis object");
    }
  });
});

for (const reset of [false, true]) test(`ten-choice query coverage uses a fixed source oracle (${reset ? "reset" : "unknown incoming"})`, qualified, () => {
  const text = source(10, reset, true);
  fixture(text, true, program => {
    const id = entry(program);
    const flow = new Dataflow(program);
    assert.ok(flow.analyze().diagnostics.some(item => item.code === "analysis-budget"));
    for (let index = 0; index < 10; index++) {
      const query: CounterQuery = { kind: "public-flow", source: parameter(program, `flag${index}`) };
      const result = queryCounterRegion(flow, id, query);
      const actual = evidence(result);
      // Source-renderer offsets are independent of extractor/projection/effects.
      const expected = Array.from({ length: 10 - index }, (_, offset) => {
        const chosen = index + offset;
        const fragment = `count.increment(${chosen % 3 === 0 ? 0 : chosen + 1} as Uint<16>)`;
        const start = text.indexOf(fragment, text.indexOf(`if (disclose(flag${chosen}))`));
        return `${program.rootSource.path}:${start}:${start + fragment.length}:ledger-operation:${query.source}:derived`;
      }).sort();
      assert.deepEqual(actual, expected, "Earlier false flags influence later writes; later flags do not influence earlier sites");
      assert.ok(result.status === "complete");
      assert.equal(result.coverage.assignments, 1024n);
    }
    const writes = queryCounterRegion(flow, id, { kind: "missing-guard-write", root: symbol(program, "count", "ledger"), guard: symbol(program, "guard", "circuit") });
    assert.equal(evidence(writes).length, 10 + Number(reset));
    assert.ok(flow.analyze().diagnostics.some(item => item.code === "analysis-budget"));
  });
});

test("independent query, witness, aggregate transfer, graph and projection budgets reject complete prefixes", () => {
  fixture(source(4), false, program => {
    const id = entry(program);
    const query: CounterQuery = { kind: "public-flow", source: parameter(program, "flag0") };
    const flow = new Dataflow(program);
    const full = queryCounterRegion(flow, id, query);
    evidence(full);
    assert.ok(full.status === "complete");
    const boundaries = { maxQueryWork: full.work.query, maxWitnesses: full.work.witnesses, maxTransferSteps: full.work.transferSteps, maxTransferValues: full.work.transferValues };
    assert.equal(queryCounterRegion(flow, id, query, boundaries).status, "complete");
    for (const name of Object.keys(boundaries) as (keyof typeof boundaries)[]) {
      const result = queryCounterRegion(flow, id, query, { ...boundaries, [name]: boundaries[name] - 1 });
      assert.equal(result.status, "incomplete", name);
      assert.equal("evidence" in result, false);
      assert.equal("witnesses" in result, false);
      if (result.status === "incomplete") assert.ok(result.diagnostics.length);
    }
    for (const limits of [{ region: { maxBranches: 1 } }, { maxGraphNodes: 1 }, { maxProjectionWork: 1 }]) {
      assert.equal(queryCounterRegion(flow, id, query, limits).status, "incomplete");
    }
    for (const constrained of [new Dataflow(program, 1), new Dataflow(program, 20000, 0), new Dataflow(program, 20000, 256, 1)]) {
      assert.equal(queryCounterRegion(constrained, id, query).status, "incomplete", "Query defaults cannot raise the caller's transfer budgets");
    }
  });
});

test("canonical selectors distinguish covered absence from malformed, foreign-source and unsupported requests", () => {
  fixture(source(3), false, program => {
    const id = entry(program);
    const flow = new Dataflow(program);
    const root = symbol(program, "count", "ledger");
    for (const query of [
      { kind: "public-flow", source: "flag0" },
      { kind: "public-flow", source: program.functions.get(program.entries[0])!.declaration.parameters[0].symbol! },
      { kind: "missing-guard-write", root, guard: "guard" },
      { kind: "missing-guard-write", root: "count", guard: id },
      { kind: "missing-guard-write", root, guard: symbol(program, "wrongGuard", "circuit") },
    ] as CounterQuery[]) assert.equal(queryCounterRegion(flow, id, query).status, "ineligible");
    const absent = queryCounterRegion(flow, id, { kind: "public-flow", source: parameter(program, "unused") });
    assert.deepEqual(evidence(absent), []);
    assert.equal(absent.work.witnesses, 0);
    assert.throws(() => queryCounterRegion(flow, id, { kind: "transition" } as unknown as CounterQuery));
    const getter = { kind: "public-flow", get source(): string { return assert.fail("query getter evaluated"); } };
    assert.throws(() => queryCounterRegion(flow, id, getter as CounterQuery));
    for (const limits of [{ maxQueryWork: 0 }, { maxWitnesses: Infinity }, { maxTransferSteps: 1.5 }, { maxTransferValues: 1000001 }]) assert.throws(() => queryCounterRegion(flow, id, { kind: "public-flow", source: parameter(program, "flag0") }, limits));
    assert.equal(queryCounterRegion(flow, "missing", { kind: "public-flow", source: parameter(program, "flag0") }).status, "ineligible");
  });
  fixture(source(2).replace("return [];", "count.read(); return [];"), false, program => {
    assert.equal(queryCounterRegion(new Dataflow(program), entry(program), { kind: "public-flow", source: parameter(program, "flag0") }).status, "ineligible");
  });
});

test("query witnesses and selectors detach; guards and empty returns do not manufacture evidence", () => {
  fixture(source(3), false, program => {
    const flow = new Dataflow(program);
    const query: CounterQuery = { kind: "missing-guard-write", root: symbol(program, "count", "ledger"), guard: entry(program) };
    const result = queryCounterRegion(flow, entry(program), query);
    assert.equal(evidence(result).length, 4, "Entry completion occurs after each write");
    const saved = structuredClone(result);
    query.guard = "changed";
    flow.analyze();
    assert.deepEqual(result, saved);
    const publicResult = queryCounterRegion(flow, entry(program), { kind: "public-flow", source: parameter(program, "flag2") });
    assert.equal(evidence(publicResult).length, 1, "Reset and empty return are not publication sites for any flag");
  });
});

test("materialization failure or inconsistent selected evidence cannot become covered absence", () => {
  fixture(source(2), false, program => {
    const original = Dataflow.prototype.selectCounterWitness;
    const query: CounterQuery = { kind: "public-flow", source: parameter(program, "flag0") };
    for (const change of [
      (path: SuccessfulPath) => { path.path[0].label = "condition may be false"; },
      (path: SuccessfulPath) => { path.sinks[0].value.flows[0].source.symbol = "foreign"; },
      (path: SuccessfulPath) => { path.writes[0].guards.push(entry(program)); },
      (path: SuccessfulPath) => { path.sinks[0].location.start++; },
    ]) {
      try {
        Dataflow.prototype.selectCounterWitness = function (...args) {
          const selected = original.apply(this, args);
          if (selected.status === "selected") change(selected.path);
          return selected;
        };
        const result = queryCounterRegion(new Dataflow(program), entry(program), query);
        assert.equal(result.status, "incomplete");
        assert.equal("evidence" in result, false);
      } finally { Dataflow.prototype.selectCounterWitness = original; }
    }
    try {
      Dataflow.prototype.selectCounterWitness = function (...args) {
        const selected = original.apply(this, args);
        assert.ok(selected.status === "selected");
        return { status: "no-surviving-path", decisions: selected.decisions, metrics: selected.metrics };
      };
      assert.equal(queryCounterRegion(new Dataflow(program), entry(program), query).status, "incomplete");
    } finally { Dataflow.prototype.selectCounterWitness = original; }
  });
});
