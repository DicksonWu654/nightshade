import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, type SuccessfulPath } from "../src/dataflow/index.js";
import { scanFile, detectors, resolvePolicies, type Policies } from "../src/index.js";
import { analyzeCorrelatedEntry, selectCorrelatedObservation, type CorrelatedGraph } from "../src/dataflow/correlated.js";
import { queryCorrelatedGraph } from "../src/dataflow/correlated-queries.js";
import { Program } from "../src/semantic/index.js";
import { hygieneOnlyDetectors, withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
function fixture(source: string, run: (program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    run(new Program(file));
  });
}
function built(program: Program): CorrelatedGraph {
  const result = analyzeCorrelatedEntry(program, program.entries[0]);
  if (result.status !== "complete") assert.fail(JSON.stringify(result));
  return result.graph;
}
const decisionsOf = (path: SuccessfulPath): boolean[] => path.path.filter(step => step.kind === "branch").map(step => {
  assert.match(step.label, /^condition may be (true|false)$/);
  return step.label.endsWith("true");
});
// Exact traversal allocates write IDs across mutually exclusive paths. Rename
// only analyzer identity fields and unordered StateWrite guard membership,
// preserving every trace, effect order and user aggregate key.
function alpha(path: SuccessfulPath): unknown {
  const ids = new Map<string, string>();
  const identity = (item: string): string => {
    if (/^write:\d+$/.test(item)) {
      if (!ids.has(item)) ids.set(item, `write:${ids.size}`);
      return ids.get(item)!;
    }
    if (item.startsWith("ordered:")) {
      const split = item.indexOf(":[");
      if (split !== -1) return item.slice(0, split + 1) + JSON.stringify((JSON.parse(item.slice(split + 1)) as string[]).map(identity));
    }
    return item;
  };
  const value = (input: unknown): unknown => {
    if (input instanceof Set) return new Set([...input].map(value));
    if (Array.isArray(input)) return input.map(value);
    if (!input || typeof input !== "object") return input;
    const record = input as Record<string, unknown>;
    const abstract = Array.isArray(record.flows) && record.ledger instanceof Set;
    const write = typeof record.ledger === "string" && record.before && record.after && Array.isArray(record.excludedBefore) && Array.isArray(record.callPath);
    return Object.fromEntries(Object.keys(record).sort().map(key => {
      const item = record[key];
      if (write && key === "guards" && Array.isArray(item)) return [key, [...item].sort()];
      if (abstract && key === "identity" && typeof item === "string") return [key, identity(item)];
      return [key, value(item)];
    }));
  };
  return value(path);
}

test("production current-state graph preserves all ten-branch full witnesses under unchanged construction limits", qualified, () => {
  const size = 10;
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  assert.equal(createHash("sha256").update(source).digest("hex"), "842ba6df0df0b6c1e85c9c6e52f4e2f26105f271f796cf64399048bec57a1039");
  fixture(source, program => {
    const graph = built(program);
    assert.equal(graph.choices.length, 10);
    const flow = new Dataflow(program);
    const originalWork = structuredClone(graph.work);
    for (let bits = 0; bits < 1024; bits++) {
      const choices = Array.from({ length: size }, (_, index) => Boolean(bits & (1 << index)));
      const selected = selectCorrelatedObservation(graph, choices);
      const reference = flow.selectCounterWitness(program.entries[0], choices);
      if (selected.status !== "selected" || reference.status !== "selected") assert.fail(JSON.stringify({ selected, reference }));
      assert.deepEqual(selected.path, reference.path, `Full witness for assignment ${bits}`);
    }
    assert.deepEqual(graph.work, originalWork, "Selection cannot execute construction transfers");
    const retained = selectCorrelatedObservation(graph, Array<boolean>(size).fill(true));
    if (retained.status !== "selected") assert.fail(JSON.stringify(retained));
    const pristine = structuredClone(retained.path);
    retained.path.writes[0].before.ledger.add("foreign-root");
    retained.path.sinks[0].value.flows[0].source.name = "changed";
    retained.path.sinks[0].value.flows[0].trace[0].location.start = -1;
    const repeated = selectCorrelatedObservation(graph, Array<boolean>(size).fill(true));
    if (repeated.status !== "selected") assert.fail(JSON.stringify(repeated));
    assert.deepEqual(repeated.path, pristine, "Selected paths must not expose graph-owned mutable values");
    const exact = flow.analyze();
    assert.deepEqual(exact.completedEntries, []);
    assert.ok(exact.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"), "Separate graph construction is not default scanner completion");
  });
});

const mixed = `import CompactStandardLibrary;
export ledger first: Field; export ledger second: Field;
circuit guard(): Field { return first; }
export circuit entry(flag: Boolean, invalidate: Boolean, x: Field, y: Field): [Field,Field] {
  const initial = guard();
  if (disclose(flag)) { first = disclose(x); second = disclose(y); const saved = guard(); }
  else { first = disclose(y); second = disclose(x); }
  if (disclose(invalidate)) { first = second; } else { second = first; }
  first = second; second = first;
  return [first,second];
}`;
test("production joins preserve full scalar provenance, caller guard completion and invalidation", qualified, () => {
  fixture(mixed, program => {
    const graph = built(program);
    const sparse = [true]; sparse.length = 2;
    Object.defineProperty(sparse, "extra", { value: false, enumerable: true });
    assert.throws(() => selectCorrelatedObservation(graph, sparse), Error);
    const accessor = [true, false]; let calls = 0;
    Object.defineProperty(accessor, "0", { get: () => { calls++; return true; }, enumerable: true });
    assert.throws(() => selectCorrelatedObservation(graph, accessor), Error);
    assert.equal(calls, 0, "Selection validation must not invoke caller getters");
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 4);
      for (const path of exact.paths) {
        const selected = selectCorrelatedObservation(graph, decisionsOf(path));
        if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
        assert.deepEqual(alpha(selected.path), alpha(path));
      }
    }
  });
});

test("conditional helper completion order preserves the same must-guard membership", qualified, () => {
  fixture(`export ledger first: Field;
circuit a(): [] {} circuit b(): [] {}
export circuit entry(flag: Boolean): [] {
  if (disclose(flag)) { a(); b(); first = 2 as Field; }
  else { b(); a(); first = 3 as Field; }
  first = 1 as Field;
}`, program => {
    const graph = built(program), exact = new Dataflow(program).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 2);
    for (const path of exact.paths) {
      const selected = selectCorrelatedObservation(graph, decisionsOf(path));
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.equal(selected.path.writes[0].guards.length, 2);
      assert.deepEqual(alpha(selected.path), alpha(path));
    }
  });
});

test("repeated Boolean parameter tests share truth across distinct CFG branch sites", qualified, () => {
  fixture(`export ledger first: Field; export ledger second: Field;
export circuit entry(flag: Boolean, x: Field, y: Field): [Field,Field] {
  if (disclose(flag)) { first = disclose(x); } else { first = disclose(y); }
  if (disclose(flag)) { second = first; } else { second = 0 as Field; }
  return [first,second];
}`, program => {
    const graph = built(program), exact = new Dataflow(program).analyze();
    assert.equal(graph.choices.length, 1); assert.equal(exact.paths.length, 2);
    assert.deepEqual(exact.diagnostics, []);
    for (const chosen of [false, true]) {
      const selected = selectCorrelatedObservation(graph, [chosen]);
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      const reference = exact.paths.find(path => decisionsOf(path)[0] === chosen)!;
      assert.deepEqual(decisionsOf(selected.path), [chosen, chosen]);
      assert.deepEqual(alpha(selected.path), alpha(reference));
    }
  });
});

test("branch assumptions refine subsequent Boolean reads without rewriting earlier publications", qualified, () => {
  fixture(`export ledger enabled: Boolean;
export circuit entry(flag: Boolean): Boolean {
  enabled = disclose(flag);
  if (disclose(flag)) { enabled = true; } else { enabled = false; }
  return disclose(flag);
}`, program => {
    const graph = built(program), exact = new Dataflow(program).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 2);
    for (const path of exact.paths) {
      const chosen = decisionsOf(path);
      const selected = selectCorrelatedObservation(graph, chosen);
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
      assert.equal(selected.path.sinks[0].value.constant, undefined);
      assert.equal(selected.path.sinks.at(-1)!.value.constant, String(chosen[0]));
    }
  });
});

test("joined scalar reads retain old local snapshots through later branch writes", qualified, () => {
  fixture(`export ledger first: Field; export ledger second: Field;
export circuit entry(flag: Boolean, x: Field): [Field,Field,Field] {
  first = 3 as Field; second = 7 as Field;
  const old = first;
  if (disclose(flag)) { first = disclose(x); } else { second = first; }
  second = first;
  return [old,first,second];
}`, program => {
    const graph = built(program), exact = new Dataflow(program).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 2);
    for (const path of exact.paths) {
      const selected = selectCorrelatedObservation(graph, decisionsOf(path));
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
      assert.equal(selected.path.sinks.at(-1)!.value.items![0].constant, "3");
    }
  });
});

test("nested choices preserve conditional control and successful effect order at a shared suffix", qualified, () => {
  fixture(`export ledger first: Field; export ledger second: Field;
export circuit entry(outer: Boolean, inner: Boolean, x: Field, y: Field): [Field,Field] {
  if (disclose(outer)) {
    if (disclose(inner)) { first = disclose(x); } else { first = disclose(y); }
  } else { second = disclose(x); }
  second = first;
  return [first,second];
}`, program => {
    const graph = built(program), exact = new Dataflow(program).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 3);
    assert.equal(graph.choices.length, 2);
    for (const outer of [false, true]) for (const inner of [false, true]) {
      const selected = selectCorrelatedObservation(graph, [outer, inner]);
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      const chosen = outer ? [outer, inner] : [outer];
      const reference = exact.paths.find(path => JSON.stringify(decisionsOf(path)) === JSON.stringify(chosen));
      assert.ok(reference);
      assert.deepEqual(alpha(selected.path), alpha(reference));
      if (!outer) assert.ok(selected.path.sinks.every(sink => sink.value.flows.every(flow => flow.source.name !== "inner")));
    }
  });
});

test("unsupported correlated continuations explicitly refuse coverage", qualified, () => {
  const sources = [
    `witness secret(): Field; export ledger first: Field; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { first = disclose(secret()); } }`,
    `export ledger first: Field; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { first = 3 as Field; } assert(first != 0 as Field, "retained predicate"); }`,
    `import CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { table.insert(1 as Field, 2 as Field); } }`,
    `export ledger first: Field; circuit checked(flag: Boolean): [] { assert(flag, "retained helper assertion"); first = 1 as Field; } export circuit entry(flag: Boolean): [] { checked(disclose(flag)); }`,
  ];
  for (const source of sources) fixture(source, program => {
    const result = analyzeCorrelatedEntry(program, program.entries[0]);
    assert.equal(result.status, "incomplete");
    if (result.status !== "incomplete") assert.fail("Unsupported effects cannot escape as a graph");
    assert.ok(result.diagnostics.length); assert.equal("graph" in result, false);
  });
});

test("production construction and selected projection exhaustion expose no partial complete evidence", qualified, () => {
  fixture(`import CompactStandardLibrary; export ledger count: Counter; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { count.increment(1); } }`, program => {
    for (const name of ["maxSteps", "maxFrontier", "maxValues"] as const) {
      const result = analyzeCorrelatedEntry(program, program.entries[0], { [name]: 1 });
      assert.equal(result.status, "incomplete", name); assert.equal("graph" in result, false);
    }
    const selected = selectCorrelatedObservation(built(program), [true], 1);
    assert.equal(selected.status, "incomplete"); assert.equal("path" in selected, false);
  });
});

test("scalar equality joins preserve full histories and all policy findings under default scan budgets", qualified, () => {
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: 10 }, (_, i) => `value${i}: Field`).join(",")}): [] { ${Array.from({ length: 10 }, (_, i) => `if (disclose(value${i}) == (0 as Field)) { count.increment(1); }`).join(" ")} }`;
  fixture(source, program => {
    const graph = built(program), reference = new Dataflow(program, 20000, 2048, 50000).analyze();
    assert.deepEqual(reference.diagnostics, []); assert.equal(reference.paths.length, 1024);
    for (const path of reference.paths) {
      const selected = selectCorrelatedObservation(graph, decisionsOf(path));
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
    }
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, i) => ({ circuit: "entry", parameter: `value${i}` })), authorization: [{ state: "count", guard: "entry" }] };
    for (const configured of [undefined, policies]) {
      const result = scanFile(program.root, { policies: configured });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(result.coverage.completedEntries, program.entries);
      assert.equal(result.findings.length, configured ? 65 : 0);
      assert.ok(result.metrics.steps <= 20000 && result.metrics.paths <= 256 && result.metrics.abstractValues <= 50000);
    }
  });
});

test("scalar predicates retain full snapshot, caller guard and negation histories across writes", qualified, () => {
  for (const negated of [false, true]) fixture(`export ledger state: Field; export ledger seen: Field; export ledger rejected: Field;
circuit guard(): [] { const observed = state; }
export circuit entry(input: Field, replacement: Field): [] {
  state = disclose(input); guard(); const old = state;
  if (disclose(old == (1 as Field))) {
    state = disclose(replacement);
    if (disclose(${negated ? "!(old == (1 as Field))" : "old != (1 as Field)"})) { rejected = 99 as Field; }
    if (disclose(state != (1 as Field))) { guard(); seen = state; }
  } else {
    state = 1 as Field;
    if (disclose(state == (1 as Field))) { seen = old; }
  }
  if (disclose(${negated ? "(1 as Field) == old" : "old == (1 as Field)"})) { seen = disclose(replacement); }
}`, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    for (let bits = 0; bits < 1 << graph.choices.length; bits++) {
      const result = selectCorrelatedObservation(graph, graph.choices.map((_, index) => Boolean(bits & (1 << index))));
      assert.notEqual(result.status, "incomplete");
      if (result.status !== "selected") continue;
      assert.ok(result.path.writes.every(write => write.after.constant !== "99"));
      selected.set(JSON.stringify(result.path.path), result.path);
    }
    assert.equal(selected.size, 3);
    const state = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "seen")!.id;
    const rejected = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "rejected")!.id;
    const guard = [...program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
    const query = queryCorrelatedGraph(graph, [{ kind: "missing-guard", ledger: state, guard }, { kind: "transition", ledger: rejected, from: "*", to: "integer:99" }], { maxWork: 20000 - graph.work.steps, maxValues: 50000 - graph.work.values });
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    assert.ok(query.absent.includes(1), "An inconsistent equality history cannot establish a transition finding");
    const unguarded = new Set(query.evidence.filter(item => item.predicate === 0).map(item => query.witnesses[item.witness].path.writes[item.eventIndex].location.start));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.deepEqual(new Set(selected.keys()), new Set(exact.paths.map(path => JSON.stringify(path.path))));
      for (const path of exact.paths) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path), `${engine}/${cached}/${negated}`);
      assert.deepEqual(unguarded, new Set(exact.paths.flatMap(path => path.writes.filter(write => write.ledger === state && !write.guards.includes(guard)).map(write => write.location.start))), "Conditional guard queries preserve the complete ordinary write-site set");
    }
  });
});

test("Boolean inequality exclusions survive subsequent direct and negated condition reads", qualified, () => {
  for (const negated of [false, true]) fixture(`export ledger rejected: Field; export ledger accepted: Field;
export circuit entry(flag: Boolean): [] {
  if (disclose(flag != true)) {
    if (disclose(${negated ? "!flag" : "flag"})) { ${negated ? "accepted" : "rejected"} = 1 as Field; }
    else { ${negated ? "rejected" : "accepted"} = 1 as Field; }
  }
}`, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    const rejected = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "rejected")!.id;
    for (let bits = 0; bits < 1 << graph.choices.length; bits++) {
      const result = selectCorrelatedObservation(graph, graph.choices.map((_, index) => Boolean(bits & (1 << index))));
      assert.notEqual(result.status, "incomplete");
      if (result.status === "selected") selected.set(JSON.stringify(result.path.path), result.path);
    }
    assert.equal(selected.size, 2);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.equal(exact.paths.length, 2);
      for (const path of exact.paths) {
        assert.ok(path.writes.every(write => write.ledger !== rejected));
        assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
      }
    }
    const query = queryCorrelatedGraph(graph, [{ kind: "transition", ledger: rejected, from: "*", to: "*" }]);
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    assert.deepEqual(query.absent, [0]);
  });
});


test("branching stateful helpers compose the unchanged ten-Field body within default scan budgets", qualified, () => {
  const parameters = Array.from({ length: 10 }, (_, i) => `value${i}: Field`).join(",");
  fixture(`import CompactStandardLibrary; export ledger count: Counter;
circuit batch(${parameters}): [] { ${Array.from({ length: 10 }, (_, i) => `if (disclose(value${i}) == (0 as Field)) { count.increment(1); }`).join(" ")} }
export circuit entry(${parameters}): [] { batch(${Array.from({ length: 10 }, (_, i) => `value${i}`).join(",")}); }`, program => {
    const graph = built(program);
    // Expanded allowances belong only to the ordinary oracle, never the scanner.
    const exact = new Dataflow(program, 30000, 2048, 50000).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 1024);
    for (const path of exact.paths) {
      const selected = selectCorrelatedObservation(graph, decisionsOf(path));
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
    }
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, i) => ({ circuit: "entry", parameter: `value${i}` })), authorization: [{ state: "count", guard: "entry" }] };
    for (const configured of [undefined, policies]) {
      const result = scanFile(program.root, { policies: configured });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, configured ? 65 : 0);
      assert.deepEqual(result.coverage.completedEntries, program.entries);
      assert.ok(result.metrics.steps <= 20000 && result.metrics.paths <= 256 && result.metrics.abstractValues <= 50000);
    }
  });
});


test("repeated nested branching calls preserve current storage, caller guards and full return provenance", qualified, () => {
  fixture(`import CompactStandardLibrary;
export ledger state: Field; export ledger seen: Field; export ledger count: Counter;
circuit guard(): Field { return state; }
circuit branch(next: Field): Field {
  const old = state;
  if (old == (1 as Field)) { guard(); state = disclose(next); count.increment(1); }
  else { state = 1 as Field; guard(); count.increment(2); }
  return old;
}
circuit middle(next: Field): Field { return branch(next); }
circuit outer(next: Field): Field { const before = state; return middle(next); }
export circuit entry(input: Field, replacement: Field, tail: Field): [Field,Field] {
  state = disclose(input); guard();
  const first = outer(replacement);
  state = disclose(tail);
  const second = outer(first);
  seen = second;
  return [first,second];
}`, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    for (let bits = 0; bits < 1 << graph.choices.length; bits++) {
      const observed = selectCorrelatedObservation(graph, graph.choices.map((_, i) => Boolean(bits & (1 << i))));
      assert.notEqual(observed.status, "incomplete");
      if (observed.status === "selected") selected.set(JSON.stringify(observed.path.path), observed.path);
    }
    const guard = [...program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
    const ledger = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "count")!.id;
    const query = queryCorrelatedGraph(graph, [{ kind: "missing-guard", ledger, guard }]);
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 4);
      assert.deepEqual(new Set(selected.keys()), new Set(exact.paths.map(path => JSON.stringify(path.path))));
      for (const path of exact.paths) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
      const expected = new Set(exact.paths.flatMap(path => path.writes.flatMap((write, i) => write.ledger === ledger && !write.guards.includes(guard) ? [i] : [])));
      assert.deepEqual(new Set(query.evidence.map(item => item.eventIndex)), expected);
      assert.deepEqual(expected, new Set([2, 5]), "Both invocations retain their real write event");
    }
    const bounded = analyzeCorrelatedEntry(program, program.entries[0], { maxFrontier: 2 });
    assert.equal(bounded.status, "incomplete", "Nested invocation frames still consume frontier allowance");
    if (bounded.status === "incomplete") assert.equal(bounded.diagnostics[0].code, "correlated-frontier-budget");
    assert.equal(scanFile(program.root, { maxPaths: 2 }).status, "incomplete", "Failed graph and exact allowances cannot become a clean scan");
  });
});

test("correlated routing counts repeated call sites to the same branching helper", qualified, () => {
  fixture(`import CompactStandardLibrary; export ledger count: Counter;
circuit bump(flag: Boolean): [] { if (disclose(flag)) { count.increment(1); } }
export circuit entry(a: Boolean, b: Boolean, c: Boolean, d: Boolean): [] { bump(a); bump(b); bump(c); bump(d); }`, program => {
    const exact = new Dataflow(program, 20000, 8, 50000).analyze();
    assert.ok(exact.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    const routed = scanFile(program.root, { maxPaths: 8 });
    assert.equal(routed.status, "complete", JSON.stringify(routed.diagnostics));
    assert.equal(routed.metrics.paths, 0);
    assert.deepEqual(routed.coverage.completedEntries, program.entries);
  });
});


test("reference loads and caller publications cannot revive a rejected nested helper", qualified, () => {
  fixture(`import CompactStandardLibrary;
export ledger state: Field; export ledger seen: Field; export ledger count: Counter;
circuit branch(flag: Boolean, secret: Field): Field {
  count.resetToDefault();
  if (disclose(flag)) { state = disclose(secret); count.decrement(1); }
  else { state = 4 as Field; }
  return state;
}
circuit middle(flag: Boolean, secret: Field): Field { return branch(flag, secret); }
circuit outer(flag: Boolean, secret: Field): Field {
  const returned = middle(flag, secret);
  const current = state;
  return current;
}
export circuit entry(flag: Boolean, secret: Field): [Field,Field,Uint<64>] {
  const snapshot = outer(flag, secret);
  const current = state;
  const remaining = count.read();
  seen = current;
  return [snapshot,current,remaining];
}`, program => {
    const graph = built(program);
    assert.equal(selectCorrelatedObservation(graph, [true]).status, "rejected");
    const selected = selectCorrelatedObservation(graph, [false]);
    if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 1);
      assert.deepEqual(alpha(selected.path), alpha(exact.paths[0]));
    }
    const secret = program.functions.get(program.entries[0])!.declaration.parameters.find(parameter => parameter.name === "secret")!.symbol!;
    const query = queryCorrelatedGraph(graph, [{ kind: "public-flow", source: secret, forms: ["raw", "derived", "hash", "commitment"] }, ...["state", "seen"].map(name => ({ kind: "transition" as const, ledger: program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === name)!.id, from: "*", to: "integer:99" }))]);
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    assert.deepEqual(query.evidence, []); assert.deepEqual(query.absent, [0, 1, 2]);
  });
});


test("conditional returns join final states and returned values without executing skipped continuations", qualified, () => {
  const cases = [
  {
    "source": "export ledger first: Field; circuit choice(flag: Boolean): Field { if (flag) { return 1 as Field; } else { return 2 as Field; } } export circuit entry(flag: Boolean): [] { first = disclose(choice(flag)); }",
    "paths": 2
  },
  {
    "source": "export ledger state: Field; circuit choose(flag: Boolean, x: Field, y: Field): Field { if (flag) { return x; } else { return y; } } export circuit entry(flag: Boolean, x: Field, y: Field): [] { state = disclose(choose(flag,x,y)); }",
    "paths": 2
  },
  {
    "source": "export ledger state: Field; circuit choose(flag: Boolean, x: Field, y: Field): Field { if (disclose(flag)) { state = disclose(x); return x; } state = disclose(y); return y; } export circuit entry(flag: Boolean, x: Field, y: Field): Field { return disclose(choose(flag,x,y)); }",
    "paths": 2
  },
  {
    "source": "export ledger state: Field; export ledger seen: Field; circuit choose(first: Boolean, second: Boolean, x: Field): Field { if (disclose(first)) { if (disclose(second)) { state = disclose(x); return x; } state = 2 as Field; } else { state = 3 as Field; } return state; } export circuit entry(first: Boolean, second: Boolean, x: Field): Field { const value = choose(first,second,x); seen = disclose(value); return value; }",
    "paths": 3
  },
  {
    "source": "export ledger state: Field; export circuit entry(flag: Boolean, x: Field): [] { if (disclose(flag)) { return []; } state = disclose(x); }",
    "paths": 2
  },
  {
    "source": "export ledger state: Field; export circuit entry(flag: Boolean, x: Field, y: Field): Field { if (disclose(flag)) { state = disclose(x); return x; } state = disclose(y); return y; }",
    "paths": 2
  }
];
  for (const item of cases) fixture(item.source, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    for (let bits = 0; bits < 1 << graph.choices.length; bits++) {
      const observed = selectCorrelatedObservation(graph, graph.choices.map((_, i) => Boolean(bits & (1 << i))));
      assert.notEqual(observed.status, "incomplete");
      if (observed.status !== "selected") continue;
      const key = JSON.stringify(observed.path.path);
      if (selected.has(key)) assert.deepEqual(alpha(observed.path), alpha(selected.get(key)!), "An unvisited choice cannot change a completed history");
      selected.set(key, observed.path);
    }
    assert.equal(selected.size, item.paths);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.deepEqual(new Set(selected.keys()), new Set(exact.paths.map(path => JSON.stringify(path.path))));
      for (const path of exact.paths) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
    }
  });
});

test("ten conditional-return calls retain concrete Counter histories and every policy finding within default budgets", qualified, () => {
  fixture(`import CompactStandardLibrary; export ledger count: Counter;
circuit guard(): [] { const checked = count.read(); }
circuit bump(value: Field): Field { if (disclose(value) == (0 as Field)) { count.increment(1); return 0 as Field; } count.increment(2); return 1 as Field; }
export circuit entry(value0: Field,value1: Field,value2: Field,value3: Field,value4: Field,value5: Field,value6: Field,value7: Field,value8: Field,value9: Field): Uint<64> { count.resetToDefault(); bump(value0); bump(value1); bump(value2); bump(value3); bump(value4); bump(value5); bump(value6); bump(value7); bump(value8); bump(value9); return count.read(); }`, program => {
    const graph = built(program), counter = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "count")!.id;
    const exact = new Dataflow(program, 100000, 2048, 100000).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 1024);
    for (const path of exact.paths) {
      const decisions = decisionsOf(path), selected = selectCorrelatedObservation(graph, decisions);
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
      assert.equal(selected.roots[counter].constant, String(decisions.reduce((sum, choice) => sum + (choice ? 1 : 2), 0)), "Separate concrete Counter sum");
      assert.equal(selected.path.writes.length, 11, "One reset plus exactly one increment per call");
    }
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, i) => ({ circuit: "entry", parameter: `value${i}` })), authorization: [{ state: "count", guard: "guard" }] };
    for (const profile of ["audit", "hygiene"] as const) {
      const selected = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions"
        && (profile === "hygiene" || !hygieneOnlyDetectors.has(detector.id)));
      const expected = new Set(selected.flatMap(detector => detector.run(exact, resolvePolicies(program, policies))).map(finding => finding.fingerprint));
      const scanned = scanFile(program.root, { policies, profile });
      assert.equal(scanned.status, "complete", JSON.stringify(scanned.diagnostics));
      assert.deepEqual(scanned.coverage.detectors, selected.map(detector => detector.id));
      assert.deepEqual(new Set(scanned.findings.map(finding => finding.fingerprint)), expected);
      assert.deepEqual(scanned.coverage.completedEntries, program.entries);
      assert.ok(scanned.metrics.steps <= 20000 && scanned.metrics.paths <= 256 && scanned.metrics.abstractValues <= 50000);
    }
  });
});

test("early return guards and rejected suffix publication remain distinct successful histories", qualified, () => {
  fixture(`import CompactStandardLibrary;
export ledger state: Field; export ledger seen: Field; export ledger rejected: Field; export ledger count: Counter;
circuit guard(): [] { const observed = state; }
circuit pick(early: Boolean, fail: Boolean, replacement: Field, secret: Field): Field {
  const old = state;
  if (disclose(early)) { guard(); return old; }
  state = disclose(replacement);
  if (disclose(fail)) { rejected = disclose(secret); count.decrement(1); }
  return state;
}
export circuit entry(early: Boolean, fail: Boolean, input: Field, replacement: Field, secret: Field): [Field,Field] {
  count.resetToDefault(); state = disclose(input); guard();
  const returned = pick(early, fail, replacement, secret);
  seen = disclose(returned);
  return [returned,state];
}`, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    for (const early of [false, true]) for (const fail of [false, true]) {
      const result = selectCorrelatedObservation(graph, [early, fail]);
      if (!early && fail) { assert.equal(result.status, "rejected"); continue; }
      if (result.status !== "selected") assert.fail(JSON.stringify(result));
      selected.set(JSON.stringify(result.path.path), result.path);
    }
    assert.equal(selected.size, 2);
    const symbol = (name: string) => program.activeSymbols().find(symbol => ["ledger", "circuit"].includes(symbol.kind) && symbol.name === name)!.id;
    const secret = program.functions.get(program.entries[0])!.declaration.parameters.find(parameter => parameter.name === "secret")!.symbol!;
    const query = queryCorrelatedGraph(graph, [{ kind: "missing-guard", ledger: symbol("seen"), guard: symbol("guard") }, { kind: "public-flow", source: secret, forms: ["raw", "derived", "hash", "commitment"] }, { kind: "transition", ledger: symbol("rejected"), from: "*", to: "*" }]);
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    assert.deepEqual(query.absent, [1, 2]);
    assert.equal(query.evidence.length, 1);
    assert.deepEqual(decisionsOf(query.witnesses[query.evidence[0].witness].path), [false, false]);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 2);
      for (const path of exact.paths) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
    }
  });
});

// The engines use different branch-label words for expression lowering. Preserve
// all spans, choices, values, provenance and effect order when comparing them.
function expressionHistory(path: SuccessfulPath): SuccessfulPath {
  return { ...path, path: path.path.map(item => item.kind === "branch"
    ? { ...item, label: item.label.replace(/^(left operand|conditional)/, "condition") } : item) };
}

test("scalar arithmetic and logical composition preserve full four-mode histories and checked rejection", qualified, () => {
  const cases = [
    { paths: 2, source: `export circuit entry(a: Boolean, b: Boolean): Boolean { return a && b; }` },
    { paths: 2, source: `export ledger state: Field; circuit touch(value: Field): Boolean { state = disclose(value + (1 as Field)); return true; } export circuit entry(a: Boolean, value: Field): Boolean { return disclose(a) && touch(value); }` },
    { paths: 1, source: `import CompactStandardLibrary; export ledger count: Counter; export ledger state: Field; circuit fail(value: Field): Boolean { state = disclose(value); count.decrement(1); return true; } export circuit entry(a: Boolean, value: Field): Boolean { count.resetToDefault(); const selected = disclose(a) || fail(value); state = 9 as Field; return selected; }` },
    { paths: 2, source: `export ledger state: Uint<8>; export circuit entry(a: Boolean): Boolean { const value = a ? 3 as Uint<8> : 5 as Uint<8>; state = disclose((value + 1) as Uint<8>); return state < 5; }` },
    { paths: 1, source: `export ledger state: Uint<8>; circuit sub(value: Uint<8>): Uint<8> { return (value - (1 as Uint<8>)) as Uint<8>; } export circuit entry(a: Boolean): Uint<8> { const value = a ? 0 as Uint<8> : 2 as Uint<8>; state = disclose(sub(value)); return state; }` },
    { paths: 1, source: `export ledger state: Uint<8>; circuit add(value: Uint<8>): Uint<8> { return (value + (1 as Uint<8>)) as Uint<8>; } export circuit entry(a: Boolean): Uint<8> { const value = a ? 255 as Uint<8> : 2 as Uint<8>; state = disclose(add(value)); return state; }` },
    { paths: 3, source: `export circuit entry(a: Boolean, b: Boolean, c: Boolean): Boolean { return (a || b) && !c; }` },
    { paths: 2, source: `export ledger state: Uint<16>; circuit touch(value: Uint<8>): Boolean { state = disclose(value * (2 as Uint<8>)); return state >= (0 as Uint<16>); } export circuit entry(a: Boolean, value: Uint<8>): Boolean { return disclose(a) || touch(value); }` },
    { paths: 1, source: `export ledger state: Uint<8>; export ledger published: Field; export circuit entry(flag: Boolean, secret: Field): [] { const x=flag ? 255 as Uint<8> : 1 as Uint<8>; state=disclose((x * (2 as Uint<8>)) as Uint<8>); published=disclose(secret); }` },
    { paths: 1, source: `import CompactStandardLibrary; export ledger count: Counter; export ledger state: Field;
circuit check(flag: Boolean, secret: Field): Boolean { if(disclose(flag)) { state=disclose(secret); return false; } count.decrement(1); return true; }
export circuit entry(flag: Boolean, secret: Field): Boolean { count.resetToDefault(); const result=(disclose(flag) && check(flag,secret)) || check(!flag,secret); state=7 as Field; return result; }` },
    { paths: 2, source: `export ledger state: Field; export circuit entry(flag: Boolean, secret: Field): [] { const x=flag ? 2 as Uint<8> : 3 as Uint<8>; if(disclose((x * x) < (4 as Uint<16>))) { state=disclose(secret); } }` },
  ];
  for (const item of cases) fixture(item.source, program => {
    const graph = built(program), selected = new Map<string, SuccessfulPath>();
    for (let bits = 0; bits < 2 ** graph.choices.length; bits++) {
      const observed = selectCorrelatedObservation(graph, graph.choices.map((_, i) => Boolean(bits & (1 << i))));
      assert.notEqual(observed.status, "incomplete");
      if (observed.status !== "selected") continue;
      const key = JSON.stringify(observed.path.path);
      if (selected.has(key)) assert.deepEqual(alpha(observed.path), alpha(selected.get(key)!));
      selected.set(key, observed.path);
    }
    assert.equal(selected.size, item.paths);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      const paths = exact.paths.map(expressionHistory);
      assert.deepEqual(new Set(selected.keys()), new Set(paths.map(path => JSON.stringify(path.path))));
      for (const path of paths) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
    }
  });
});

test("joined scalar values satisfy separate concrete arithmetic and comparison expectations", qualified, () => {
  fixture(`export circuit entry(flag: Boolean): [Field,Field,Boolean,Boolean,Boolean,Boolean] {
    const x = flag ? 0 as Field : 3 as Field;
    const n = flag ? 0 as Uint<8> : 3 as Uint<8>;
    return [(x - (1 as Field)) + (1 as Field), x * x, n < 2, n <= 3, n > 2, n >= 3];
  }`, program => {
    const graph = built(program);
    for (const flag of [false, true]) {
      const observed = selectCorrelatedObservation(graph, [flag]);
      if (observed.status !== "selected") assert.fail(JSON.stringify(observed));
      assert.deepEqual(observed.path.sinks.at(-1)!.value.items!.map(value => value.constant),
        flag ? ["0", "0", "true", "true", "false", "false"] : ["3", "9", "false", "true", "true", "true"]);
    }
  });
});

test("ten arithmetic short-circuit helpers complete every policy finding within unchanged budgets", qualified, () => {
  fixture(`import CompactStandardLibrary; export ledger count: Counter;
circuit guard(): [] { const checked = count.read(); }
circuit tick(value: Uint<8>): Boolean { count.increment(disclose((value + 1) as Uint<16>)); return value * 2 <= 2; }
export circuit entry(value0: Uint<8>,value1: Uint<8>,value2: Uint<8>,value3: Uint<8>,value4: Uint<8>,value5: Uint<8>,value6: Uint<8>,value7: Uint<8>,value8: Uint<8>,value9: Uint<8>): Uint<64> { count.resetToDefault(); disclose(value0 == (0 as Uint<8>)) && tick(value0); disclose(value1 == (0 as Uint<8>)) && tick(value1); disclose(value2 == (0 as Uint<8>)) && tick(value2); disclose(value3 == (0 as Uint<8>)) && tick(value3); disclose(value4 == (0 as Uint<8>)) && tick(value4); disclose(value5 == (0 as Uint<8>)) && tick(value5); disclose(value6 == (0 as Uint<8>)) && tick(value6); disclose(value7 == (0 as Uint<8>)) && tick(value7); disclose(value8 == (0 as Uint<8>)) && tick(value8); disclose(value9 == (0 as Uint<8>)) && tick(value9); return count.read(); }`, program => {
    const graph = built(program), counter = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "count")!.id;
    // Only the ordinary oracle has expanded allowances.
    const exact = new Dataflow(program, 100000, 2048, 100000).analyze();
    assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 1024);
    for (const path of exact.paths) {
      const decisions = decisionsOf(path), selected = selectCorrelatedObservation(graph, decisions);
      if (selected.status !== "selected") assert.fail(JSON.stringify(selected));
      assert.deepEqual(alpha(selected.path), alpha(path));
      assert.equal(selected.roots[counter].constant, String(decisions.filter(Boolean).length), "Only evaluated RHS calls increment, each by one");
      assert.equal(selected.path.writes.length, 1 + decisions.filter(Boolean).length, "One reset plus exactly the evaluated RHS effects");
    }
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, i) => ({ circuit: "entry", parameter: `value${i}` })), authorization: [{ state: "count", guard: "guard" }] };
    for (const profile of ["audit", "hygiene"] as const) {
      const selected = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions"
        && (profile === "hygiene" || !hygieneOnlyDetectors.has(detector.id)));
      const expected = new Set(selected.flatMap(detector => detector.run(exact, resolvePolicies(program, policies))).map(finding => finding.fingerprint));
      const scanned = scanFile(program.root, { policies, profile });
      assert.equal(scanned.status, "complete", JSON.stringify(scanned.diagnostics));
      assert.deepEqual(scanned.coverage.detectors, selected.map(detector => detector.id));
      assert.equal(scanned.findings.length, expected.size);
      assert.deepEqual(new Set(scanned.findings.map(finding => finding.fingerprint)), expected);
      assert.deepEqual(scanned.coverage.completedEntries, program.entries);
      assert.ok(scanned.metrics.steps <= 20000 && scanned.metrics.paths <= 256 && scanned.metrics.abstractValues <= 50000);
    }
    assert.equal(scanFile(program.root, { policies, maxSteps: 32 }).status, "incomplete");
    assert.equal(analyzeCorrelatedEntry(program, program.entries[0], { maxValues: 10 }).status, "incomplete");
  });
});

test("short-circuit guards are conditional and arithmetic-infeasible publications have no evidence", qualified, () => {
  fixture(`export ledger state: Field; export ledger seen: Field; export ledger unreachable: Field;
    circuit guard(): Boolean { return state == (1 as Field); }
    export circuit entry(flag: Boolean, secret: Field): [] {
      state = 1 as Field;
      disclose(flag) && guard();
      seen = state;
      state = disclose(secret + (1 as Field));
      seen = state;
      const x = flag ? 2 as Uint<8> : 3 as Uint<8>;
      if (disclose((x * x) < (4 as Uint<16>))) { unreachable = 99 as Field; }
    }`, program => {
    const graph = built(program), guard = [...program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
    const seen = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "seen")!.id;
    const unreachable = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "unreachable")!.id;
    const query = queryCorrelatedGraph(graph, [{ kind: "missing-guard", ledger: seen, guard }, { kind: "transition", ledger: unreachable, from: "*", to: "integer:99" }, { kind: "transition", ledger: seen, from: "*", to: "integer:99" }]);
    if (query.status !== "complete") assert.fail(JSON.stringify(query));
    assert.deepEqual(query.absent, [1]);
    assert.ok(query.evidence.some(item => item.predicate === 2), "Unknown input arithmetic may still reach 99");
    assert.deepEqual(new Set(query.evidence.map(item => item.eventIndex)), new Set([1, 3]));
    for (const item of query.evidence) {
      const path: SuccessfulPath = query.witnesses[item.witness].path;
      if (item.eventIndex === 1) assert.equal(decisionsOf(path)[0], false, "Only skipped guards are absent before mutation");
      assert.ok(!path.writes[item.eventIndex].guards.includes(guard));
    }
    const selected = new Map<string, SuccessfulPath>();
    for (const flag of [false, true]) {
      const observed = selectCorrelatedObservation(graph, [flag, false]);
      if (observed.status !== "selected") assert.fail(JSON.stringify(observed));
      selected.set(JSON.stringify(observed.path.path), observed.path);
      assert.equal(observed.path.writes[1].guards.includes(guard), flag);
      assert.equal(observed.path.writes[3].guards.includes(guard), false);
      assert.equal(selectCorrelatedObservation(graph, [flag, true]).status, "rejected");
    }
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 2);
      for (const path of exact.paths.map(expressionHistory)) assert.deepEqual(alpha(selected.get(JSON.stringify(path.path))!), alpha(path));
    }
  });
});
