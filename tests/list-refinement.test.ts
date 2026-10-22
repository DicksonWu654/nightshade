import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Policies, Program, detectors, resolvePolicies } from "../src/index.js";
import { AbstractValue } from "../src/dataflow/index.js";
import { OBSERVATION_RULES } from "../src/analysis/rule-observations.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const prelude = "pragma language_version >= 0.26.0; import CompactStandardLibrary; export ledger items: List<Field>;";
const outputs = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const values = (value: AbstractValue): unknown => value.items ? value.items.map(values) : value.fields ? Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, values(field)])) : value.constant;
const names = (value: AbstractValue) => [...new Set(value.flows.map(flow => flow.source.name))].sort();
interface Options {
  incomplete?: string;
  policies?: Policies;
  readHits?: boolean;
  mutationHits?: boolean;
  maxValues?: number;
  pathSemantics?: AnalysisFacts["pathSemantics"];
  allPredicates?: boolean;
}

// Every source here is compiled when COMPACTC_TEST is set. Domain-only cases
// live in list-domain.test.ts; these integrations do not substitute for runtime evidence.
function compare(source: string, check: (facts: AnalysisFacts, program: Program) => void, options: Options = {}): void {
  withFiles({ "main.compact": `${prelude}\n${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const results = (["instructions", "expressions"] as const).flatMap(engine => [true, false].map(cached =>
      // Supply the reset consumer's full predicates only in its applicable
      // cases; preserve the original witness-mode resource-budget assertions.
      new Dataflow(program, 20000, 256, options.maxValues ?? 50000, engine, cached, cached, options.pathSemantics, false, true, options.allPredicates ? "all" : "witness").analyze()));
    for (const index of [0, 2]) {
      if (options.readHits) assert.ok(results[index].metrics.readSummaryHits > 0, "must exercise read replay");
      if (options.mutationHits) assert.ok(results[index].metrics.statefulSummaryHits > 0, "must exercise mutation replay");
    }
    const policies = resolvePolicies(program, options.policies ?? {});
    // Ordinary facts do not include the separate, exact evidence required by
    // compilation-unit observation rules. Their integration has its own tests.
    const ordinaryDetectors = detectors.filter(detector => !OBSERVATION_RULES.has(detector.id));
    const findings = results.map(facts => ordinaryDetectors.flatMap(detector => detector.run(facts, policies)));
    for (const [index, facts] of results.entries()) {
      assert.deepEqual(facts.completedEntries, options.incomplete ? [] : program.entries);
      if (options.incomplete) assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === options.incomplete), JSON.stringify(facts.diagnostics));
      else assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.diagnostics, results[0].diagnostics);
      assert.deepEqual(facts.failedAssertions, results[0].failedAssertions);
      assert.deepEqual(semanticPaths(facts), semanticPaths(results[0]));
      assert.deepEqual(findings[index], findings[0]);
      check(facts, program);
    }
    assert.deepEqual(results[0].paths, results[1].paths);
    assert.deepEqual(results[2].paths, results[3].paths);
  });
}

for (const condition of ["!items.isEmpty()", "items.isEmpty() == false", "false == items.isEmpty()", "items.isEmpty() != true", "(!items.isEmpty()) == true", "(!!items.isEmpty()) == false"]) {
  test(`revision-matched List predicate ${condition} permits a lossy tail pop`, () => {
    compare(`export circuit entry(): [Boolean,Uint<64>,Maybe<Field>] { assert(${condition},"nonempty"); items.popFront(); return [items.isEmpty(),items.length(),items.head()]; }`, facts => {
      assert.deepEqual(facts.failedAssertions, []);
      assert.deepEqual(outputs(facts).map(values), [[undefined, undefined, { is_some: undefined, value: undefined }]]);
    });
  });
}

test("stored List predicates survive their producing helper's local scope", () => {
  compare(`circuit nonempty(): Boolean { const saved = items.isEmpty(); return !saved; }
    export circuit entry(): Boolean { const saved = nonempty(); assert(saved,"nonempty"); items.popFront(); return items.isEmpty(); }`, facts => {
    assert.deepEqual(outputs(facts).map(values), [undefined]);
    assert.deepEqual(facts.failedAssertions, []);
  });
});

test("asserted empty Lists have default Maybe and zero length without losing their ledger dependency", () => {
  compare('export circuit entry(): [Maybe<Field>,Uint<64>] { assert(items.isEmpty(),"empty"); return [items.head(),items.length()]; }', (facts, program) => {
    assert.deepEqual(outputs(facts).map(values), [[{ is_some: "false", value: "0" }, "0"]]);
    const root = program.activeSymbols().find(symbol => symbol.name === "items")!.id;
    assert.ok(outputs(facts)[0].items!.every(value => value.ledger.has(root)));
  });
});

for (const body of [
  'assert(!items.isEmpty(),"nonempty"); assert(items.isEmpty(),"conflict");',
  'assert(items.isEmpty(),"empty"); assert(!items.isEmpty(),"conflict");',
  'items.resetToDefault(); assert(!items.isEmpty(),"conflict");',
  'items.pushFront(1 as Field); assert(items.isEmpty(),"conflict");',
]) test(`contradictory List proof prunes the successful mutation: ${body}`, () => {
  compare(`export circuit entry(): [] { ${body} items.popFront(); }`, facts => {
    assert.deepEqual(facts.paths, []);
    assert.equal(facts.failedAssertions.length, 1);
  });
});

test("the false branch of List emptiness supports guarded pop while the empty branch stays empty", () => {
  compare('export circuit entry(): Uint<64> { if (items.isEmpty()) return items.length(); items.popFront(); return items.length(); }', facts => {
    assert.equal(outputs(facts).length, 2);
    assert.ok(outputs(facts).some(value => value.constant === "0"));
    assert.ok(outputs(facts).some(value => value.constant === undefined));
  });
});

for (const [name, body] of [
  ["consumed proof", 'assert(!items.isEmpty(),"nonempty"); items.popFront(); items.popFront();'],
  ["saved consumed proof", 'const saved = items.isEmpty(); assert(!saved,"nonempty"); items.popFront(); assert(!saved,"old"); items.popFront();'],
  ["prefix proof does not strengthen suffix", 'items.pushFront(1 as Field); assert(!items.isEmpty(),"prefix"); items.popFront(); items.popFront();'],
  ["reset after snapshot", 'const saved = items.isEmpty(); items.resetToDefault(); assert(!saved,"old"); items.popFront();'],
  ["push and pop after snapshot", 'const saved = items.isEmpty(); items.pushFront(1 as Field); items.popFront(); assert(!saved,"old"); items.popFront();'],
  ["helper mutation after snapshot", 'const saved = items.isEmpty(); reset(); assert(!saved,"old"); items.popFront();'],
  ["later reset cannot erase unsupported outcome", 'assert(!items.isEmpty(),"nonempty"); items.popFront(); items.popFront(); items.resetToDefault();'],
]) test(`List ${name} remains explicitly incomplete`, () => {
  compare(`circuit reset(): [] { items.resetToDefault(); } export circuit entry(): [] { ${body} }`, facts => {
    assert.deepEqual(facts.paths, []);
    assert.deepEqual(facts.failedAssertions, []);
  }, { incomplete: "list-pop-outcome-unqualified" });
});

test("a nonempty tail proof established before a push survives removal of that known prefix", () => {
  compare('export circuit entry(secret: Field): Boolean { assert(!items.isEmpty(),"tail"); items.pushFront(disclose(secret)); items.popFront(); items.popFront(); return items.isEmpty(); }', facts => {
    assert.deepEqual(outputs(facts).map(values), [undefined]);
    assert.deepEqual(names(outputs(facts)[0]), []);
  });
});

test("a saved empty predicate cannot reset a newer known prefix", () => {
  compare('export circuit entry(): [Field,Uint<64>] { const saved = items.isEmpty(); items.resetToDefault(); items.pushFront(9 as Field); assert(saved,"old empty"); return [items.head().value,items.length()]; }', facts => {
    assert.deepEqual(outputs(facts).map(values), [["9", "1"]]);
  }, { allPredicates: true });
});

for (const replacement of ["table.insertDefault(1 as Field);", "table.insertDefault(disclose(key));"]) test(`List refinement is invalidated by ancestor or wildcard replacement: ${replacement}`, () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(key: Field): [] {
    const saved = table.lookup(1 as Field).isEmpty(); assert(!saved,"nonempty");
    ${replacement} assert(!saved,"old proof"); table.lookup(1 as Field).popFront();
  }`, facts => {
    assert.deepEqual(facts.paths, []);
    assert.deepEqual(facts.failedAssertions, []);
  }, { incomplete: "list-pop-outcome-unqualified" });
});

test("an established List proof survives disjoint sibling and unrelated-root writes", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export ledger other: Field; export circuit entry(): Boolean {
    assert(!table.lookup(1 as Field).isEmpty(),"nonempty"); table.insertDefault(2 as Field); other = 7 as Field;
    table.lookup(1 as Field).popFront(); return table.lookup(1 as Field).isEmpty();
  }`, facts => assert.deepEqual(outputs(facts).map(values), [undefined]), { allPredicates: true });
});

test("a saved predicate cannot establish a new List proof after a same-root sibling revision", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(): [] {
    const saved = table.lookup(1 as Field).isEmpty(); table.insertDefault(2 as Field);
    assert(!saved,"old revision"); table.lookup(1 as Field).popFront();
  }`, facts => assert.deepEqual(facts.failedAssertions, []), { incomplete: "list-pop-outcome-unqualified" });
});

test("an unrelated-root write does not stale a saved List predicate", () => {
  compare('export ledger other: Field; export circuit entry(): Boolean { const saved = items.isEmpty(); other = 7 as Field; assert(!saved,"nonempty"); items.popFront(); return items.isEmpty(); }', facts => assert.deepEqual(outputs(facts).map(values), [undefined]));
});

test("a stable dynamic selection retains its nonempty proof for one pop", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(key: Field): [] {
    assert(!table.lookup(disclose(key)).isEmpty(),"one selected list"); table.lookup(disclose(key)).popFront();
  }`, facts => { assert.deepEqual(facts.failedAssertions, []); assert.equal(facts.paths.length, 1); });
});

test("a nonempty predicate cannot authorize a pop through a different dynamic selection", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(first: Field, second: Field): [] {
    assert(!table.lookup(disclose(first)).isEmpty(),"one selected list"); table.lookup(disclose(second)).popFront();
  }`, facts => assert.deepEqual(facts.failedAssertions, []), { incomplete: "list-pop-outcome-unqualified" });
});

test("different wildcard emptiness reads retain independent outcomes", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(first: Field,second: Field): Boolean {
    const left = table.lookup(disclose(first)).isEmpty(); const right = table.lookup(disclose(second)).isEmpty();
    assert(left != right,"different selections"); return true;
  }`, facts => { assert.deepEqual(outputs(facts).map(values), ["true"]); assert.deepEqual(facts.failedAssertions, []); });
});

test("retained Maybe snapshots and popped payloads stay separate from unknown-tail structure", () => {
  compare(`export ledger other: Field; export circuit entry(secret: Field): [Field,Field,Boolean,Maybe<Field>] {
    assert(!items.isEmpty(),"nonempty"); const saved = items.head();
    items.pushFront(other); items.popFront(); items.pushFront(disclose(secret)); const pushed = items.head();
    items.popFront(); items.popFront(); return [saved.value,pushed.value,items.isEmpty(),items.head()];
  }`, (facts, program) => {
    const result = outputs(facts)[0].items!;
    const root = program.activeSymbols().find(symbol => symbol.name === "items")!.id;
    assert.equal(result[0].constant, undefined);
    assert.deepEqual(names(result[1]), ["secret"]);
    for (const value of [result[0], ...result.slice(2)]) {
      assert.deepEqual(names(value), []);
      assert.deepEqual([...value.ledger], [root]);
    }
  });
});

test("canonical selected regions preserve selection provenance when a predicate creates List facts", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(key: Field): Boolean {
    assert(key == (1 as Field),"fixed selection"); assert(!table.lookup(disclose(key)).isEmpty(),"nonempty");
    table.lookup(1 as Field).popFront(); return table.lookup(1 as Field).isEmpty();
  }`, facts => { assert.deepEqual(names(outputs(facts)[0]), ["key"]); assert.equal(outputs(facts)[0].constant, undefined); });
});

for (const pathSemantics of ["equivalent-states", "guard-cover"] as const) test(`conditional lossy pops retain structural control under ${pathSemantics}`, () => {
  compare(`export circuit entry(flag: Boolean): Boolean {
    assert(!items.isEmpty(),"nonempty"); if (disclose(flag)) items.popFront(); return items.isEmpty();
  }`, facts => {
    assert.equal(outputs(facts).length, 2);
    const changed = outputs(facts).find(value => value.constant === undefined)!;
    assert.deepEqual(names(changed), ["flag"]);
    assert.ok(outputs(facts).some(value => value.constant === "false"));
  }, { pathSemantics });
});

test("nested read replay observes same-revision refinement and mutation replay consumes fresh proofs", () => {
  compare(`circuit read(): Boolean { return items.isEmpty(); }
    circuit outer(): Boolean { return read(); }
    circuit pop(): [] { items.popFront(); } circuit outerPop(): [] { pop(); }
    circuit guard(): [] { const local = outer(); assert(!local,"nonempty"); }
    export circuit entry(): [Boolean,Boolean,Boolean] {
      outer(); const before = outer(); guard(); outer(); const refined = outer();
      items.pushFront(7 as Field); outerPop(); outerPop(); outer(); outer(); guard(); outerPop(); outer();
      return [before,refined,outer()];
    }`, facts => assert.deepEqual(outputs(facts).map(values), [["false", "false", undefined]]), { readHits: true, mutationHits: true });
});

for (const body of [
  'assert(!items.isEmpty(),"nonempty"); pop(); pop();',
  'assert(!items.isEmpty(),"nonempty"); pop(); items.resetToDefault(); pop();',
]) test(`cached pop rechecks unknown and empty callers: ${body}`, () => {
  compare(`circuit pop(): [] { items.popFront(); } export circuit entry(): [] { ${body} }`, facts => {
    assert.deepEqual(facts.paths, []); assert.deepEqual(facts.failedAssertions, []);
  }, { incomplete: "list-pop-outcome-unqualified", mutationHits: true });
});

test("List read replay preserves public sinks under private control", () => {
  compare(`circuit read(): Boolean { return items.isEmpty(); } circuit outer(): Boolean { return read(); }
    export circuit entry(flag: Boolean): Boolean {
      if (disclose(flag)) { outer(); assert(!outer(),"nonempty"); items.popFront(); outer(); return outer(); }
      return false;
    }`, facts => {
    const path = facts.paths.find(path => path.writes.length > 0)!;
    const sinks = path.sinks.filter(sink => sink.kind === "ledger-operation");
    assert.equal(sinks.length, 5);
    assert.ok(sinks.every(sink => names(sink.value).includes("flag")));
  }, { readHits: true });
});

test("guard completion authorizes its guarded pop and is invalidated before the next write", () => {
  compare(`circuit guard(): [] { assert(!items.isEmpty(),"nonempty"); }
    circuit pop(): [] { items.popFront(); }
    export circuit entry(): [] { guard(); pop(); items.pushFront(7 as Field); guard(); pop(); items.pushFront(8 as Field); pop(); }`, (facts, program) => {
    const guard = program.activeSymbols().find(symbol => symbol.name === "guard")!.id;
    assert.deepEqual(facts.paths[0].writes.map(write => write.guards.includes(guard)), [true, false, true, false, false]);
  }, { policies: { authorization: [{ state: "items", guard: "guard" }] }, mutationHits: true });
});

test("assumption-created List regions exhaust explicitly and later reset cannot erase the diagnostic", () => {
  const declarations = Array.from({ length: 256 }, (_, index) => `export ledger list${index}: List<Field>;`).join("\n");
  const assumptions = Array.from({ length: 256 }, (_, index) => `assert(!list${index}.isEmpty(),"nonempty");`).join("\n");
  compare(`${declarations} export circuit entry(): [] { assert(!items.isEmpty(),"first"); ${assumptions} items.resetToDefault(); }`, facts => {
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "list-budget"));
  }, { incomplete: "list-budget" });
});

test("guard-backed Lists cannot bypass the saved-payload value budget through mutation replay", () => {
  // An ordinary default is summary-eligible; a numeric cast would disable replay.
  // Seven values permit recording and one successful replay before the next
  // retained payload exceeds the budget. Expanded evaluation must also fail.
  compare(`circuit push(): [] { items.pushFront(default<Field>); }
    export circuit entry(): [] { assert(!items.isEmpty(),"nonempty"); push(); push(); push(); }`, facts => {
    assert.deepEqual(facts.paths, []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "value-budget" && diagnostic.message.includes("Stored List element snapshot")));
    if (facts.metrics.statefulSummaryHits) assert.equal(facts.metrics.statefulSummaryHits, 2);
  }, { incomplete: "value-budget", maxValues: 7, mutationHits: true });
});
