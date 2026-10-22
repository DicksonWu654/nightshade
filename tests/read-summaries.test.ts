import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts, program: Program) => void): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const facts = ["instructions", "expressions"].flatMap(engine => [true, false].map(cached =>
      new Dataflow(program, 20000, 256, 50000, engine as "instructions" | "expressions", cached).analyze()));
    for (const result of facts) {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
      assert.deepEqual(result.failedAssertions, facts[0].failedAssertions);
      assert.deepEqual(semanticPaths(result), semanticPaths(facts[0]));
    }
    // Within each engine, compare every trace and call path as well as semantic facts.
    assert.deepEqual(facts[0].paths, facts[1].paths);
    assert.deepEqual(facts[2].paths, facts[3].paths);
    for (const result of [facts[0], facts[2]]) {
      assert.ok(result.metrics.readSummaryHits > 0, "the differential must exercise read replay");
      assert.ok(result.metrics.summaryEntries <= 256);
      assert.ok(result.metrics.summaryEffects <= 4096);
      check(result, program);
    }
    for (const result of [facts[1], facts[3]]) assert.equal(result.metrics.readSummaryHits, 0);
  });
}

const output = (facts: AnalysisFacts) => facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
const names = (facts: AnalysisFacts, ids: string[]) => ids.map(id => facts.program.symbols.get(id)!.name);

test("read summaries reuse scalar, field and derived values with complete provenance", () => {
  compare(`
    struct Box { value: Field; }
    export ledger scalar: Field;
    export ledger box: Box;
    circuit direct(): Field { return scalar; }
    circuit field(): Field { return box.value; }
    circuit derived(): Field { return scalar + box.value; }
    export circuit entry(secret: Field): [Field, Field, Field] {
      scalar = disclose(secret); box = Box { value: 3 as Field };
      direct(); field(); derived(); return [direct(), field(), derived()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 3);
    const values = output(facts).items!;
    assert.equal(values[1].constant, "3");
    assert.deepEqual(values[0].flows.map(flow => flow.source.name), ["secret"]);
    assert.deepEqual(values[2].flows.map(flow => flow.source.name), ["secret"]);
    assert.equal(values[0].flows[0].form, "raw");
    assert.equal(values[2].flows[0].form, "derived");
  });
});

test("writes and resets invalidate read roots while unrelated writes retain reuse", () => {
  compare(`
    export ledger scalar: Field; export ledger other: Field;
    circuit read(): Field { return scalar; }
    export circuit entry(): [Field, Field, Field] {
      scalar = 1 as Field; read(); read(); other = 9 as Field; const first = read();
      scalar = 2 as Field; read(); const second = read();
      scalar.resetToDefault(); read(); return [first, second, read()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 4);
    assert.deepEqual(output(facts).items!.map(value => value.constant), ["1", "2", "0"]);
  });
});

test("transitive read roots invalidate an enclosing cached return", () => {
  compare(`
    export ledger first: Field; export ledger second: Field;
    circuit leaf(): Field { return second; }
    circuit pair(): [Field, Field] { return [first, leaf()]; }
    export circuit entry(): [[Field, Field], [Field, Field], [Field, Field]] {
      first = 1 as Field; second = 2 as Field; pair(); const before = pair();
      second = 3 as Field; pair(); const changed = pair();
      first = 4 as Field; pair(); return [before, changed, pair()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 4);
    assert.deepEqual(output(facts).items!.map(value => value.items!.map(item => item.constant)), [["1", "2"], ["1", "3"], ["4", "3"]]);
  });
});

test("same-revision lookup membership refinement invalidates a read snapshot", () => {
  compare(`
    export ledger table: Map<Field, Field>;
    circuit query(): Boolean { return table.member(default<Field>); }
    export circuit entry(): [Boolean, Boolean, Boolean] {
      const before = query(); table.lookup(default<Field>); return [before, query(), query()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 1);
    assert.deepEqual(output(facts).items!.map(value => value.constant), [undefined, "true", "true"]);
    assert.deepEqual(facts.paths[0].writes, []);
  });
});

test("collection mutation and reset revisions invalidate cached membership", () => {
  compare(`
    export ledger table: Map<Field, Field>;
    circuit query(): Boolean { return table.member(default<Field>); }
    export circuit entry(): [Boolean, Boolean, Boolean, Boolean] {
      table.resetToDefault(); query(); const empty = query();
      table.insert(default<Field>, default<Field>); query(); const present = query();
      table.remove(default<Field>); query(); const removed = query();
      table.resetToDefault(); query(); return [empty, present, removed, query()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 4);
    assert.deepEqual(output(facts).items!.map(value => value.constant), ["false", "true", "false", "false"]);
  });
});

test("Counter and collection summary returns use current receiver revisions", () => {
  compare(`
    export ledger count: Counter; export ledger values: Set<Field>;
    circuit query(): [Uint<64>, Boolean, Uint<64>] { return [count.read(), values.isEmpty(), values.size()]; }
    export circuit entry(): [[Uint<64>, Boolean, Uint<64>], [Uint<64>, Boolean, Uint<64>]] {
      count.resetToDefault(); values.resetToDefault(); query(); const before = query();
      count.increment(2); values.insert(default<Field>); query(); return [before, query()];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    assert.deepEqual(output(facts).items!.map(value => value.items!.map(item => item.constant)), [["0", "true", "0"], ["2", "false", "1"]]);
  });
});

test("read summaries retain every public query sink and distinct private arguments", () => {
  compare(`
    export ledger table: Map<Field, Field>;
    circuit query(key: Field): Boolean { return table.member(disclose(key)); }
    export circuit entry(first: Field, second: Field): Boolean {
      query(first); query(second); query(first); return query(second);
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    const sinks = facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation");
    assert.equal(sinks.length, 4);
    assert.deepEqual(sinks.map(sink => sink.value.flows.map(flow => flow.source.name)), [["first"], ["second"], ["first"], ["second"]]);
    assert.ok(sinks.every(sink => sink.name === "table.member"));
    assert.notEqual(sinks[0].value.flows[0].source.id, sinks[1].value.flows[0].source.id);
    assert.equal(sinks[0].value.flows[0].source.id, sinks[2].value.flows[0].source.id);
  });
});

test("nested read replay records sinks and completion order in enclosing summaries", () => {
  compare(`
    export ledger seen: Set<Field>; export ledger marker: Field;
    circuit query(key: Field): Boolean { return seen.member(disclose(key)); }
    circuit outer(key: Field): Boolean { query(key); return query(key); }
    export circuit entry(secret: Field): [Boolean, Boolean, Boolean] {
      const first = query(secret); const second = outer(secret); const third = outer(secret);
      marker = default<Field>; return [first, second, third];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    const sinks = facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation");
    assert.equal(sinks.length, 5);
    assert.deepEqual(sinks.map(sink => names(facts, sink.callPath)), [
      ["entry", "query"], ["entry", "outer", "query"], ["entry", "outer", "query"],
      ["entry", "outer", "query"], ["entry", "outer", "query"],
    ]);
    assert.ok(sinks.every(sink => sink.value.flows[0].source.name === "secret"));
    assert.deepEqual(names(facts, facts.paths[0].writes[0].guards), ["query", "outer"]);
  });
});

test("cached read sinks rebase to a different nested caller", () => {
  compare(`
    export ledger seen: Set<Field>; export ledger key: Field; export ledger marker: Field;
    circuit query(): Boolean { return seen.member(key); }
    circuit outer(): Boolean { return query(); }
    export circuit entry(secret: Field): [Boolean, Boolean, Boolean] {
      key = disclose(secret); const first = query(); const second = outer(); const third = outer();
      marker = default<Field>; return [first, second, third];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    const sinks = facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation");
    assert.deepEqual(sinks.map(sink => names(facts, sink.callPath)), [["entry", "query"], ["entry", "outer", "query"], ["entry", "outer", "query"]]);
    assert.ok(sinks.every(sink => sink.value.flows[0].source.name === "secret"));
    assert.deepEqual(names(facts, facts.paths[0].writes[1].guards), ["query", "outer"]);
  });
});

test("read replay preserves caller guards and cannot restore an invalidated guard", () => {
  compare(`
    export ledger authorized: Boolean; export ledger scalar: Field; export ledger sensitive: Field;
    circuit guard(): [] { assert(authorized, "authorized"); }
    circuit read(): Field { return scalar; }
    export circuit entry(): [] {
      guard(); read(); read(); sensitive = default<Field>;
      authorized = false; read(); sensitive = 1 as Field;
    }
  `, (facts, program) => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    const writes = facts.paths[0].writes.filter(write => program.symbols.get(write.ledger)!.name === "sensitive");
    assert.ok(names(facts, writes[0].guards).includes("guard"));
    assert.ok(!names(facts, writes[1].guards).includes("guard"));
    const policies = resolvePolicies(program, { authorization: [{ state: "sensitive", guard: "guard" }] });
    const findings = detectors.flatMap(detector => detector.run(facts, policies)).filter(finding => finding.detectorId === "unguarded-sensitive-state-write");
    assert.equal(findings.length, 1);
  });
});

test("cached returned Boolean evidence refines only its original collection revision", () => {
  compare(`
    export ledger table: Map<Field, Field>;
    circuit query(): Boolean { return table.member(default<Field>); }
    export circuit entry(): Boolean {
      query(); const before = query(); table.insert(default<Field>, default<Field>);
      assert(!before, "originally absent"); query(); return query();
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    assert.equal(output(facts).constant, "true");
    assert.deepEqual(facts.failedAssertions, []);
  });
});

test("asserting cached Boolean evidence establishes same-revision collection presence", () => {
  compare(`
    export ledger table: Map<Field, Field>;
    circuit query(): Boolean { return table.member(default<Field>); }
    export circuit entry(): Boolean {
      query(); const present = query(); assert(present, "present"); return table.member(default<Field>);
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 1);
    assert.equal(output(facts).constant, "true");
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(facts.paths[0].writes, []);
  });
});

test("asserting a cached read return retains ledger hash-binding evidence", () => {
  compare(`
    export ledger digest: Bytes<32>;
    circuit matches(secret: Field): Boolean { return persistentHash<Field>(secret) == digest; }
    export circuit entry(secret: Field): Field {
      matches(secret); const matched = matches(secret); assert(matched, "bound"); return disclose(secret);
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 1);
    assert.equal(facts.paths[0].bindings.length, 1);
    assert.equal(facts.paths[0].bindings[0].source.name, "secret");
    assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 1);
  });
});

test("changed caller constraints separate cached derived read outcomes", () => {
  compare(`
    export ledger scalar: Field;
    circuit read(value: Field): Field { return scalar + value; }
    export circuit entry(secret: Field): [Field, Field, Field] {
      scalar = 2 as Field; const before = read(secret); read(secret);
      assert(secret == (1 as Field), "fixed"); const after = read(secret); return [before, after, read(secret)];
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    assert.deepEqual(output(facts).items!.map(value => value.constant), [undefined, "3", "3"]);
  });
});

test("read summaries separate ambient private control and retain its provenance", () => {
  compare(`
    export ledger scalar: Field;
    circuit read(): Field { return scalar; }
    export circuit entry(flag: Boolean): [Field, Field] {
      scalar = 5 as Field; read(); read();
      if (disclose(flag)) { const first = read(); return [first, read()]; }
      else { const first = read(); return [first, read()]; }
    }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 3);
    assert.equal(facts.paths.length, 2);
    assert.ok(facts.paths.every(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.items!.every(value => value.flows.some(flow => flow.source.name === "flag"))));
  });
});

test("read summaries retain distinct private provenance across entrypoints", () => {
  compare(`
    export ledger scalar: Field;
    circuit read(): Field { return scalar; }
    export circuit first(secret: Field): [Field, Field] { scalar = disclose(secret); return [read(), read()]; }
    export circuit second(secret: Field): [Field, Field] { scalar = disclose(secret); return [read(), read()]; }
  `, facts => {
    assert.equal(facts.metrics.readSummaryHits, 2);
    assert.equal(facts.paths.length, 2);
    const sources = facts.paths.map(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.items![0].flows[0].source.id);
    assert.notEqual(sources[0], sources[1]);
  });
});
