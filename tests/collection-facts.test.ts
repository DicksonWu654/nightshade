import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Policies, Program, detectors, resolvePolicies } from "../src/index.js";
import { MutationCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

type Check = (facts: AnalysisFacts, program: Program) => void;

function compare(source: string, check: Check = () => {}, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const cached = new Dataflow(program).analyze();
    const uncached = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const facts of [cached, uncached, reference]) {
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
    }
    assert.deepEqual(cached.paths, uncached.paths);
    assert.deepEqual(cached.failedAssertions, uncached.failedAssertions);
    assert.deepEqual(cached.completedEntries, uncached.completedEntries);
    assert.deepEqual(cached.failedAssertions, reference.failedAssertions);
    assert.deepEqual(cached.completedEntries, reference.completedEntries);
    assert.deepEqual(semanticPaths(cached), semanticPaths(reference));
    const configured = resolvePolicies(program, policies);
    const findings = (facts: AnalysisFacts) => detectors.flatMap(detector => detector.run(facts, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(findings(cached), findings(uncached));
    assert.deepEqual(findings(cached), findings(reference));
    check(cached, program);
  });
}

const returns = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const constants = (facts: AnalysisFacts) => returns(facts).map(value => value.constant).sort();
const flowNames = (facts: AnalysisFacts) => [...new Set(returns(facts).flatMap(value => value.flows.map(flow => flow.source.name)))].sort();

for (const [name, source, expected] of [
  ["Map reset gives size zero", "export ledger table: Map<Field,Field>; export circuit entry(): Uint<64> { table.resetToDefault(); return table.size(); }", "0"],
  ["Map reset is empty", "export ledger table: Map<Field,Field>; export circuit entry(): Boolean { table.resetToDefault(); return table.isEmpty(); }", "true"],
  ["Map reset makes keys absent", "export ledger table: Map<Field,Field>; export circuit entry(): Boolean { table.resetToDefault(); return table.member(1 as Field); }", "false"],
  ["Set reset gives size zero", "export ledger values: Set<Field>; export circuit entry(): Uint<64> { values.resetToDefault(); return values.size(); }", "0"],
  ["Set reset is empty", "export ledger values: Set<Field>; export circuit entry(): Boolean { values.resetToDefault(); return values.isEmpty(); }", "true"],
  ["Set reset makes values absent", "export ledger values: Set<Field>; export circuit entry(): Boolean { values.resetToDefault(); return values.member(1 as Field); }", "false"],
  ["repeated Map key preserves cardinality", "export ledger table: Map<Field,Field>; export circuit entry(): Uint<64> { table.resetToDefault(); table.insert(1 as Field, 7 as Field); table.insert(1 as Field, 8 as Field); return table.size(); }", "1"],
  ["repeated Map key replaces its value", "export ledger table: Map<Field,Field>; export circuit entry(): Field { table.resetToDefault(); table.insert(1 as Field, 7 as Field); table.insert(1 as Field, 8 as Field); return table.lookup(1 as Field); }", "8"],
  ["repeated Set value preserves cardinality", "export ledger values: Set<Field>; export circuit entry(): Uint<64> { values.resetToDefault(); values.insert(1 as Field); values.insert(1 as Field); return values.size(); }", "1"],
  ["Map insertDefault creates a member", "export ledger table: Map<Field,Field>; export circuit entry(): Boolean { table.resetToDefault(); table.insertDefault(1 as Field); return table.member(1 as Field); }", "true"],
  ["Map insertDefault stores the type default", "export ledger table: Map<Field,Field>; export circuit entry(): Field { table.resetToDefault(); table.insertDefault(1 as Field); return table.lookup(1 as Field); }", "0"],
  ["missing Map removal is a no-op", "export ledger table: Map<Field,Field>; export circuit entry(): Uint<64> { table.resetToDefault(); table.remove(1 as Field); return table.size(); }", "0"],
  ["missing Set removal is a no-op", "export ledger values: Set<Field>; export circuit entry(): Uint<64> { values.resetToDefault(); values.remove(1 as Field); return values.size(); }", "0"],
] as const) test(name, () => compare(source, facts => assert.deepEqual(constants(facts), [expected])));

test("known absent Map lookup aborts the successful path", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(): Field { table.resetToDefault(); return table.lookup(1 as Field); }", facts => {
    assert.deepEqual(facts.paths, []);
    assert.deepEqual(facts.failedAssertions, []);
  });
});

for (const [name, expression] of [
  ["unknown initial Map membership stays unknown", "table.member(1 as Field)"],
  ["unknown initial Map size stays unknown", "table.size()"],
  ["unknown initial Map emptiness stays unknown", "table.isEmpty()"],
  ["unknown initial Set membership stays unknown", "values.member(1 as Field)"],
] as const) test(name, () => compare(`export ledger table: Map<Field,Field>; export ledger values: Set<Field>; export circuit entry(): ${expression.includes("size") ? "Uint<64>" : "Boolean"} { return ${expression}; }`, facts => {
  assert.equal(returns(facts)[0].constant, undefined);
}));

test("negated member conditions refine the present branch", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(): Field { if (!table.member(1 as Field)) return 7 as Field; return table.lookup(1 as Field); }", facts => {
    assert.equal(facts.paths.length, 2);
    assert.ok(constants(facts).includes("7"));
  });
});

for (const [name, condition] of [
  ["member condition refines lookup", "table.member(1 as Field)"],
  ["member equality with true refines lookup", "table.member(1 as Field) == true"],
  ["member inequality with false refines lookup", "table.member(1 as Field) != false"],
] as const) test(name, () => compare(`export ledger table: Map<Field,Field>; export circuit entry(): Field { if (${condition}) return table.lookup(1 as Field); return 0 as Field; }`, facts => {
  assert.equal(facts.paths.length, 2);
  assert.ok(constants(facts).includes("0"));
}));

test("empty conditions refine size and membership", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(): Uint<64> { if (table.isEmpty()) return table.size(); table.remove(1 as Field); return table.size(); }", facts => {
    assert.equal(facts.paths.length, 2);
    assert.ok(constants(facts).includes("0"));
  });
});

test("nested Map reset preserves the ancestor entry", () => {
  compare("export ledger table: Map<Field,Map<Field,Field>>; export circuit entry(): Uint<64> { table.resetToDefault(); table.insertDefault(1 as Field); table.lookup(1 as Field).insert(2 as Field, 3 as Field); table.lookup(1 as Field).resetToDefault(); return table.size(); }", facts => {
    assert.deepEqual(constants(facts), ["1"]);
  });
});

test("ancestor replacement invalidates stale nested facts", () => {
  compare("export ledger table: Map<Field,Map<Field,Field>>; export circuit entry(): Uint<64> { table.resetToDefault(); table.insertDefault(1 as Field); table.lookup(1 as Field).insert(2 as Field, 3 as Field); table.insertDefault(1 as Field); return table.lookup(1 as Field).size(); }", facts => {
    assert.deepEqual(constants(facts), ["0"]);
  });
});

test("unknown-key replacement invalidates matching nested regions", () => {
  compare("export ledger table: Map<Field,Map<Field,Field>>; export circuit entry(key: Field): Boolean { table.resetToDefault(); table.insertDefault(1 as Field); table.lookup(1 as Field).insert(2 as Field, 3 as Field); table.insert(disclose(key), default<Map<Field,Field>>); return table.lookup(1 as Field).member(2 as Field); }", facts => {
    assert.equal(returns(facts)[0].constant, undefined);
  });
});

test("Map lookups are value snapshots rather than live projections", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(): Field { table.resetToDefault(); table.insert(1 as Field, 7 as Field); const before = table.lookup(1 as Field); table.insert(1 as Field, 8 as Field); return before; }", facts => {
    assert.deepEqual(constants(facts), ["7"]);
  });
});

test("Map arguments are evaluated left to right before insertion", () => {
  compare("export ledger table: Map<Field,Field>; circuit key(): Field { table.insert(0 as Field, 9 as Field); return 1 as Field; } circuit value(): Field { return table.lookup(0 as Field); } export circuit entry(): Field { table.resetToDefault(); table.insert(key(), value()); return table.lookup(1 as Field); }", facts => {
    assert.deepEqual(constants(facts), ["9"]);
  });
});

test("repeated immutable dynamic keys retain collection membership and values", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(key: Field): Field { table.resetToDefault(); table.insert(disclose(key), 7 as Field); assert(table.member(disclose(key)), \"inserted\"); return table.lookup(disclose(key)); }", facts => {
    assert.deepEqual(constants(facts), ["7"]);
    assert.equal(facts.paths.length, 1);
  });
});

for (const [name, operations, query] of [
  ["dynamic insertion may populate a literal key", "table.resetToDefault(); table.insert(disclose(key), 7 as Field);", "1 as Field"],
  ["literal removal may delete a dynamic key", "table.resetToDefault(); table.insert(disclose(key), 7 as Field); table.remove(1 as Field);", "disclose(key)"],
  ["literal insertion may restore a dynamic key", "table.remove(disclose(key)); table.insert(1 as Field, 7 as Field);", "disclose(key)"],
] as const) test(name, () => compare(`export ledger table: Map<Field,Field>; export circuit entry(key: Field): Boolean { ${operations} return table.member(${query}); }`, facts => {
  assert.equal(facts.paths.length, 1);
  assert.equal(returns(facts)[0].constant, undefined);
}));

test("alias writes in both directions retain possible values and provenance", () => {
  for (const [first, second] of [["disclose(key)", "1 as Field"], ["1 as Field", "disclose(key)"]]) {
    compare(`export ledger table: Map<Field,Field>; export circuit entry(key: Field, secret: Field): Field { table.insert(${first}, 7 as Field); table.insert(${second}, disclose(secret)); return table.lookup(${first}); }`, facts => {
      assert.equal(returns(facts)[0].constant, undefined);
      assert.deepEqual(flowNames(facts), ["key", "secret"]);
    });
  }
});

test("nested dynamic receiver updates invalidate alias membership, size and emptiness", () => {
  for (const [first, second] of [["1 as Field", "disclose(key)"], ["disclose(key)", "1 as Field"], ["disclose(key)", "disclose(other)"]]) {
    compare(`export ledger table: Map<Field,Map<Field,Field>>; export circuit entry(key: Field, other: Field): [Boolean, Uint<64>, Boolean] {
      table.insertDefault(${first});
      table.lookup(${second}).insert(2 as Field, 7 as Field);
      return [table.lookup(${first}).member(2 as Field), table.lookup(${first}).size(), table.lookup(${first}).isEmpty()];
    }`, facts => {
      assert.equal(facts.paths.length, 1);
      assert.ok(returns(facts)[0].items!.every(item => item.constant === undefined));
    });
  }
});

test("private keys and values remain provenance on wildcard lookups", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(key: Field, secret: Field): Field { table.insert(disclose(key), disclose(secret)); return table.lookup(1 as Field); }", facts => {
    assert.deepEqual(flowNames(facts), ["key", "secret"]);
  });
});

test("private control remains attached to collection membership", () => {
  compare("export ledger table: Map<Field,Field>; export circuit entry(flag: Boolean): Boolean { table.resetToDefault(); if (disclose(flag)) table.insert(1 as Field, 7 as Field); return table.member(1 as Field); }", facts => {
    assert.equal(facts.paths.length, 2);
    assert.ok(returns(facts).every(value => value.flows.some(flow => flow.source.name === "flag")));
  });
});

test("cached calls preserve Map mutation argument order and replacement", () => {
  compare("export ledger table: Map<Field,Field>; export ledger marker: Field; circuit put(value: Field): Field { table.insert(1 as Field, disclose(value)); return value; } circuit remember(value: Field): [] { marker = disclose(value); } export circuit entry(first: Field, second: Field): Field { table.resetToDefault(); table.insert(1 as Field, disclose(second)); for (const iteration of 0..3) remember(put(first)); return table.lookup(1 as Field); }", (facts, program) => {
    const put = program.activeSymbols().find(symbol => symbol.name === "put")!;
    const remember = program.activeSymbols().find(symbol => symbol.name === "remember")!;
    const eligibility = new MutationCircuitEligibility(program);
    assert.equal(eligibility.allows(put.id), false);
    assert.equal(eligibility.allows(remember.id), true);
    assert.ok(facts.metrics.statefulSummaryHits > 0);
    assert.deepEqual(flowNames(facts), ["first"]);
  });
});

test("known Counter method underflow prunes the path", () => {
  compare("export ledger count: Counter; export circuit entry(): [] { count.resetToDefault(); count.decrement(1); }", facts => assert.deepEqual(facts.paths, []));
});

test("known Counter compound-assignment underflow prunes the path", () => {
  compare("export ledger count: Counter; export circuit entry(): [] { count.resetToDefault(); count -= 1; }", facts => assert.deepEqual(facts.paths, []));
});

test("cached Counter decrement rechecks underflow against current storage", () => {
  compare("export ledger count: Counter; circuit take(): [] { count.decrement(1); } export circuit entry(): [] { count.resetToDefault(); count.increment(1); take(); count.increment(1); take(); take(); }", facts => {
    assert.ok(facts.metrics.statefulSummaryHits >= 2);
    assert.deepEqual(facts.paths, []);
  });
});

test("collection writes retain authorization guard policy semantics", () => {
  const policies: Policies = { authorization: [{ state: "table", guard: "guard" }] };
  compare('export ledger allowed: Boolean; export ledger table: Map<Field,Field>; circuit guard(): [] { assert(allowed, "allowed"); } export circuit entry(flag: Boolean): [] { if (disclose(flag)) guard(); table.insert(1 as Field, 7 as Field); }', (facts, program) => {
    const findings = detectors.flatMap(detector => detector.run(facts, resolvePolicies(program, policies)));
    assert.equal(findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 1);
  }, policies);
});

test("collection writes retain declared-secret publication policy semantics", () => {
  const policies: Policies = { secrets: [{ circuit: "entry", parameter: "secret" }] };
  compare("export ledger table: Map<Field,Field>; export circuit entry(secret: Field): [] { table.insert(1 as Field, disclose(secret)); }", (facts, program) => {
    const findings = detectors.flatMap(detector => detector.run(facts, resolvePolicies(program, policies)));
    assert.ok(findings.some(finding => finding.detectorId === "declared-secret-publication"));
  }, policies);
});
