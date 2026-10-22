import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";
import { informationalDetectors } from "../src/detectors/informational.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, incomplete = false): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary; export ledger table: Map<Field,Field>; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const cached = new Dataflow(program).analyze();
    const uncached = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    assert.deepEqual(cached.paths, uncached.paths);
    assert.deepEqual(semanticPaths(cached), semanticPaths(reference));
    for (const facts of [cached, uncached, reference]) {
      assert.deepEqual(facts.diagnostics, cached.diagnostics);
      assert.deepEqual(facts.failedAssertions, cached.failedAssertions);
      assert.deepEqual(facts.completedEntries, incomplete ? [] : program.entries);
      if (!incomplete) assert.deepEqual(facts.diagnostics, []);
    }
    check(cached);
  });
}

const constants = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value.constant)).sort();
const securityDetectors = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions" && !informationalDetectors.some(rule => rule.id === detector.id));

for (const query of ["member(1 as Field)", "isEmpty()", "size()"]) test(`wildcard receivers do not imply equal ${query} results`, () => {
  compare(`export ledger nested: Map<Field,Map<Field,Field>>; export circuit entry(first: Field,second: Field): Boolean { const left = nested.lookup(disclose(first)).${query}; const right = nested.lookup(disclose(second)).${query}; assert(left != right,"different entries"); return true; }`, facts => {
    assert.deepEqual(constants(facts), ["true"]);
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(securityDetectors.flatMap(detector => detector.run(facts)), []);
  });
});

test("wildcard scalar lookups do not imply equal stored values", () => {
  compare('export circuit entry(first: Field,second: Field): Boolean { const left = table.lookup(disclose(first)); const right = table.lookup(disclose(second)); assert(left != right,"different entries"); return true; }', facts => {
    assert.deepEqual(constants(facts), ["true"]);
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(securityDetectors.flatMap(detector => detector.run(facts)), []);
  });
});

test("the same concrete collection and revision retain query identity", () => {
  compare('export circuit entry(): Boolean { const left = table.member(1 as Field); const right = table.member(1 as Field); assert(left != right,"same query"); return true; }', facts => {
    assert.deepEqual(facts.paths, []);
    assert.equal(facts.failedAssertions.length, 1);
  });
});

for (const query of ["member(1 as Field)", "isEmpty()"]) test(`saved ${query} before a mutation keeps both original outcomes`, () => {
  compare(`export circuit entry(): Uint<8> { const before = table.${query}; table.insert(1 as Field,7 as Field); if (before) return 1; return 0; }`, facts => {
    assert.deepEqual(constants(facts), ["0", "1"]);
  });
});

test("a saved absence predicate does not erase a subsequent insertion", () => {
  compare('export circuit entry(): Field { const before = table.member(1 as Field); table.insert(1 as Field,7 as Field); assert(!before,"originally absent"); return table.lookup(1 as Field); }', facts => {
    assert.deepEqual(constants(facts), ["7"]);
  });
});

test("a saved emptiness predicate does not reset post-write cardinality", () => {
  compare('export circuit entry(): Uint<64> { const before = table.isEmpty(); table.resetToDefault(); table.insert(1 as Field,7 as Field); assert(before,"originally empty"); return table.size(); }', facts => {
    assert.deepEqual(constants(facts), ["1"]);
  });
});

test("successful lookup proves presence on the same storage revision", () => {
  compare("export circuit entry(): Boolean { table.lookup(1 as Field); return table.member(1 as Field); }", facts => {
    assert.deepEqual(constants(facts), ["true"]);
  });
});

test("cached Map transfer replay replaces a value in current storage", () => {
  compare("circuit put(key: Field,value: Field): [] { table.insert(disclose(key),disclose(value)); } export circuit entry(first: Field,second: Field): Field { table.resetToDefault(); put(1 as Field,first); put(1 as Field,second); put(1 as Field,first); return table.lookup(1 as Field); }", facts => {
    assert.equal(facts.metrics.statefulSummaryHits, 1);
    const output = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.deepEqual([...new Set(output.flows.map(flow => flow.source.name))], ["first"]);
  });
});

test("asserted absence makes a following lookup unable to succeed", () => {
  compare('export circuit entry(): Field { assert(table.member(1 as Field) == false,"absent"); return table.lookup(1 as Field); }', facts => {
    assert.deepEqual(facts.paths, []);
    assert.deepEqual(facts.failedAssertions, []);
  });
});

test("constructors alone seed initial collection defaults", () => {
  compare('constructor() { assert(table.isEmpty(),"initially empty"); assert(table.size() == 0,"zero"); } export circuit entry(): Uint<64> { return table.size(); }', facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(constants(facts), [undefined]);
  });
});

test("known missing nested receivers abort before their mutation", () => {
  compare("export ledger nested: Map<Field,Map<Field,Field>>; export circuit entry(): [] { nested.resetToDefault(); nested.lookup(1 as Field).insert(2 as Field,3 as Field); }", facts => {
    assert.deepEqual(facts.paths, []);
  });
});

test("collection fact exhaustion diagnoses incomplete analysis rather than absence", () => {
  compare("export circuit entry(): Uint<64> { table.resetToDefault(); for (const index of 0..256) table.insert(index as Field,0 as Field); table.insert(256 as Field,0 as Field); return table.size(); }", facts => {
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "collection-budget"));
  }, true);
});
