import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const maximum = 18446744073709551615n;

function compare(source: string, check: (facts: AnalysisFacts, cached: boolean) => void): void {
  withFiles({ "main.compact": `pragma language_version 0.26.0; import { Counter } from CompactStandardLibrary; export ledger count: Counter; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, path);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(path);
    const results: AnalysisFacts[] = [];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.failedAssertions, [], "ledger arithmetic failure must not invent an assertion failure");
      const findings = detectors.flatMap(detector => detector.run(facts));
      assert.deepEqual(findings.map(finding => [finding.detectorId, finding.metadata.certainty]),
        facts.paths.length ? [] : [["impossible-assertion", "no-successful-path"]]);
      check(facts, cached);
      results.push(facts);
    }
    assert.deepEqual(results[0].paths, results[1].paths);
    assert.deepEqual(results[2].paths, results[3].paths);
    for (const facts of results.slice(1)) assert.deepEqual(semanticPaths(facts), semanticPaths(results[0]));
  });
}

const cases = [
  ["reach maximum", maximum - 1n, "+", 1n, maximum],
  ["zero increment at maximum", maximum, "+", 0n, maximum],
  ["increment past maximum", maximum, "+", 1n, undefined],
  ["maximum Uint16 increment fits", maximum - 65535n, "+", 65535n, maximum],
  ["maximum Uint16 increment overflows", maximum - 65534n, "+", 65535n, undefined],
  ["zero decrement at maximum", maximum, "-", 0n, maximum],
  ["maximum Uint16 decrement", maximum, "-", 65535n, maximum - 65535n],
  ["decrement to zero", 65535n, "-", 65535n, 0n],
  ["zero decrement at zero", 0n, "-", 0n, 0n],
  ["decrement below zero", 0n, "-", 1n, undefined],
] as const;

for (const style of ["method", "compound"] as const) for (const [name, initial, operator, amount, expected] of cases) {
  test(`qualified Counter ${style}: ${name}`, qualified, () => {
    const operation = style === "method" ? `count.${operator === "+" ? "increment" : "decrement"}(amount);` : `count ${operator}= amount;`;
    // This assumption characterizes entry storage; it does not establish that
    // the high representation is transaction-reachable from the constructor.
    compare(`export circuit entry(): Uint<64> {
      const boundary: Uint<64> = ${initial}; const amount: Uint<16> = ${amount};
      assert(count.read() == boundary, "fixed initial boundary");
      ${operation} return count.read();
    }`, facts => {
      assert.equal(facts.paths.length, expected === undefined ? 0 : 1);
      if (expected !== undefined) {
        const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
        assert.equal(returned.type, "Uint<64>");
        assert.equal(returned.constantKind, "integer");
        assert.equal(returned.constant, expected.toString());
        assert.equal(facts.paths[0].writes.length, 1);
      }
    });
  });
}

for (const style of ["method", "compound"] as const) test(`qualified Counter ${style} helper rechecks overflow after a successful update`, qualified, () => {
  const operation = style === "method" ? "count.increment(amount);" : "count += amount;";
  compare(`circuit bump(amount: Uint<16>): [] { ${operation} }
    export circuit entry(): Uint<64> {
      const boundary: Uint<64> = ${maximum - 1n}; const one: Uint<16> = 1;
      assert(count.read() == boundary, "fixed initial boundary");
      bump(one); bump(one); return count.read();
    }`, (facts, cached) => {
    assert.deepEqual(facts.paths, []);
    if (cached && style === "method") assert.ok(facts.metrics.statefulSummaryHits > 0, "second call must actually replay the cached mutation");
    // Compound assignments remain excluded by the existing summary eligibility;
    // they execute normally in all four modes rather than claiming a cache hit.
    else assert.equal(facts.metrics.summaryHits, 0);
  });
});

test("qualified Counter maximum update preserves a saved pre-update snapshot", qualified, () => {
  compare(`export circuit entry(): [Uint<64>, Uint<64>] {
    const boundary: Uint<64> = ${maximum - 1n}; const one: Uint<16> = 1;
    const saved = count.read(); assert(saved == boundary, "fixed initial boundary");
    count.increment(one); return [saved, count.read()];
  }`, facts => {
    assert.equal(facts.paths.length, 1);
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.deepEqual(returned.items!.map(value => value.constant), [(maximum - 1n).toString(), maximum.toString()]);
  });
});

test("qualified Counter unknown amount retains a possible successful path without wrapping a constant", qualified, () => {
  compare(`export circuit entry(amount: Uint<16>): Uint<64> {
    const boundary: Uint<64> = ${maximum}; assert(count.read() == boundary, "fixed initial boundary");
    count.increment(disclose(amount)); return count.read();
  }`, facts => {
    assert.equal(facts.paths.length, 1, "amount zero remains possible");
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(returned.constant, undefined);
    assert.ok(returned.flows.some(flow => flow.source.name === "amount"));
  });
});

test("qualified Counter zero updates retain contents and cached replay still records writes and invalidates guards", qualified, () => {
  compare(`circuit gate(): [] { assert(count.read() != 0, "nonzero"); }
    circuit zero(): [] { count.increment(0); }
    export circuit entry(): [Uint<64>, Uint<64>] {
      gate(); const saved = count.read(); zero(); zero();
      return [saved, count.read()];
    }`, (facts, cached) => {
    const path = facts.paths[0];
    assert.equal(path.writes.length, 2);
    const [first, second] = path.writes;
    assert.ok(first.guards.some(id => facts.program.symbols.get(id)?.name === "gate"));
    assert.equal(second.guards.some(id => facts.program.symbols.get(id)?.name === "gate"), false);
    assert.equal(first.before.identity, first.after.identity);
    assert.equal(first.after.identity, second.after.identity);
    assert.equal(second.before.region!.revision, first.before.region!.revision! + 1);
    const returned = path.sinks.find(sink => sink.kind === "exported-return")!.value.items!;
    assert.equal(returned[0].identity, returned[1].identity);
    if (cached) assert.ok(facts.metrics.statefulSummaryHits > 0);
  });
});
