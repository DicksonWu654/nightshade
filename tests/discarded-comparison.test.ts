import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { cachedSourceObservations, sourceObservations } from "../src/analysis/source-observations.js";
import { discardedComparison as rule } from "../src/detectors/discarded-comparison.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = "import CompactStandardLibrary;\nexport ledger count: Counter;\n";
function checked(body: string, expected: string[], inspect?: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), source = sourceObservations(program, 200000, "comparisons");
    assert.equal(source.complete, true);
    assert.deepEqual(source.observations.filter(item => item.kind === rule.id).map(item => item.metadata.discardedBy), expected);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, expected.length);
    for (const finding of report.findings) {
      assert.equal(finding.severity, "low"); assert.equal(finding.confidence, "high");
      assert.equal(finding.metadata.pathFeasibility, "not-proven");
      assert.equal(finding.metadata.otherGuards, "not-analyzed");
    }
    inspect?.(program, file);
  });
}

test("discarded relational and equality outcomes retain other guards and operand effects", () => {
  checked(`circuit limited(x: Uint<64>): Uint<64> { assert(x < 100,"operand guard"); count.increment(1); return x; }
export circuit entry(x: Uint<64>, y: Uint<64>): [] {
  assert(x != y,"another guard");
  x == y; x != y; x < y; x <= y; x > y; x >= y;
  limited(x) < y; count.increment(1);
}`, Array(7).fill("expression-statement"), program => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(rule.run(facts).length, 7);
      const effects = { writes: facts.paths.map(path => path.writes), assertions: facts.assertionReaches };
      baseline ??= effects; assert.deepEqual(effects, baseline);
      assert.ok(facts.assertionReaches.length >= 2);
    }
  });
});

test("unused bindings and immutable identity alias chains report at the originating comparison", () => checked(`
export circuit entry(x: Uint<64>, y: Uint<64>): [] {
  const unused = x < y;
  const predicate = x >= y; const alias = disclose(predicate as Boolean); const unusedAlias = alias;
  { const predicate = true; assert(predicate,"unrelated shadow"); }
  disclose(x == y); count.increment(1);
}`, ["unused-binding", "unused-alias-chain", "expression-statement"]));

test("consumed predicates, fan-out aliases, captures, aggregates and returned checkers stay quiet", () => checked(`
circuit consume(ok: Boolean): [] { assert(ok,"check"); }
export circuit entry(x: Uint<64>, y: Uint<64>): [] {
  const predicate = x < y; const unused = predicate; const used = predicate; consume(used);
  const captured = x <= y;
  const results = map((ignored: Field): Boolean => captured, [0 as Field]); assert(results[0],"capture");
  const aggregate = [x != y]; assert(aggregate[0],"aggregate");
  const computed = x >= y; const unusedComputation = !computed;
  if (disclose(x < y)) { count.increment(1); }
  count.increment(1);
}
export circuit checker(x: Uint<64>, y: Uint<64>): Boolean { return disclose(x < y); }
`, []));

test("alias-only captures conservatively retain the outer comparison", () => checked(`
export circuit entry(x: Uint<64>, y: Uint<64>): [] {
  const predicate = x < y;
  const results = map((ignored: Field): Boolean => { const unused = predicate; return true; }, [0 as Field]);
  count.increment(1);
}`, []));

test("typed scalar constant comparisons and source-dead statements are excluded", () => checked(`
circuit unused(x: Uint<64>): [] { x < 8; }
export circuit entry(x: Uint<64>): [] {
  const a = 3 as Uint<64>; const b = a; b < 8; true == false;
  if (false) { x < 8; }
  for (const i of 0..0) { x != 0; }
  assert(false,"reject"); x >= 8;
}`, []));

test("sequence prefixes are discarded in returned and asserted sequences; consumed tails stay quiet", () => checked(`
export circuit checker(x: Uint<64>): Boolean {
  x < 10, count.increment(1), x == 9;
  return (x > 0, disclose(x <= 7));
}
export circuit guarded(x: Uint<64>): [] {
  assert((x == 4, x < 7),"tail check");
  const used = (x != 4, x <= 6); assert(used,"tail binding");
  const unused = (x > 1, x >= 2); count.increment(1);
}`, ["sequence-prefix", "expression-statement", "sequence-prefix", "sequence-prefix", "sequence-prefix", "sequence-prefix", "unused-binding"]));

test("a definitely rejecting sequence stops source reach before later components and statements", () => checked(`
export circuit entry(x: Uint<64>): [] {
  x < 10, assert(false,"reject"), x == 9;
  x > 0;
}`, ["sequence-prefix"]));

test("skipped logical operands remain unvisited and optional rejection preserves continuation", () => checked(`
export circuit skipped(x: Uint<64>): [] {
  false && (assert(false,"skipped reject"), x < 8, true);
  true || (assert(false,"skipped reject"), x > 8, false);
  x == 8; count.increment(1);
}
export circuit optional(flag: Boolean, x: Uint<64>): [] {
  flag && (assert(false,"optional reject"), true);
  x != 8; count.increment(1);
}
export circuit optionalOr(flag: Boolean, x: Uint<64>): [] {
  flag || (assert(false,"optional reject"), false);
  x >= 8; count.increment(1);
}`, ["expression-statement", "expression-statement", "expression-statement"]));

test("known conditional arms and required logical operands preserve only evaluated sequence prefixes", () => checked(`
export circuit entry(x: Uint<64>): [] {
  const yes = true ? (x < 8, true) : (x > 8, true);
  const no = false ? (x != 8, true) : (x >= 8, true);
  true && (x <= 8, true); false || (x == 8, true);
  count.increment(1);
}`, Array(4).fill("sequence-prefix")));

test("definite eager-operand and if/for control rejection exclude later comparisons", () => checked(`
circuit use(a: Boolean, b: Boolean): [] { count.increment(1); }
export circuit eagerArgs(x: Uint<64>): [] {
  use((assert(false,"reject"), true), (x < 8, true)); x > 8;
}
export circuit condition(x: Uint<64>): [] {
  if ((assert(false,"reject"), true)) { x < 8; } x > 8;
}
export circuit loop(x: Uint<64>): [] {
  for (const i of (assert(false,"reject"), [0 as Field])) { x < 8; } x > 8;
}`, []));

test("callback lint reach is structural and does not establish nonzero execution", () => checked(`
export circuit entry(x: Uint<64>): [] {
  const results = map((ignored: Field): Boolean => { x < 8; return true; }, [] as Vector<0, Field>);
  count.increment(1);
}`, ["expression-statement"]));

test("comparison source budgets fail closed and keep ordinary source/cache accounting independent", () => checked(`
export circuit entry(x: Uint<64>): [] {
  const predicate = x < 8; const alias = predicate; const unused = alias; count.increment(1);
}`, ["unused-alias-chain"], program => {
  const ordinary = sourceObservations(program), full = sourceObservations(program, 200000, "comparisons");
  assert.deepEqual(sourceObservations(program, full.work, "comparisons"), full);
  const exhausted = sourceObservations(program, full.work - 1, "comparisons");
  assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
  assert.equal(sourceObservations(program, ordinary.work).complete, true);
  assert.equal(sourceObservations(program, ordinary.work, "comparisons").complete, false);
  assert.deepEqual(cachedSourceObservations(program), ordinary);
  assert.deepEqual(cachedSourceObservations(program, "comparisons"), full);
  const facts = new Dataflow(program).analyze(); rule.run(facts);
  assert.deepEqual(cachedSourceObservations(program), ordinary);
}));
