import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

test("positive unsigned spends cannot follow a missing-entry zero allowance history", () => {
  const source = `import CompactStandardLibrary;
ledger table: Map<Field,Uint<128>>;
export ledger output: Uint<128>;
circuit allowance(key: Field): Uint<128> { if (!table.member(disclose(key))) { return 0; } return table.lookup(disclose(key)); }
export circuit spend(key: Field, value: Uint<128>): [] {
  if (disclose(value > 0)) { const current = allowance(key); assert(current >= value, "enough"); output = disclose(current - value as Uint<128>); }
}
export circuit contradiction(value: Uint<128>): [] { assert(value > 0, "positive"); assert((0 as Uint<128>) >= value, "zero bound"); output = 1; }
export circuit corrected(value: Uint<128>): [] { assert(value >= 0, "nonnegative"); assert((0 as Uint<128>) >= value, "zero bound"); output = 1; }
export circuit independent(first: Uint<128>, second: Uint<128>): [] { assert(first > 0, "positive"); assert((0 as Uint<128>) >= second, "zero bound"); output = 1; }
export circuit mixed(value: Uint<8>): [] { assert(value > (0 as Uint<16>), "positive"); assert((0 as Uint<32>) >= value, "zero bound"); output = 1; }
new type Word<#N> = Uint<N>;
export circuit nominal(value: Word<8>): [] { assert(value > (0 as Word<16>), "positive"); assert((0 as Word<32>) >= value, "zero bound"); output = 1; }
export circuit upper(value: Uint<8>): [] { assert(value < 5, "below"); assert(value >= 5, "above"); output = 1; }
export circuit negated(value: Uint<8>): [] { assert(!(value <= 0), "positive"); assert(value < 1, "below one"); output = 1; }
export circuit boundary(value: Uint<8>): [] { assert(value >= 5, "lower"); assert(value <= 5, "upper"); output = 1; }
export circuit wide(value: Uint<16>): [] { assert(value > 255, "wide"); assert(value <= 300, "upper"); output = 1; }
`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file);
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const counts = Object.fromEntries(program.entries.map(entry => [program.symbols.get(entry)!.name, facts.paths.filter(path => path.entry === entry).length]));
      assert.deepEqual(counts, { spend: 2, contradiction: 0, corrected: 1, independent: 1,
        mixed: 0, nominal: 0, upper: 0, negated: 0, boundary: 1, wide: 1 });
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});
