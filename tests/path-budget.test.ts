import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const fixtures = [
  { name: "statement return alternatives", paths: 2, source: "export circuit entry(flag: Boolean): Field { if (disclose(flag)) { return 1 as Field; } else { return 2 as Field; } }" },
  { name: "conditional expression in the final return", paths: 2, source: "export circuit entry(flag: Boolean): Field { return disclose(flag) ? 1 as Field : 2 as Field; }" },
  { name: "nested call alternatives in the final return", paths: 2, source: "circuit choose(flag: Boolean): Field { return disclose(flag) ? 1 as Field : 2 as Field; } export circuit entry(flag: Boolean): Field { return choose(flag); }" },
  { name: "cartesian nested returns", paths: 4, source: "circuit choose(flag: Boolean): Field { return disclose(flag) ? 1 as Field : 2 as Field; } export circuit entry(first: Boolean, second: Boolean): [Field,Field] { return [choose(first),choose(second)]; }" },
  { name: "completed history plus later expansion", paths: 3, source: "export circuit entry(first: Boolean, second: Boolean): Field { if (disclose(first)) { return 1 as Field; } else { return disclose(second) ? 2 as Field : 3 as Field; } }" },
];
for (const fixture of fixtures) test(`path budget counts current and expanded histories: ${fixture.name}`, qualified, () => {
  withFiles({ "main.compact": `pragma language_version 0.26.0;\n${fixture.source}\n` }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file);
    const complete = [];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const exact = new Dataflow(program, 20000, fixture.paths, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.equal(exact.completedEntries.length, 1);
      assert.equal(exact.paths.length, fixture.paths);
      complete.push(exact);
      for (const limit of new Set([1, fixture.paths - 1])) {
        const limited = new Dataflow(program, 20000, limit, 50000, engine, cached, cached).analyze();
        assert.ok(limited.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"), `${engine}/${cached}/${limit} must not return a clean report`);
        assert.deepEqual(limited.completedEntries, []);
        assert.ok(limited.paths.length <= limit, "completed evidence cannot exceed the effective path bound");
      }
    }
    assert.deepEqual(complete[0].paths, complete[1].paths);
    assert.deepEqual(complete[2].paths, complete[3].paths);
    for (const facts of complete.slice(1)) assert.deepEqual(semanticPaths(facts), semanticPaths(complete[0]));
  });
});

test("a single successful path still fits a one-path budget with repeated summary replay", qualified, () => {
  withFiles({ "main.compact": "pragma language_version 0.26.0; circuit identity(value: Field): Field { return value; } export circuit entry(value: Field): Field { identity(value); identity(value); return identity(value); }" }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiled.valid, true, compiled.error);
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, 20000, 1, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.completedEntries.length, 1);
      assert.equal(facts.paths.length, 1);
      if (cached) assert.ok(facts.metrics.summaryHits > 0);
      else assert.equal(facts.metrics.summaryHits, 0);
    }
  });
});
