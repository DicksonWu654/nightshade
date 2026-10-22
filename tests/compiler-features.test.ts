import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { semanticPaths, withFiles } from "./helpers.js";

for (const fixture of ["aggregates", "generics", "generic-specializations", "numeric-types", "type-resolution", "type-exports", "type-compatibility", "casts", "sequences", "intrinsic-legality", "collections", "strings", "overloads", "lexical-overloads", "higher-order", "higher-order-library", "sequence-loop", "nested-map", "adt-aliases", "expression-effects", "expression-pair", "ledger-snapshot", "argument-effects", "stateful-summaries", "nominal-types", "nominal-ledger", "list", "repeated-module", "distinct-specializations", "module-composition", "includes/main"]) {
  test(`language feature ${fixture}`, () => {
    const result = scanFile(resolve("tests/fixtures/features", `${fixture}.compact`), { compiler: process.env.COMPACTC_TEST });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.entrypoints.length, 1);
    assert.equal(result.coverage.completedEntries.length, 1);
    const program = new Program(resolve("tests/fixtures/features", `${fixture}.compact`));
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    const instructions = new Dataflow(program).analyze();
    assert.deepEqual(instructions.diagnostics, reference.diagnostics);
    assert.deepEqual(semanticPaths(instructions), semanticPaths(reference));
    assert.deepEqual(instructions.failedAssertions, reference.failedAssertions);
    if (fixture === "stateful-summaries") assert.ok(instructions.metrics.statefulSummaryHits > 0);
    if (process.env.COMPACTC_TEST) assert.equal(result.compilerValidated, true);
    if (process.env.COMPACTC_TEST && ["repeated-module", "distinct-specializations", "module-composition"].includes(fixture)) {
      const source = readFileSync(resolve("tests/fixtures/features", `${fixture}.compact`), "utf8") + "\nexport { First_value, Second_value };\n";
      withFiles({ "main.compact": source }, directory => {
        const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", resolve(directory, "main.compact"), resolve(directory, "output")], { encoding: "utf8", timeout: 30000 });
        assert.equal(compiled.status, 0, compiled.stderr);
        const generated = readFileSync(resolve(directory, "output/contract/index.js"), "utf8");
        const first = /get First_value\(\)[\s\S]*?\.toValue\((\d+)n\)/.exec(generated)?.[1];
        const second = /get Second_value\(\)[\s\S]*?\.toValue\((\d+)n\)/.exec(generated)?.[1];
        assert.notEqual(first, undefined);
        assert.notEqual(second, undefined);
        assert.equal(first === second, fixture !== "distinct-specializations", "Compiler ledger indices must agree with module alias semantics");
      });
    }
  });
}
