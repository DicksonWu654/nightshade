import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const helpers = `import CompactStandardLibrary;
circuit take(value: Either<Field,Field>, add: Field): Field { return value.left + add; }`;

for (const [name, body] of [
  ["nested call", "return take(left<Field,Field>(value),1 as Field);"],
  ["tuple element", "return [left<Field,Field>(value),1 as Field][0].left;"],
  ["generic call with trivia", "return take(left</* type */ Field, /* second */ Field>(value),1 as Field);"],
]) test(`compiler-valid ${name} retains its generic arguments and provenance`, () => {
  withFiles({ "main.compact": `${helpers} export circuit entry(value: Field): Field { ${body} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.flows.some(flow => flow.source.name === "value"));
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
});

for (const [name, args, valid] of [
  ["parenthesized comparisons", "(a < b), (c > d)", true],
  ["comparisons without a call-shaped right operand", "a < b, c > d", true],
  ["call-shaped syntax is a generic invocation", "a < b, c > (d)", false],
] as const) test(`generic-call precedence preserves compiler treatment of ${name}`, () => {
  withFiles({ "main.compact": `circuit take(x: Boolean,y: Boolean): Boolean { return x && y; }
export circuit entry(a: Uint<8>,b: Uint<8>,c: Uint<8>,d: Uint<8>): Boolean { return take(${args}); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, valid);
    const result = scanFile(file);
    assert.equal(result.status, valid ? "complete" : "incomplete");
    if (!valid) assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "invalid-type-context"));
  });
});
