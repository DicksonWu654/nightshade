import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Dataflow, Program, parseSource, scanFile } from "../src/index.js";
import { withFiles } from "./helpers.js";

test("grammar artifacts and native binding have the same verified build identity", () => {
  const check = spawnSync(process.execPath, ["scripts/build-parser.mjs", "--verify"], { encoding: "utf8", timeout: 30000 });
  assert.equal(check.status, 0, check.stderr);
  const manifest = JSON.parse(readFileSync("dist/parser/manifest.json", "utf8"));
  const result = scanFile(resolve("tests/fixtures/features/expression-pair.compact"));
  assert.equal(result.grammarRevision, manifest.upstreamRevision);
  assert.equal(result.grammarBuild, manifest.identity);
  assert.equal(manifest.abi, 15);
});

test("verification rejects stale parser artifacts without regeneration or native compilation", () => {
  const inputs = ["src/parser/native/config.json", "src/parser/native/grammar.cjs", "src/parser/native/binding.c", "binding.gyp", "scripts/build-parser.mjs"];
  withFiles(Object.fromEntries(inputs.map(path => [path, readFileSync(path, "utf8")])), directory => {
    cpSync("dist/parser", resolve(directory, "dist/parser"), { recursive: true });
    writeFileSync(resolve(directory, "dist/parser/src/parser.c"), "stale generated parser\n");
    const check = spawnSync(process.execPath, [resolve(directory, "scripts/build-parser.mjs"), "--verify"], { encoding: "utf8", timeout: 10000 });
    assert.equal(check.status, 1);
    assert.match(check.stderr, /Parser artifacts are absent or stale/);
    assert.equal(existsSync(resolve(directory, "build")), false);
    assert.equal(readFileSync(resolve(directory, "dist/parser/src/parser.c"), "utf8"), "stale generated parser\n");
  });
});

for (const size of [1, 2, 3, 4, 6]) test(`expression sequences preserve all ${size} operands`, () => {
  const values = Array.from({ length: size }, (_, index) => `${index} as Field`).join(", ");
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export circuit entry(): Field { return (${values}); }` }, directory => {
    const path = resolve(directory, "main.compact");
    const result = scanFile(path, { compiler: process.env.COMPACTC_TEST });
    assert.deepEqual(result.diagnostics, []);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.paths.map(item => item.sinks[0].value.constant), [String(size - 1)]);
    }
  });
});

test("paired sequences preserve left-to-right state effects and return only the last operand", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0;
export ledger value: Field;
circuit set(next: Field): Field { value = disclose(next); return next; }
export circuit entry(): Field { return set(1 as Field), set(2 as Field); }` }, directory => {
    const path = resolve(directory, "main.compact");
    assert.deepEqual(scanFile(path, { compiler: process.env.COMPACTC_TEST }).diagnostics, []);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 1);
      assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["1", "2"]);
      assert.equal(facts.paths[0].sinks.at(-1)!.value.constant, "2");
    }
  });
});

test("aborting first operands prevent evaluation of second operands", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0;
export ledger value: Field;
export circuit entry(): [] { (assert(false, "abort"), value = 1 as Field); }` }, directory => {
    const path = resolve(directory, "main.compact");
    assert.deepEqual(scanFile(path, { compiler: process.env.COMPACTC_TEST }).diagnostics, []);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.paths, []);
    }
  });
});

test("paired condition, statement and loop sequences preserve effect order", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger ticks: Counter;
circuit mark(): [] { ticks.increment(1); }
export circuit entry(): [] {
  if (mark(), true) { mark(), mark(); }
  for (const value of (mark(), [1 as Field, 2 as Field])) { ticks.increment(1); }
}` }, directory => {
    const path = resolve(directory, "main.compact");
    assert.deepEqual(scanFile(path, { compiler: process.env.COMPACTC_TEST }).diagnostics, []);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 1);
      assert.equal(facts.paths[0].writes.length, 6);
      assert.deepEqual(facts.paths[0].writes.map(write => write.location.line), [4, 4, 4, 4, 7, 7]);
    }
  });
});

test("paired sequences keep UTF-8 offsets and UTF-16 columns without rewriting source", () => {
  const source = "export circuit entry(secret: Field): Field {\r\n  return (0 as Field, /* Ω🚀 */ secret);\r\n}";
  const parsed = parseSource("unicode.compact", source);
  const body = parsed.ast.declarations[0].body!;
  assert.equal(body.kind, "block");
  if (body.kind !== "block" || body.body[0].kind !== "return") return assert.fail("Missing return");
  const expression = body.body[0].expr;
  assert.equal(expression.kind, "sequence");
  assert.equal(expression.args.length, 2);
  const location = expression.args[1].span;
  assert.equal(Buffer.from(source).subarray(location.start, location.end).toString(), "secret");
  assert.equal(location.line, 2);
  assert.equal(location.column, source.split("\r\n")[1].indexOf("secret") + 1);
  assert.equal(parsed.text, source);
});

for (const expression of ["(, 1)", "(1,)", "(1,,2)", "(1,2,)", "()"])
  test(`malformed sequence ${expression} remains a parse error`, () => {
    withFiles({ "main.compact": `export circuit entry(): Field { return ${expression}; }` }, directory => {
      const result = scanFile(resolve(directory, "main.compact"));
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, "parse-error");
    });
  });
