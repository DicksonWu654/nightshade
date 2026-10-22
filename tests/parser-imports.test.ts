import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { parseSource, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

test("empty import selections remain distinct from importing every export", () => {
  const parsed = parseSource("main.compact", "import Library; import {} from Library;");
  assert.equal(parsed.ast.imports[0].selections, undefined);
  assert.deepEqual(parsed.ast.imports[1].selections, []);
});

test("empty import selections preserve comments, source spans and generic instantiation", () => {
  const source = "pragma language_version >= 0.26.0;\r\nmodule Library<T> { export ledger value: T; }\r\n/* Ω🚀 */ import { /* empty */ } from Library<Field> prefix L_;\r\nexport circuit entry(): [] {}";
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    assert.deepEqual(scanFile(path, { compiler: process.env.COMPACTC_TEST }).diagnostics, []);
    const program = new Program(path);
    assert.equal(program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    const imported = program.files.get(path)!.ast.imports[0];
    assert.deepEqual(imported.selections, []);
    assert.equal(imported.span.line, 3);
    assert.equal(imported.span.column, source.split("\r\n")[2].indexOf("import") + 1);
    assert.equal(Buffer.from(source).subarray(imported.span.start, imported.span.end).toString(), "import { /* empty */ } from Library<Field> prefix L_;");
  });
});

test("empty standard-library selection does not inject native bindings", () => {
  withFiles({ "main.compact": "pragma language_version >= 0.26.0; import {} from CompactStandardLibrary; export circuit entry(): [] {}" }, directory => {
    const path = resolve(directory, "main.compact");
    assert.deepEqual(scanFile(path, { compiler: process.env.COMPACTC_TEST }).diagnostics, []);
    assert.equal([...new Program(path).symbols.values()].some(symbol => symbol.kind === "intrinsic"), false);
  });
});

for (const [name, source, code] of [
  ["empty selections do not bind omitted exports", "module Library { export circuit run(): [] {} } import {} from Library; export circuit entry(): [] { run(); }", "unresolved-symbol"],
  ["empty selections still require generic arguments", "module Library<T> {} import {} from Library; export circuit entry(): [] {}", "generic-arity"],
  ["a leading import comma is invalid", "import {,} from CompactStandardLibrary; export circuit entry(): [] {}", "parse-error"],
  ["repeated import separators are invalid", "import { some,, } from CompactStandardLibrary; export circuit entry(): [] {}", "parse-error"],
] as const) test(name, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const rejected = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(rejected.valid, false);
      assert.match(rejected.error!, /Exception:/);
    }
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code);
  });
});
