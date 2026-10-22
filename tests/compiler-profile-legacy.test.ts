import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, scanFileIsolated, mergeResults } from "../src/index.js";
import { checkLegacySyntax, selectCompilerVersion, type CompilerVersion } from "../src/semantic/profile.js";
import { AnalysisError, type Expr, type Statement } from "../src/model.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { readConfiguration } from "../src/config.js";
import { JUBJUB_SCALAR_MODULUS } from "../src/semantic/fields.js";
import { withFiles, semanticPaths } from "./helpers.js";

const compilers: Partial<Record<CompilerVersion, string>> = { "0.28.0": process.env.COMPACTC_028_TEST, "0.29.0": process.env.COMPACTC_029_TEST, "0.30.0": process.env.COMPACTC_030_TEST, "0.31.1": process.env.COMPACTC_031_TEST, "0.34.0": process.env.COMPACTC_TEST };
const old: CompilerVersion[] = ["0.30.0", "0.31.1"];
const nativePointOld: readonly [CompilerVersion, string][] = [["0.28.0", "0.20"], ["0.29.0", "0.21"]];
const location = { file: "owned.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
function checked(source: string, version: CompilerVersion, valid: boolean, inspect: (file: string) => void): void {
  checkedFiles({ "main.compact": source }, version, valid, inspect);
}
function checkedFiles(files: Record<string, string>, version: CompilerVersion, valid: boolean, inspect: (file: string) => void): void {
  withFiles(files, directory => {
    const file = resolve(directory, "main.compact"), compiler = compilers[version];
    if (compiler) {
      const result = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(result.valid, valid, `${version}: ${result.error}`);
    }
    inspect(file);
  });
}

const widening = [
  "export circuit entry(x: Uint<64>): Field { return x; }",
  "circuit f(x: Field): Field { return x; } export circuit entry(x: Uint<64>): Field { return f(x); }",
  "export circuit entry(x: Vector<2, Uint<8>>): Vector<2, Field> { return x; }",
  "export circuit entry(x: Uint<8>): [Field, Field] { return [x, x]; }",
  "export ledger value: Field; export circuit entry(x: Uint<64>): [] { value = disclose(x); }",
  "export circuit entry(x: Uint<8>, y: Field, flag: Boolean): Field { return flag ? x : y; }",
];
test("legacy Uint-to-Field subtyping covers values and aggregate/conditional joins without weakening 0.34", () => {
  for (const source of widening) for (const version of [...old, "0.34.0"] as CompilerVersion[]) checked(source, version, version !== "0.34.0", file => {
    const result = scanFile(file, { compilerVersion: version, detectors: [] });
    assert.equal(result.status, version === "0.34.0" ? "incomplete" : "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.semanticProfile, `compact-${version}-zkir2`);
  });
});

test("legacy assignment preserves provenance and both execution/cache modes", () => {
  for (const version of old) checked(`import CompactStandardLibrary;
export ledger total: Field;
circuit widen(x: Uint<8>): Field { return x; }
export circuit entry(x: Uint<8>, flag: Boolean): Field {
  total = disclose(widen(x)); if (disclose(flag)) { total = 3; }
  return total;
}`, version, true, file => {
    const program = new Program(file, [], undefined, undefined, 2, version);
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cache, cache).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths.some(path => path.writes.some(write => write.after.flows.some(flow => flow.source.name === "x"))));
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("0.31.1 qualified profile preserves checked Bytes-to-Uint conversion", () => {
  checked(`pragma language_version 0.23;
export circuit entry(value: Bytes<4>): Uint<32> { return value as Uint<32>; }`, "0.31.1", true, file => {
    const report = scanFile(file, { compilerVersion: "0.31.1", detectors: [] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.semanticProfile, "compact-0.31.1-zkir2");
    assert.equal(report.coverage.baselineStatus, "complete");
  });
});

test("0.31.1 accepts composed roots containing canonical JubjubPoint values", () => {
  checked(`pragma language_version 0.23; import CompactStandardLibrary;
struct Signed { key: JubjubPoint; amount: Uint<64>; }
export circuit root(value: Signed): Bytes<32> { return persistentHash<Signed>(value); }`, "0.31.1", true, file => {
    const report = scanFile(file, { compilerVersion: "0.31.1", detectors: [] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.coverage.completedEntries.length, report.entrypoints.length);
  });
});

test("legacy native signatures retain opaque nominal point identity and group-order semantics", () => {
  for (const version of old) checked(`import CompactStandardLibrary;
export circuit point(x: Field): JubjubPoint { return ecMulGenerator(x); }
export circuit identity(): Boolean { return jubjubPointX(ecMulGenerator(${JUBJUB_SCALAR_MODULUS} as Field)) == 0; }
`, version, true, file => {
    const program = new Program(file, [], undefined, undefined, 2, version);
    assert.equal(program.representationOf("standard-type::JubjubPoint"), 'Opaque<"JubjubPoint">');
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.ok(facts.paths.some(path => path.sinks.some(sink => sink.value.constantKind === "boolean" && sink.value.constant === "true")));
  });
  checked(`import CompactStandardLibrary; export circuit point(x: Field): JubjubPoint { return ecMulGenerator(x); }`, "0.34.0", false,
    file => assert.equal(scanFile(file).status, "incomplete"));
});

test("0.28/0.29 curve natives are compiler-valid but explicitly profile-incomplete", () => {
  const sources = [
    "export circuit point(a: NativePoint, b: NativePoint): NativePoint { return ecAdd(a, b); }",
    "export circuit point(a: NativePoint, b: Field): NativePoint { return ecMul(a, b); }",
    "export circuit point(value: Field): NativePoint { return ecMulGenerator(value); }",
    "export circuit point(value: Field): NativePoint { return hashToCurve<Field>(value); }",
  ];
  for (const [version, language] of nativePointOld) for (const source of sources) checked(`pragma language_version ${language}; import CompactStandardLibrary; ${source}`, version, true, file => {
      const result = scanFile(file, { compilerVersion: version });
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, "unsupported-profile-native");
      assert.match(result.diagnostics[0].message, new RegExp(`NativePoint.*${version}`));
    });
});

test("0.28/0.29 compiler-valid file lookup retains the working-directory bound", () => {
  for (const [version, language] of nativePointOld) {
    checkedFiles({ "main.compact": `pragma language_version ${language}; include "parts/entry";`, "parts/entry.compact": "export circuit entry(value: Field): Field { return value; }" }, version, true, file => {
      const result = scanFile(file, { compilerVersion: version });
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, "unsupported-profile-search-order");
    });
    checkedFiles({ "main.compact": `pragma language_version ${language}; import "Library"; export circuit entry(value: Field): Field { return pass(value); }`, "Library.compact": "module Library { export circuit pass(value: Field): Field { return value; } }" }, version, true, file => {
      const result = scanFile(file, { compilerVersion: version });
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, "unsupported-profile-search-order");
    });
  }
});

test("0.30 point reference equality is explicit incomplete, including aggregate and nominal wrappers", () => {
  for (const [declaration, expression] of [
    ["", "x == y"],
    ["", "[x] != [y]"],
    ["struct Box { point: JubjubPoint; }", "Box { point: x } == Box { point: y }"],
    ["new type Point = JubjubPoint;", "(x as Point) == (y as Point)"],
  ]) for (const version of old) checked(`import CompactStandardLibrary; ${declaration} export circuit entry(x: JubjubPoint, y: JubjubPoint): Boolean { return ${expression}; }`, version, true, file => {
    const result = scanFile(file, { compilerVersion: version });
    assert.equal(result.status, version === "0.30.0" ? "incomplete" : "complete");
    if (version === "0.30.0") assert.equal(result.diagnostics[0].code, "unsupported-profile-point-equality");
  });
});

test("new native exports and zero-width Uint are unavailable in older profiles", () => {
  const sources = [
    'import CompactStandardLibrary; export circuit entry(x: Field): Bytes<32> { return keccak256<Field>(x); }',
    'import CompactStandardLibrary; export circuit entry(x: JubjubPoint): JubjubPoint { return ecNeg(x); }',
    'import CompactStandardLibrary; export circuit entry(x: JubjubScalar): JubjubScalar { return x; }',
    'import CompactStandardLibrary; export circuit entry(x: JubjubSchnorrSignature): [] {}',
    'struct Paused {} export circuit entry(): [] { emit(Paused {}); }',
    'export circuit entry(x: Uint<0>): Uint<0> { return x; }',
  ];
  for (const version of old) for (const source of sources) checked(source, version, false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).status, "incomplete"));
  for (const version of old) checked('export circuit entry(x: Uint<0..1>): Uint<0..1> { return x; }', version, true,
    file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
  for (const version of old) checked('struct Paused {} circuit unused<T>(): [] { emit(Paused {}); } export circuit entry(): [] {}', version, true,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "unsupported-profile-syntax", "Unused generic emit is an explicit analyzer restriction, not compiler rejection"));
});

test("0.30 rejects natural-parameter loop bounds before specialization; 0.31.1 accepts them", () => {
  const source = `circuit loop<#N>(): [] { for (const i of 0..N) { assert(true, "loop"); } }
export circuit entry(): [] { loop<2>(); }`;
  for (const version of old) checked(source, version, version === "0.31.1", file => {
    const result = scanFile(file, { compilerVersion: version });
    assert.equal(result.status, version === "0.30.0" ? "incomplete" : "complete");
  });
  checked("circuit reversed<#N>(): [] { for (const i of 2..1) {} } export circuit entry(): [] {}", "0.30.0", false,
    file => assert.equal(scanFile(file, { compilerVersion: "0.30.0" }).status, "incomplete"));
});

test("export schema validation follows the legacy profile even without concrete generic instances", () => {
  for (const version of old) {
    checked("export type Zero<T> = Uint<0>; export circuit entry(): [] {}", version, false,
      file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "invalid-numeric-type"));
    checked("import CompactStandardLibrary; export { JubjubPoint }; export circuit entry(): Field { return 1; }", version, true,
      file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
    checked('export type Point<T> = Opaque<"JubjubPoint">; export circuit entry(x: Opaque<"JubjubPoint">): Opaque<"JubjubPoint"> { return x; }', version, true,
      file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
  }
  checked("import CompactStandardLibrary; export { JubjubPoint }; export circuit entry(): Field { return 1 as Field; }", "0.34.0", false,
    file => assert.equal(scanFile(file).diagnostics[0].code, "invalid-type-export"));
});

test("legacy syntax checks have no nesting limit but keep their node allowance and rejections", () => {
  // A 210-term conjunction (cf. a pairwise-distinct cell check) nests far beyond the former 128-level guard.
  const pairs = Array.from({ length: 21 }, (_, i) => Array.from({ length: 20 - i }, (_, k) => `v[${i}] != v[${i + k + 1}]`)).flat();
  const chain = `pure circuit distinct(v: Vector<21, Field>): Boolean { return ${pairs.join(" && ")}; }`;
  for (const version of old) checked(`${chain}
export circuit entry(v: Vector<21, Field>): Boolean { return distinct(v); }`, version, true, file => {
    const program = new Program(file, [], undefined, undefined, 2, version);
    assert.ok(program.entries.length === 1);
  });
  // Deep rejections are still found in the same pre-order: emit below 200 nested blocks.
  for (const version of old) checked(`struct Paused {} export circuit entry(): [] { ${"{ ".repeat(200)}emit(Paused {}); ${"} ".repeat(200)}}`, version, false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "unsupported-profile-syntax"));
  checked(`circuit loop<#N>(): [] { ${"{ ".repeat(200)}for (const i of 0..N) { assert(true, "loop"); } ${"} ".repeat(200)}}
export circuit entry(): [] { loop<2>(); }`, "0.30.0", false, file => assert.equal(scanFile(file, { compilerVersion: "0.30.0" }).diagnostics[0].code, "unsupported-profile-syntax"));
  // Owned model trees: an explicit stack handles any depth; the node allowance is unchanged.
  const span = location;
  const leaf = (): Expr => ({ kind: "literal", span, value: "true", args: [] });
  let deep: Expr = leaf();
  for (let index = 0; index < 100000; index++) deep = { kind: "binary", name: "&&", span, args: [deep, leaf()] };
  const rejected = (body: Statement): string | undefined => {
    try { checkLegacySyntax(body, "0.31.1"); return undefined; } catch (error) { if (error instanceof AnalysisError) return error.diagnostic.code; throw error; }
  };
  assert.equal(rejected({ kind: "return", span, expr: { kind: "unary", name: "!", span, args: [{ kind: "literal", span, value: "true", args: [] }] } }), undefined);
  assert.equal(rejected({ kind: "block", span, body: [{ kind: "expr", span, expr: { kind: "assert", span, args: [leaf()] } }, { kind: "return", span, expr: { kind: "binary", name: "&&", span, args: [{ kind: "literal", span, value: "true", args: [] }, leaf()] } }] }), undefined);
  // 100000 binary nodes + 100001 leaves + the statement exceed the 200000-node allowance.
  assert.equal(rejected({ kind: "return", span, expr: deep }), "profile-syntax-budget");
  let shallower: Expr = leaf();
  for (let index = 0; index < 60000; index++) shallower = { kind: "binary", name: "&&", span, args: [shallower, leaf()] };
  assert.equal(rejected({ kind: "return", span, expr: shallower }), undefined);
  assert.equal(rejected({ kind: "return", span, expr: { kind: "binary", name: "&&", span, args: [shallower, { kind: "emit", span, args: [] }] } }), "unsupported-profile-syntax");
  const flat: Statement = { kind: "block", span, body: Array.from({ length: 200001 }, () => ({ kind: "expr" as const, span, expr: leaf() })) };
  assert.equal(rejected(flat), "profile-syntax-budget");
  const wide: Expr = { kind: "tuple", span, args: Array.from({ length: 200001 }, leaf) };
  assert.equal(rejected({ kind: "return", span, expr: wide }), "profile-syntax-budget");
  // The parent and return charge two nodes. Exactly 199998 arguments still fit.
  wide.args.length = 199998;
  assert.equal(rejected({ kind: "return", span, expr: wide }), undefined);
  wide.args.push({ kind: "emit", span, args: [] });
  assert.equal(rejected({ kind: "return", span, expr: wide }), "profile-syntax-budget",
    "The allowance is charged before rejecting the first out-of-budget node");
  wide.args[0] = { kind: "emit", span, args: [] };
  assert.equal(rejected({ kind: "return", span, expr: wide }), "unsupported-profile-syntax",
    "An early syntax rejection still precedes later budget exhaustion");
});
