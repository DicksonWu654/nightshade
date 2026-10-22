import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { Dataflow, Program, Policies, detectors, resolvePolicies, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { FIELD_MODULUS } from "../src/semantic/types.js";
import { castConstant } from "../src/dataflow/constants.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void = () => {}, policies: Policies = {}, files: Record<string, string> = {}): void {
  withFiles({ ...files, "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const facts = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const result of [facts, expanded, reference]) {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
    }
    assert.deepEqual(facts.paths, expanded.paths);
    assert.deepEqual(facts.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(facts.failedAssertions, reference.failedAssertions);
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const configured = resolvePolicies(program, policies);
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(expanded));
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

const returned = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const byteSource = (value: bigint, length: number): string => `Bytes[${Array.from({ length }, (_, index) => Number(value >> BigInt(8 * index) & 255n)).join(",")}]`;

for (const [name, source, expected] of [
  ["unsigned widening", "export circuit entry(): Uint<16> { return (1 as Uint<8>) as Uint<16>; }", "1"],
  ["unsigned narrowing", "export circuit entry(): Uint<8> { return (255 as Uint<16>) as Uint<8>; }", "255"],
  ["Field conversion", "export circuit entry(): Field { return (1 as Uint<8>) as Field; }", "1"],
  ["Field narrowing", "export circuit entry(): Uint<8> { return (255 as Field) as Uint<8>; }", "255"],
  ["Boolean nonzero", "export circuit entry(): Boolean { return 2 as Boolean; }", "true"],
  ["Boolean zero", "export circuit entry(): Boolean { return default<Field> as Boolean; }", "false"],
  ["Boolean to Uint", "export circuit entry(): Uint<8> { return true as Uint<8>; }", "1"],
  ["Boolean to Field", "export circuit entry(): Field { return false as Field; }", "0"],
  ["nominal unsigned widening", "new type Byte = Uint<8>; new type Word = Uint<16>; export circuit entry(): Word { return (255 as Byte) as Word; }", "255"],
  ["enum ordinal", "enum Phase { FIRST,SECOND } export circuit entry(): Uint<8> { return Phase.SECOND as Uint<8>; }", "1"],
  ["enum through Field", "enum Phase { FIRST,SECOND } export circuit entry(): Uint<8> { return ((1 as Field) as Phase) as Uint<8>; }", "1"],
  ["numeric bytes little endian", "export circuit entry(): Bytes<2> { return 513 as Bytes<2>; }", "0102"],
  ["bytes to unsigned", "export circuit entry(): Uint<16> { return Bytes[1,2] as Uint<16>; }", "513"],
  ["bytes to native Field", "export circuit entry(): Field { return Bytes[1,2] as Field; }", "513"],
  ["maximum native Field from bytes", `export circuit entry(): Field { return ${byteSource(FIELD_MODULUS - 1n, 32)} as Field; }`, String(FIELD_MODULUS - 1n)],
  ["same-size Bytes identity", "export circuit entry(): Bytes<2> { return Bytes[1,2] as Bytes<2>; }", "0102"],
  ["nominal Bytes identity", "new type Encoded = Bytes<2>; export circuit entry(): Encoded { return Bytes[1,2] as Encoded; }", "0102"],
  ["tuple to Bytes", "export circuit entry(): Bytes<2> { return [1,2] as Bytes<2>; }", "0102"],
  ["vector to Bytes", "export circuit entry(): Bytes<2> { const values: Vector<2,Uint<8>> = [1,2]; return values as Bytes<2>; }", "0102"],
  ["zero-length tuple to Bytes", "export circuit entry(): Bytes<0> { return [] as Bytes<0>; }", ""],
  ["nominal byte construction", "new type Byte = Uint<8>; export circuit entry(): Bytes<2> { return Bytes[1 as Byte,2 as Byte]; }", "0102"],
  ["byte construction with mixed spreads", "export circuit entry(): Bytes<4> { const middle: Vector<2,Uint<8>> = [2,3]; return Bytes[1,...middle,...[4]]; }", "01020304"],
  ["byte construction with Bytes spread", "export circuit entry(): Bytes<3> { return Bytes[...pad(2,\"a\"),3]; }", "610003"],
  ["byte construction with empty tuple spread", "export circuit entry(): Bytes<0> { return Bytes[...[]]; }", ""],
  ["Jubjub default in qualified ZKIR2 profile", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Field { return default<JubjubScalar> as Field; }", "0"],
  ["Jubjub Field conversion in qualified ZKIR2 profile", `import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Field { return ((${FIELD_MODULUS - 1n} as Field) as JubjubScalar) as Field; }`, String(FIELD_MODULUS - 1n)],
  ["Jubjub from unsigned", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Uint<8> { return (255 as JubjubScalar) as Uint<8>; }", "255"],
  ["Jubjub from Boolean", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Field { return (true as JubjubScalar) as Field; }", "1"],
  ["Jubjub from enum", "import { JubjubScalar } from CompactStandardLibrary; enum Phase { FIRST,SECOND } export circuit entry(): Field { return (Phase.SECOND as JubjubScalar) as Field; }", "1"],
  ["Jubjub to Boolean", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Boolean { return (2 as JubjubScalar) as Boolean; }", "true"],
] as const) test(`compiler-valid cast constants: ${name}`, () => compare(source, facts => assert.equal(returned(facts)[0].constant, expected)));

for (const [name, source] of [
  ["unsigned narrowing", "export circuit entry(): Uint<8> { return (256 as Uint<16>) as Uint<8>; }"],
  ["Field narrowing", "export circuit entry(): Uint<8> { return (256 as Field) as Uint<8>; }"],
  ["Boolean narrowing", "export circuit entry(): Uint<0> { return true as Uint<0>; }"],
  ["numeric byte capacity", "export circuit entry(): Bytes<1> { return 256 as Bytes<1>; }"],
  ["byte unsigned capacity", "export circuit entry(): Uint<8> { return Bytes[0,1] as Uint<8>; }"],
  ["native Field byte capacity", `export circuit entry(): Field { return ${byteSource(FIELD_MODULUS, 32)} as Field; }`],
  ["enum range", "enum Phase { FIRST,SECOND } export circuit entry(): Phase { return 2 as Phase; }"],
  ["Jubjub unsigned narrowing", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(): Uint<8> { return (256 as JubjubScalar) as Uint<8>; }"],
] as const) test(`compiler-valid casts with checked runtime rejection: ${name}`, () => compare(source, facts => assert.deepEqual(facts.paths, [])));

for (const [name, source] of [
  ["tuple-to-vector widening", "export circuit entry(secret: Uint<8>): Vector<2,Uint<16>> { return [secret,1] as Vector<2,Uint<16>>; }"],
  ["vector-to-vector widening", "export circuit entry(secret: Uint<8>): Vector<2,Uint<16>> { const values: Vector<2,Uint<8>> = [secret,1]; return values as Vector<2,Uint<16>>; }"],
  ["vector-to-tuple widening", "export circuit entry(secret: Uint<8>): [Uint<16>,Uint<16>] { const values: Vector<2,Uint<8>> = [secret,1]; return values as [Uint<16>,Uint<16>]; }"],
  ["tuple-to-tuple widening", "export circuit entry(secret: Uint<8>): [Uint<16>,Uint<16>] { return [secret,1] as [Uint<16>,Uint<16>]; }"],
  ["nominal wrapper widening", "new type Pair = [Uint<8>,Uint<8>]; new type Wide = Vector<2,Uint<16>>; export circuit entry(secret: Uint<8>): Wide { return ([secret,1] as Pair) as Wide; }"],
] as const) test(`aggregate casts preserve field-sensitive private values: ${name}`, () => compare(source, facts => {
  const result = returned(facts)[0];
  assert.ok(result.items![0].flows.some(flow => flow.source.name === "secret" && flow.form === "raw"));
  assert.equal(result.items![1].flows.length, 0);
  assert.equal(result.items![1].constant, "1");
}));

for (const target of ["Vector<2,Uint<8>>", "[Uint<16>,Field]", "Vector<2,Byte>", "[Byte,Byte]", "Vector<2,JubjubScalar>"]) test(`Bytes conversion checks element representation: ${target}`, () => {
  compare(`import { JubjubScalar } from CompactStandardLibrary; new type Byte = Uint<8>; export circuit entry(): ${target} { return Bytes[1,2] as ${target}; }`, facts => assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "2"]));
});

test("aggregate identity cast preserves fields and nominal source dependencies", () => {
  compare("struct Box { secret: Field; visible: Field; } new type Wrapped = Box; export circuit entry(secret: Field): Field { const box = Box { secret, visible: 0 as Field } as Wrapped; return (box as Box).secret; }", facts => assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "secret" && flow.form === "raw")));
});

test("ADT identity casts remain legal for local default values", () => {
  compare("import { Map } from CompactStandardLibrary; export circuit entry(): [] { const empty = default<Map<Field,Field>> as Map<Field,Field>; }");
});

for (const conversion of ["value as Uint<16>", "value as Field", "(value as Uint<16>) as Uint<8>"]) test(`value-preserving numeric casts cannot hide full raw disclosure: ${conversion}`, () => {
  const resultType = conversion === "value as Field" ? "Field" : conversion === "value as Uint<16>" ? "Uint<16>" : "Uint<8>";
  compare(`import { persistentHash } from CompactStandardLibrary; export ledger digest: Bytes<32>; witness secret(): Uint<8>; circuit convert(value: Uint<8>): ${resultType} { return ${conversion}; } export circuit entry(): ${resultType} { const value = secret(); assert(persistentHash<Uint<8>>(value) == digest,"bound"); return disclose(convert(value)); }`, facts => {
    assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 1);
  });
});

test("a representation-only cast of a digest is not a raw-preimage publication", () => {
  compare('import { persistentHash } from CompactStandardLibrary; new type Digest = Bytes<32>; export ledger digest: Bytes<32>; witness secret(): Uint<8>; export circuit entry(): Digest { const value = secret(); const hashed = persistentHash<Uint<8>>(value); assert(hashed == digest,"bound"); return disclose(hashed as Digest); }', facts => {
    assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 0);
    assert.ok(returned(facts)[0].flows.every(flow => flow.form === "hash"));
  });
});

test("checked casts compose with guarded state writes and declared secrecy", () => {
  const policies: Policies = { authorization: [{ state: "stored", guard: "guard" }], secrets: [{ circuit: "entry", parameter: "secret" }] };
  compare('export ledger allowed: Boolean; export ledger stored: Uint<8>; circuit guard(): [] { assert(allowed,"allowed"); } export circuit entry(secret: Uint<16>, flag: Boolean): [] { if (disclose(flag)) guard(); stored = disclose(secret as Uint<8>); }', facts => {
    const observations = detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies)));
    assert.equal(observations.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 1);
    assert.ok(observations.some(finding => finding.detectorId === "declared-secret-publication"));
  }, policies);
});

const rejected: [string, string, string][] = [
  ["Boolean to Bytes", "export circuit entry(): Bytes<1> { return true as Bytes<1>; }", "cast-type-mismatch"],
  ["Bytes to Boolean", 'export circuit entry(): Boolean { return "a" as Boolean; }', "cast-type-mismatch"],
  ["enum to Boolean", "enum Phase { FIRST,SECOND } export circuit entry(): Boolean { return Phase.SECOND as Boolean; }", "cast-type-mismatch"],
  ["Boolean to enum", "enum Phase { FIRST,SECOND } export circuit entry(): Phase { return true as Phase; }", "cast-type-mismatch"],
  ["distinct enums", "enum First { YES,NO } enum Second { YES,NO } export circuit entry(value: First): Second { return value as Second; }", "cast-type-mismatch"],
  ["different struct identities", "struct First { value: Field; } struct Second { value: Field; } export circuit entry(value: First): Second { return value as Second; }", "cast-type-mismatch"],
  ["struct to scalar", "struct Box { value: Field; } export circuit entry(value: Box): Field { return value as Field; }", "cast-type-mismatch"],
  ["scalar to tuple", "export circuit entry(value: Field): [Field] { return value as [Field]; }", "cast-type-mismatch"],
  ["tuple-to-vector narrowing", "export circuit entry(value: Uint<16>): Vector<1,Uint<8>> { return [value] as Vector<1,Uint<8>>; }", "cast-type-mismatch"],
  ["vector narrowing", "export circuit entry(value: Vector<2,Uint<16>>): Vector<2,Uint<8>> { return value as Vector<2,Uint<8>>; }", "cast-type-mismatch"],
  ["Bytes resize", "export circuit entry(value: Bytes<2>): Bytes<1> { return value as Bytes<1>; }", "cast-type-mismatch"],
  ["Bytes into narrow elements", "export circuit entry(value: Bytes<2>): Vector<2,Uint<7>> { return value as Vector<2,Uint<7>>; }", "cast-type-mismatch"],
  ["Bytes into wrong length", "export circuit entry(value: Bytes<2>): Vector<3,Uint<8>> { return value as Vector<3,Uint<8>>; }", "cast-type-mismatch"],
  ["large elements to Bytes", "export circuit entry(value: Vector<2,Uint<16>>): Bytes<2> { return value as Bytes<2>; }", "cast-type-mismatch"],
  ["Field elements to Bytes", "export circuit entry(value: Vector<2,Field>): Bytes<2> { return value as Bytes<2>; }", "cast-type-mismatch"],
  ["zero-length Bytes into scalar", "export circuit entry(): Field { return default<Bytes<0>> as Field; }", "cast-type-mismatch"],
  ["scalar into zero-length Bytes", "export circuit entry(): Bytes<0> { return 0 as Bytes<0>; }", "cast-type-mismatch"],
  ["empty vector retains element type", "export circuit entry(): Vector<0,Boolean> { return default<Vector<0,Field>> as Vector<0,Boolean>; }", "cast-type-mismatch"],
  ["zero Bytes vector element check", "export circuit entry(): Vector<0,Boolean> { return default<Bytes<0>> as Vector<0,Boolean>; }", "cast-type-mismatch"],
  ["zero vector Bytes element check", "export circuit entry(): Bytes<0> { return default<Vector<0,Field>> as Bytes<0>; }", "cast-type-mismatch"],
  ["nested nominal types are not erased", "new type Byte = Uint<8>; export circuit entry(value: Vector<2,Byte>): Vector<2,Uint<8>> { return value as Vector<2,Uint<8>>; }", "nominal-type-mismatch"],
  ["nominal invalid byte cast", "new type Flag = Boolean; export circuit entry(value: Flag): Bytes<1> { return value as Bytes<1>; }", "nominal-type-mismatch"],
  ["Bytes Jubjub cast", "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(value: Bytes<32>): JubjubScalar { return value as JubjubScalar; }", "cast-type-mismatch"],
  ["byte constructor Boolean", "export circuit entry(): Bytes<1> { return Bytes[true]; }", "bytes-argument-type"],
  ["byte constructor Field", "export circuit entry(): Bytes<1> { return Bytes[1 as Field]; }", "bytes-argument-type"],
  ["byte constructor wide value", "export circuit entry(): Bytes<1> { return Bytes[256]; }", "bytes-argument-type"],
  ["byte constructor non-sequence spread", "export circuit entry(): Bytes<0> { return Bytes[...true]; }", "bytes-argument-type"],
  ["byte constructor mixed tuple spread", "export circuit entry(): Bytes<2> { return Bytes[...[1,true]]; }", "bytes-argument-type"],
  ["byte constructor zero-vector element", "export circuit entry(): Bytes<0> { return Bytes[...default<Vector<0,Boolean>>]; }", "bytes-argument-type"],
];

for (const [name, source, code] of rejected) test(`compiler-rejected casts and byte construction: ${name}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, false, source);
      assert.ok(!compiled.error?.includes("Internal error"), compiled.error);
    }
    const report = scanFile(path);
    assert.equal(report.status, "incomplete");
    assert.equal(report.diagnostics[0]?.code, code, JSON.stringify(report.diagnostics));
    assert.deepEqual(report.coverage.completedEntries, []);
  });
});

test("unmodeled scalar-to-bytes conversion is diagnosed without relying on compiler internal errors", () => {
  withFiles({ "main.compact": "import { JubjubScalar } from CompactStandardLibrary; export circuit entry(value: JubjubScalar): Bytes<32> { return value as Bytes<32>; }" }, directory => {
    const report = scanFile(resolve(directory, "main.compact"));
    assert.equal(report.status, "incomplete");
    assert.equal(report.diagnostics[0]?.code, "cast-type-mismatch");
    assert.deepEqual(report.coverage.completedEntries, []);
  });
});

test("valid sequence conversion beyond the analysis layout budget fails explicitly", () => {
  withFiles({ "main.compact": "export circuit entry(value: Bytes<257>): Vector<257,Uint<8>> { return value as Vector<257,Uint<8>>; }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, true);
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.equal(facts.diagnostics[0]?.code, "unsupported-sequence-cast");
      assert.deepEqual(facts.completedEntries, []);
    }
  });
});

test("invalid imported cast preserves the defining Unicode source span", () => {
  withFiles({ "main.compact": 'import "Helper"; export circuit entry(): Bytes<1> { return bad(); }', "Helper.compact": "module Helper { /* Ω🚀 */ export circuit bad(): Bytes<1> { return true as Bytes<1>; } }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const diagnostic = scanFile(path).diagnostics[0];
    assert.equal(diagnostic.code, "cast-type-mismatch");
    assert.equal(diagnostic.location.file, resolve(directory, "Helper.compact"));
    const source = readFileSync(diagnostic.location.file);
    assert.equal(source.subarray(diagnostic.location.start, diagnostic.location.end).toString(), "true as Bytes<1>");
    assert.equal(diagnostic.location.column, source.subarray(0, diagnostic.location.start).toString().length + 1);
  });
});

test("native byte-to-Field constants reject overflow rather than using a foreign-field modulus", () => {
  const bytes = (value: bigint): string => value.toString(16).padStart(64,"0").match(/../g)!.reverse().join("");
  assert.equal(castConstant({ kind: "bytes", value: bytes(FIELD_MODULUS) }, "Field"), null);
  assert.deepEqual(castConstant({ kind: "bytes", value: bytes(FIELD_MODULUS - 1n) }, "Field"), { kind: "integer", value: String(FIELD_MODULUS - 1n) });
});

test("compiler emission distinguishes checked native casts and ZKIR-specific Jubjub conversion", { skip: !process.env.COMPACTC_TEST ? "Requires COMPACTC_TEST" : false }, () => {
  withFiles({ "main.compact": "import { JubjubScalar } from CompactStandardLibrary; export circuit checked(value: Bytes<32>): Field { return value as Field; } export circuit convert(value: Field): JubjubScalar { return value as JubjubScalar; }" }, directory => {
    for (const version3 of [false, true]) {
      const target = resolve(directory, version3 ? "v3" : "v2");
      const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", ...(version3 ? ["--feature-zkir-v3"] : []), resolve(directory,"main.compact"), target], { encoding: "utf8", timeout: 30000 });
      assert.equal(compiled.status, 0, compiled.stderr);
      const output = readFileSync(resolve(target,"contract/index.js"),"utf8");
      assert.match(output, new RegExp(`convertBytesToUint\\(${FIELD_MODULUS - 1n}n`));
      assert.equal(output.includes("convertNumericToJubjubScalar("), version3);
      if (!version3) assert.match(output, /_convert_\d+\(value_\d+\) \{ return value_\d+; \}/);
    }
  });
});
