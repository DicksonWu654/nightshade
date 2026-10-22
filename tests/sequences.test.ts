import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, Policies, detectors, resolvePolicies, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void = () => {}, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
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

for (const [name, source, expected] of [
  ["heterogeneous tuple literal index", "export circuit entry(): Field { return [true,17 as Field][1]; }", "17"],
  ["safe-cast literal index", "export circuit entry(): Field { return [true,17 as Field][1 as Uint<8>]; }", "17"],
  ["nominal literal index", "new type Offset = Uint<8>; export circuit entry(): Field { return [true,17 as Field][1 as Offset]; }", "17"],
  ["radix literal index", "export circuit entry(): Uint<8> { return Bytes[1,2,3][0b10]; }", "3"],
  ["computed homogeneous tuple index", "export circuit entry(): Uint<16> { const index = 0; return [1,256][index]; }", "1"],
  ["arithmetic index", "export circuit entry(): Uint<16> { return [1,256][0 + 1]; }", "256"],
  ["checked-cast index", "export circuit entry(): Uint<8> { return Bytes[1,2][(1 as Uint<16>) as Uint<8>]; }", "2"],
  ["index in an inlined helper", "circuit select(values: Vector<2,Uint<16>>, index: Uint<8>): Uint<16> { return values[index]; } export circuit entry(): Uint<16> { return select([1,256],1); }", "256"],
  ["Bytes partial constant slice", 'export circuit entry(): Bytes<2> { return slice<2>("abcd",1); }', "6263"],
  ["Bytes full constant slice", 'export circuit entry(): Bytes<2> { return slice<2>("ab",0); }', "6162"],
  ["empty Bytes slice at end", 'export circuit entry(): Bytes<0> { return slice<0>("ab",2); }', ""],
  ["nominal Bytes slice", 'new type Encoded = Bytes<3>; export circuit entry(): Bytes<1> { return slice<1>("abc" as Encoded,1); }', "62"],
  ["Bytes slice computed index", 'export circuit entry(): Bytes<1> { const offset = 1; return slice<1>("abc",offset); }', "62"],
  ["Bytes destructuring", 'export circuit entry(): Uint<8> { const [,byte] = "abc"; return byte; }', "98"],
  ["nominal Bytes destructuring", 'new type Encoded = Bytes<3>; export circuit entry(): Uint<8> { const [,byte] = "abc" as Encoded; return byte; }', "98"],
  ["partial destructuring", "export circuit entry(): Uint<8> { const [value] = [7,true]; return value; }", "7"],
  ["omitted entries beyond length", "export circuit entry(): Uint<8> { const [value,,,] = [7]; return value; }", "7"],
  ["repeated struct projection with distinct names", "struct Box { value: Uint<8>; } export circuit entry(): Uint<8> { const { value: first, value: second } = Box { value: 7 }; return second; }", "7"],
  ["nested partial patterns", "struct Box { values: [Boolean,Uint<8>]; } export circuit entry(): Uint<8> { const { values: [,selected] } = Box { values: [true,7] }; return selected; }", "7"],
  ["tuple-only heterogeneous spreads", "export circuit entry(): Field { const values = [true,...[9 as Field],...[]]; return values[1]; }", "9"],
  ["mixed numeric vector spreads", "export circuit entry(): Uint<16> { const middle: Vector<2,Uint<8>> = [1,2]; const values = [256,...middle,3]; return values[1]; }", "1"],
  ["Bytes spread implies byte vector", 'export circuit entry(): Uint<8> { const values = [..."ab",1]; return values[1]; }', "98"],
] as const) test(`compiler-valid sequence constants: ${name}`, () => compare(source, facts => assert.equal(returned(facts)[0].constant, expected)));

for (const [name, source, expectedType, constants] of [
  ["static heterogeneous tuple slice", "export circuit entry(): [Boolean,Field] { const result = slice<2>([1,true,9 as Field],1); return result; }", "[Boolean,Field]", ["true","9"]],
  ["safe-cast literal slice", "export circuit entry(): [Boolean,Field] { const result = slice<2>([1,true,9 as Field],1 as Uint<8>); return result; }", "[Boolean,Field]", ["true","9"]],
  ["vector slice retains vector shape", "export circuit entry(): Vector<1,Uint<16>> { const input: Vector<2,Uint<16>> = [1,2]; const result = slice<1>(input,1); return result; }", "Vector<1,Uint<16>>", ["2"]],
  ["non-literal tuple slice joins all elements", "export circuit entry(): Vector<1,Uint<16>> { const index = 0; const result = slice<1>([1,256],index); return result; }", "Vector<1,Uint<0..257>>", ["1"]],
  ["empty tuple slice at end", "export circuit entry(): [] { const result = slice<0>([true,7],2); return result; }", "[]", []],
  ["empty vector slice retains element type", "export circuit entry(): Vector<0,Boolean> { const result = slice<0>(default<Vector<0,Boolean>>,0); return result; }", "Vector<0,Boolean>", []],
  ["zero vector spread retains element type", "export circuit entry(): Vector<0,Boolean> { const result = [...default<Vector<0,Boolean>>]; return result; }", "Vector<0,Boolean>", []],
  ["zero Bytes spread retains byte type", "export circuit entry(): Vector<0,Uint<8>> { const result = [...default<Bytes<0>>]; return result; }", "Vector<0,Uint<8>>", []],
] as const) test(`compiler-valid sequence shape: ${name}`, () => compare(source, facts => {
  assert.equal([...facts.program.symbols.values()].find(symbol => symbol.name === "result")!.type, expectedType);
  assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), constants);
}));

test("non-literal index infers the common element type instead of element zero", () => {
  compare("export circuit entry(secret: Uint<16>): Uint<16> { const index = 0; const result = [1,secret][index]; return result; }", facts => {
    assert.equal([...facts.program.symbols.values()].find(symbol => symbol.name === "result")!.type, "Uint<16>");
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(returned(facts)[0].flows.length, 0);
  });
});

for (const parameters of ["[value]: [Field], value: Field", "value: Field, [value]: [Field]"]) test(`parameter projections shadow ordinary parameters independent of order: ${parameters}`, () => {
  compare(`circuit select(${parameters}): Field { return value; } export circuit entry(secret: Field): Field { return select(${parameters.startsWith("[") ? "[secret],0 as Field" : "0 as Field,[secret]"}); }`, facts => assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "secret" && flow.form === "raw")));
});

test("empty and all-omitted patterns do not impose a container requirement", () => {
  compare("export circuit entry(): [] { const [] = true; const {} = false; const [,,] = 1; }");
});

test("commented omitted slots retain their projection position", () => {
  compare('export circuit entry(): Uint<8> { const [ /* Ω🚀 */ , selected, , ] = Bytes[1,2]; return selected; }', facts => assert.equal(returned(facts)[0].constant,"2"));
});

for (const range of ["0..2","255..256","0..0"]) test(`range-loop element types follow literal bounds: ${range}`, () => {
  compare(`circuit accept(value: Uint<8>): [] {} export circuit entry(): [] { for (const index of ${range}) accept(index); }`);
});

test("destructured anonymous parameters preserve selected field identity", () => {
  compare("export circuit entry(secret: Field): Field { const result = map(([value]: [Field]): Field => value, [[secret]]); return result[0]; }", facts => assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "secret" && flow.form === "raw")));
});

test("Bytes parameter destructuring preserves partial private provenance", () => {
  compare("export circuit entry([byte]: Bytes<2>): Uint<8> { return byte; }", facts => assert.ok(returned(facts)[0].flows.some(flow => flow.form === "derived")));
});

test("full Bytes slices preserve raw private identity without labeling partial slices raw", () => {
  compare("export circuit entry(secret: Bytes<2>): [Bytes<2>,Bytes<1>] { return [slice<2>(secret,0),slice<1>(secret,0)]; }", facts => {
    const [full, partial] = returned(facts)[0].items!;
    assert.ok(full.flows.some(flow => flow.source.name === "secret" && flow.form === "raw"));
    assert.ok(partial.flows.some(flow => flow.source.name === "secret" && flow.form === "derived"));
    assert.ok(partial.flows.every(flow => flow.form !== "raw"));
  });
});

for (const digestOnly of [false,true]) test(`full-width Bytes slice preserves preimage versus hash classification: ${digestOnly}`, () => {
  compare(`import { persistentHash } from CompactStandardLibrary; export ledger digest: Bytes<32>; witness secret(): Bytes<32>; export circuit entry(): Bytes<32> { const value = secret(); const hashed = persistentHash<Bytes<32>>(value); assert(hashed == digest,"bound"); return disclose(slice<32>(${digestOnly ? "hashed" : "value"},0)); }`, facts => {
    assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length,digestOnly ? 0 : 1);
  });
});

test("generic helpers and unrolled indices preserve ledger write order and snapshots", () => {
  compare("import { Map } from CompactStandardLibrary; export ledger values: Map<Field,Field>; circuit select<#N>(input: Vector<N,Field>, index: Uint<8>): Field { return input[index]; } export circuit entry(secret: Field): Field { const input: Vector<2,Field> = [secret,0 as Field]; for (const index of 0..2) values.insert(index as Field,disclose(select<2>(input,index))); const snapshot = values.lookup(0 as Field); values.insert(0 as Field,1 as Field); return snapshot; }", facts => {
    assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "secret"));
    assert.equal(facts.paths[0].writes.length, 3);
    assert.equal(facts.paths[0].writes[1].after.flows.length, 0);
  });
});

test("selected elements compose with guard and secrecy policies without contaminating siblings", () => {
  const policies: Policies = { authorization: [{ state: "stored", guard: "guard" }], secrets: [{ circuit: "entry", parameter: "secret" }] };
  compare('export ledger allowed: Boolean; export ledger stored: Field; circuit guard(): [] { assert(allowed,"allowed"); } export circuit entry(secret: Field, flag: Boolean): Field { const values = [0 as Field,secret]; if (disclose(flag)) guard(); const [,selected] = slice<2>(values,0); stored = disclose(selected); return values[0]; }', facts => {
    const findings = detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies)));
    assert.equal(findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 1);
    assert.ok(findings.some(finding => finding.detectorId === "declared-secret-publication"));
    assert.ok(returned(facts).every(value => !value.flows.some(flow => flow.source.name === "secret")));
  }, policies);
});

const rejected: [string,string,string][] = [
  ["Boolean index", "export circuit entry(): Uint<8> { return [1,2][true]; }", "sequence-index-type"],
  ["Field index", "export circuit entry(): Uint<8> { return [1,2][0 as Field]; }", "sequence-index-type"],
  ["enum index", "enum Position { FIRST,SECOND } export circuit entry(): Uint<8> { return [1,2][Position.FIRST]; }", "sequence-index-type"],
  ["scalar projection", "export circuit entry(): Uint<8> { return (7 as Uint<8>)[0]; }", "sequence-type-mismatch"],
  ["literal index out of bounds", "export circuit entry(): Uint<8> { return [1,2][2]; }", "sequence-index-range"],
  ["literal index compiler maximum", "export circuit entry(): Uint<8> { return [1,2][16777216]; }", "sequence-index-range"],
  ["empty literal projection", "export circuit entry(): Uint<8> { return [][0]; }", "sequence-index-range"],
  ["empty non-literal projection", "export circuit entry(index: Uint<8>): Uint<8> { return default<Bytes<0>>[index]; }", "sequence-index-range"],
  ["non-literal heterogeneous tuple projection", "export circuit entry(): Boolean { const index = 0; return [true,7][index]; }", "incompatible-sequence-elements"],
  ["arithmetic heterogeneous tuple projection", "export circuit entry(): Boolean { return [true,7][0+0]; }", "incompatible-sequence-elements"],
  ["disclosed heterogeneous tuple projection", "export circuit entry(): Boolean { return [true,7][disclose(0)]; }", "incompatible-sequence-elements"],
  ["slice Field index", "export circuit entry(): [Uint<8>] { return slice<1>([1,2],0 as Field); }", "sequence-index-type"],
  ["slice source is scalar", "export circuit entry(): [] { return slice<0>(true,0); }", "sequence-type-mismatch"],
  ["slice range", "export circuit entry(): [Uint<8>,Uint<8>] { return slice<2>([1,2],1); }", "sequence-index-range"],
  ["empty slice beyond end", "export circuit entry(): [] { return slice<0>([1],2); }", "sequence-index-range"],
  ["slice unresolved size", "export circuit entry(): [] { return slice<Size>([1],0); }", "sequence-slice-size"],
  ["slice oversized source length", "export circuit entry(): [] { const unused = slice<16777217>([1],0); }", "sequence-slice-size"],
  ["computed heterogeneous slice", "export circuit entry(): [Boolean] { const offset = 0; return slice<1>([true,7],offset); }", "incompatible-sequence-elements"],
  ["scalar spread", "export circuit entry(): [] { const value = [...true]; }", "sequence-type-mismatch"],
  ["vector spread incompatible element", "export circuit entry(): [] { const value = [true,...default<Vector<1,Uint<8>>>]; }", "incompatible-sequence-elements"],
  ["empty vector spread element participates", "export circuit entry(): [] { const value = [1,...default<Vector<0,Boolean>>]; }", "incompatible-sequence-elements"],
  ["ADT element construction", "import { Map } from CompactStandardLibrary; export circuit entry(): [] { const value = [default<Map<Field,Field>>]; }", "ledger-type-context"],
  ["destructuring selected scalar", "export circuit entry(): [] { const [value] = true; }", "sequence-type-mismatch"],
  ["destructuring selected out of bounds", "export circuit entry(): [] { const [,value] = [1]; }", "sequence-index-range"],
  ["destructuring missing field", "struct Box { value: Field; } export circuit entry(): [] { const { absent } = Box { value: 0 as Field }; }", "unknown-field"],
  ["nested empty pattern still projects", "struct Box { value: Field; } export circuit entry(): [] { const { absent: {} } = Box { value: 0 as Field }; }", "unknown-field"],
  ["parameter pattern duplicate", "export circuit entry([value]: [Field], [value]: [Field]): Field { return value; }", "duplicate-symbol"],
  ["local pattern duplicate", "export circuit entry(): [] { const [value,value] = [1,2]; }", "duplicate-symbol"],
  ["lambda ordinary duplicate", "export circuit entry(): [] { map((value: Field,value: Field): Field => value,[1 as Field],[2 as Field]); }", "duplicate-symbol"],
  ["range loop is not implicitly narrowed", "circuit accept(value: Uint<8>): [] {} export circuit entry(): [] { for (const index of 256..257) accept(index); }", "call-type-mismatch"],
  ["struct pattern cannot omit a named field before a comma", "export circuit entry(): [] { const {,} = 1; }", "parse-error"],
  ["tuple pattern requires separators", "export circuit entry(): [] { const [first second] = [1,2]; }", "parse-error"],
  ["unresolved dynamic index", "export circuit entry(values: Vector<2,Uint<8>>, index: Uint<8>): Uint<8> { return values[index]; }", "unsupported-projection"],
  ["unresolved pure dynamic slice", "export pure circuit entry(values: Bytes<2>, index: Uint<8>): Bytes<1> { return slice<1>(values,index); }", "unsupported-slice"],
];

for (const [name,source,code] of rejected) test(`compiler-rejected sequence operation: ${name}`, () => {
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST,path);
      assert.equal(compiled.valid, false, source);
      assert.ok(!compiled.error?.includes("Internal error"), compiled.error);
    }
    const report = scanFile(path);
    assert.equal(report.status,"incomplete");
    assert.equal(report.diagnostics[0]?.code,code,JSON.stringify(report.diagnostics));
    assert.deepEqual(report.coverage.completedEntries,[]);
  });
});

for (const expression of ["[...values]", "slice<257>(values,0)"]) test(`compiler-valid sequence layout budget remains explicit: ${expression}`, () => {
  withFiles({ "main.compact": `export circuit entry(values: Vector<257,Uint<8>>): Vector<257,Uint<8>> { return ${expression}; }` }, directory => {
    const path = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST,path).valid,true);
    const program = new Program(path);
    for (const engine of ["instructions","expressions"] as const) {
      const facts = new Dataflow(program,20000,256,50000,engine).analyze();
      assert.equal(facts.diagnostics[0]?.code,"sequence-budget");
      assert.deepEqual(facts.completedEntries,[]);
    }
  });
});

test("sequence construction size validation uses shapes without flattening huge vectors", () => {
  withFiles({ "main.compact": "export circuit entry(values: Vector<16777216,Uint<8>>): [] { const copy = [...values,0]; }" }, directory => {
    const report = scanFile(resolve(directory,"main.compact"));
    assert.equal(report.status,"incomplete");
    assert.equal(report.diagnostics[0]?.code,"numeric-type-range");
  });
});

test("invalid imported projection preserves its original Unicode source region", () => {
  withFiles({ "main.compact": 'import "Helper"; export circuit entry(): Uint<8> { return bad(); }', "Helper.compact": "module Helper { /* Ω🚀 */ export circuit bad(): Uint<8> { return [1,2][true]; } }" }, directory => {
    const path = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST,path).valid,false);
    const diagnostic = scanFile(path).diagnostics[0];
    assert.equal(diagnostic.code,"sequence-index-type");
    assert.equal(diagnostic.location.file,resolve(directory,"Helper.compact"));
    const bytes = readFileSync(diagnostic.location.file);
    assert.equal(bytes.subarray(diagnostic.location.start,diagnostic.location.end).toString(),"true");
    assert.equal(diagnostic.location.column,bytes.subarray(0,diagnostic.location.start).toString().length + 1);
  });
});
