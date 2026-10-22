import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { FIELD_MODULUS, MAX_SEQUENCE_LENGTH, UINT_BITS, UINT_BOUND, arithmeticType, numericBound } from "../src/semantic/types.js";
import { semanticPaths, withFiles } from "./helpers.js";

test("canonical Uint bound queries agree with parsed spellings and preserve legality boundaries", () => {
  for (const size of ["0", "1", "8", "64", "248", "249", "00064", "0..0", "0..1", "0..340282366920938463463374607431768211457", "00..0007", "N", "-1", "8,Field"]) {
    assert.equal(numericBound(`Uint<${size}>`), numericBound(` Uint < ${size} > `), size);
  }
});

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
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
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

test("numeric limits and exclusive arithmetic bounds match the qualified compiler", () => {
  assert.equal(UINT_BITS, 248);
  assert.equal(MAX_SEQUENCE_LENGTH, 16777216n);
  assert.equal(numericBound("Uint<248>"), UINT_BOUND);
  assert.equal(numericBound("Uint<249>"), undefined);
  assert.equal(arithmeticType("+", "Uint<8>", "Uint<8>"), "Uint<0..511>");
  assert.equal(arithmeticType("*", "Uint<8>", "Uint<8>"), "Uint<0..65026>");
  assert.equal(arithmeticType("-", "Uint<8>", "Uint<16>"), "Uint<0..256>");
});

for (const type of ["Uint<0>", "Uint<248>", `Uint<0..${UINT_BOUND}>`, "Bytes<0>", "Vector<0, Field>", "[Uint<0>, Bytes<0>]"]) test(`source type ${type} remains supported`, () => {
  compare(`circuit identity(value: ${type}): ${type} { return value; } export circuit entry(value: ${type}): ${type} { return identity(value); }`, facts => {
    assert.equal(returned(facts).length, 1);
    assert.equal(facts.program.sameType("Uint<248>", `Uint<0..${UINT_BOUND}>`), true);
  });
});

for (const [expression, bound] of [["first + second", 511], ["first * second", 65026], ["first + 0", 256], ["first * 0", 1], ["first - second", 256]] as const) test(`arithmetic ${expression} resolves calls at its exact result bound`, () => {
  compare(`circuit identity(value: Uint<0..${bound}>): Uint<0..${bound}> { return value; } export circuit entry(first: Uint<8>, second: Uint<8>): Uint<0..${bound}> { return identity(${expression}); }`, facts => {
    assert.equal(returned(facts).length, 1);
    assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "first"));
    const call = facts.program.functions.get(facts.program.entries[0])!.cfg.nodes.find(node => node.kind === "return")!.expr!;
    assert.equal(numericBound(call.args[0].inferredType!), BigInt(bound));
  });
});

test("exact arithmetic bounds restore nearest-compatible overload selection", () => {
  compare("circuit select(value: Uint<9>): Uint<8> { return 0; } module Inner { export circuit select(value: Uint<0..511>): Uint<8> { return 1; } export circuit calculate(first: Uint<8>, second: Uint<8>): Uint<8> { return select(first + second); } } import { calculate } from Inner; export circuit entry(): Uint<8> { return calculate(2, 3); }", facts => assert.equal(returned(facts)[0].constant, "1"));
});

test("a correctly selected bounded overload retains private-derived return flows", () => {
  compare("circuit select(value: Uint<9>): Uint<0..511> { return 0; } module Inner { export circuit select(value: Uint<0..511>): Uint<0..511> { return value; } export circuit calculate(first: Uint<8>, second: Uint<8>): Uint<0..511> { return select(first + second); } } import { calculate } from Inner; export circuit entry(secret: Uint<8>): Uint<0..511> { return calculate(secret, 0); }", facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(returned(facts)[0].flows[0].form, "derived");
  });
});

test("largest unsigned literal retains its exact value", () => {
  compare(`export circuit entry(): Uint<248> { return ${UINT_BOUND - 1n}; }`, facts => assert.equal(returned(facts)[0].constant, String(UINT_BOUND - 1n)));
});

for (const target of ["Field", "Alias", "Nominal"]) test(`large direct literal casts to ${target} retain Field arithmetic`, () => {
  compare(`type Alias = Field; new type Nominal = Field; export circuit entry(): ${target} { return (${FIELD_MODULUS - 1n} as ${target}) + (1 as ${target}); }`, facts => assert.equal(returned(facts)[0].constant, "0"));
});

test("explicit Field operands permit arithmetic above unsigned result bounds", () => {
  compare(`export circuit entry(): Field { const maximum = ${UINT_BOUND - 1n}; return (maximum as Field) + maximum; }`, facts => assert.equal(returned(facts)[0].constant, String(2n * (UINT_BOUND - 1n))));
});

test("valid large Field narrowing aborts without becoming a source-legality diagnostic", () => {
  compare(`export circuit entry(): Uint<248> { return (${UINT_BOUND} as Field) as Uint<248>; }`, facts => assert.deepEqual(facts.paths, []));
});

for (const type of [`Bytes<${MAX_SEQUENCE_LENGTH}>`, `Vector<${MAX_SEQUENCE_LENGTH}, Field>`]) test(`maximum ${type} is validated without allocating an unused value`, () => {
  compare(`circuit marker<T>(): Field { return 7 as Field; } export circuit entry(): Field { return marker<${type}>(); }`, facts => assert.equal(returned(facts)[0].constant, "7"));
});

test("typed metadata ignores comments without rewriting source spans or quoted contents", () => {
  compare('import CompactStandardLibrary; type Byte<# /* parameter */ N> = Uint</* width */ N>; circuit identity<T>(value: T): T { return value; } export circuit entry(secret: Byte</* argument */ 8>): [Uint<8>, Bytes<32>] { const value: Uint</* local */ 8> = identity<Byte</* generic */ 8>>(secret); const copied = ((item: Uint</* input */ 8>): Uint</* result */ 8> => item)(value); return disclose([copied as Uint</* cast */ 8>, persistentCommit<Uint<8>>(secret, pad(/* Ω🚀 */ 0X20, "//<salt>,/*text*/"))]); }', facts => {
    const items = returned(facts)[0].items!;
    assert.equal(items[0].flows[0].source.name, "secret");
    const commitment = items[1].commitments![0];
    assert.equal(commitment.randomness.constant, Buffer.from("//<salt>,/*text*/").toString("hex").padEnd(64, "0"));
    const location = commitment.location;
    const source = readFileSync(location.file);
    assert.equal(source.subarray(location.start, location.end).toString(), 'persistentCommit<Uint<8>>(secret, pad(/* Ω🚀 */ 0X20, "//<salt>,/*text*/"))');
    assert.equal(location.column, source.subarray(0, location.start).toString().length + 1);
    assert.equal(detectors.find(detector => detector.id === "predictable-commitment-randomness")!.run(facts).length, 1);
  });
});

test("commented natural parameters and imports retain specialization identity", () => {
  compare("module Helper<T, # /* natural */ N> { export circuit pass(value: Vector</* size */ N, T>): Vector<N, T> { return value; } } import Helper</* type */ Field, /* size */ 1>; export circuit entry(secret: Field): Field { return map(/* reference */ pass, [[secret]])[0][0]; }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "secret"));
});

const rejected: [string, string, string][] = [
  ["width exceeds 248", "export circuit entry(value: Uint<249>): [] {}", "invalid-numeric-type"],
  ["width is not rounded to a Field bit count", "export circuit entry(value: Uint<254>): [] {}", "invalid-numeric-type"],
  ["empty unsigned range", "export circuit entry(value: Uint<0..0>): [] {}", "invalid-numeric-type"],
  ["nonzero range start", "export circuit entry(value: Uint<1..8>): [] {}", "invalid-numeric-type"],
  ["range exceeds Uint", `export circuit entry(value: Uint<0..${UINT_BOUND + 1n}>): [] {}`, "invalid-numeric-type"],
  ["unresolved width", "export circuit entry(value: Uint<Missing>): [] {}", "invalid-numeric-type"],
  ["oversized Bytes", `circuit marker<T>(): [] {} export circuit entry(): [] { marker<Bytes<${MAX_SEQUENCE_LENGTH + 1n}>>(); }`, "invalid-numeric-type"],
  ["oversized Vector", `circuit marker<T>(): [] {} export circuit entry(): [] { marker<Vector<${MAX_SEQUENCE_LENGTH + 1n}, Field>>(); }`, "invalid-numeric-type"],
  ["nested invalid numeric type", "export circuit entry(value: Vector<2, Uint<249>>): [] {}", "invalid-numeric-type"],
  ["specialized invalid width", "type Word<#N> = Uint<N>; export circuit entry(value: Word<249>): [] {}", "invalid-numeric-type"],
  ["unused module type argument still checked", "module Marker<T> { export circuit answer(): [] {} } import Marker<Uint<249>>; export circuit entry(): [] { answer(); }", "invalid-numeric-type"],
  ["constant exceeds Field", `export circuit entry(): Field { return ${FIELD_MODULUS} as Field; }`, "literal-range"],
  ["unannotated literal exceeds Uint", `export circuit entry(): Field { return ${UINT_BOUND}; }`, "literal-type"],
  ["large Boolean literal conversion is not a direct Field cast", `export circuit entry(): Boolean { return ${UINT_BOUND} as Boolean; }`, "literal-type"],
  ["an outer cast does not legalize an inner literal", `export circuit entry(): Field { return (${UINT_BOUND} + 0) as Field; }`, "literal-type"],
  ["numeric generic exceeds Field", `circuit marker<#N>(): [] {} export circuit entry(): [] { marker<${FIELD_MODULUS}>(); }`, "literal-range"],
  ["unsigned addition exceeds the type limit", "export circuit entry(first: Uint<248>, second: Uint<248>): Field { return (first + second) as Field; }", "arithmetic-range"],
  ["unsigned multiplication exceeds the type limit", "export circuit entry(first: Uint<128>, second: Uint<128>): Field { return (first * second) as Field; }", "arithmetic-range"],
  ["nominal narrowing cannot legalize oversized intermediate arithmetic", "new type Wide = Uint<248>; export circuit entry(first: Wide, second: Wide): Wide { return first + second; }", "arithmetic-range"],
  ["Boolean is not a numeric arithmetic operand", "export circuit entry(value: Field): Field { return value + true; }", "arithmetic-type-mismatch"],
  ["Bytes is not a numeric arithmetic operand", "export circuit entry(value: Field): Field { return value * default<Bytes<1>>; }", "arithmetic-type-mismatch"],
];

for (const [name, source, code] of rejected) test(`compiler-rejected numeric application: ${name}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code, JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});
