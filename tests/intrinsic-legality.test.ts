import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function accepted(source: string, check: (facts: AnalysisFacts) => void = () => {}): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validation.valid, true, validation.error);
    }
    const program = new Program(file);
    const cached = new Dataflow(program).analyze();
    const uncached = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const facts of [cached, uncached, reference]) {
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.failedAssertions, cached.failedAssertions);
      assert.deepEqual(detectors.flatMap(detector => detector.run(facts)), detectors.flatMap(detector => detector.run(cached)));
    }
    assert.deepEqual(cached.paths, uncached.paths);
    assert.deepEqual(semanticPaths(cached), semanticPaths(reference));
    check(cached);
  });
}

function rejected(source: string): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validation.valid, false, source);
      assert.match(validation.error ?? "", /cannot be applied to a first argument containing opaque JavaScript values/);
    }
    const result = scanFile(file);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, "unsupported-opaque-intrinsic", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
}

const returnValue = (facts: AnalysisFacts) => facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
const privateHash = (facts: AnalysisFacts) => assert.ok(returnValue(facts).flows.some(flow => flow.source.name === "input" && flow.form === "hash"));

for (const name of ["persistentHash", "persistentCommit", "keccak256"]) {
  for (const kind of ["string", "Uint8Array"]) test(`${name} rejects Opaque ${kind} inputs`, () => {
    rejected(`import { ${name} } from CompactStandardLibrary; export circuit entry(input: Opaque<"${kind}">): Bytes<32> { return ${name}<Opaque<"${kind}">>(input${name === "persistentCommit" ? ",default<Bytes<32>>" : ""}); }`);
  });
  test(`${name} accepts a phantom Opaque generic with no represented opaque field`, () => {
    accepted(`import { ${name} } from CompactStandardLibrary; struct Box<T> { value: Field; } export circuit entry(input: Field): Bytes<32> { return disclose(${name}<Box<Opaque<"string">>>(Box<Opaque<"string">> { value: input }${name === "persistentCommit" ? ",default<Bytes<32>>" : ""})); }`, facts => {
      assert.ok(returnValue(facts).flows.some(flow => flow.source.name === "input" && flow.form === (name === "persistentCommit" ? "commitment" : "hash")));
    });
  });
}

for (const [name, declarations, type, expression] of [
  ["tuple", "", '[Field,Opaque<"string">]', "input"],
  ["zero vector", "", 'Vector<0,Opaque<"string">>', "input"],
  ["nested represented field", 'struct Box<T> { item: T; }', 'Box<Vector<1,Opaque<"Uint8Array">>>', "input"],
  ["nominal representation", 'new type Text = Opaque<"string">;', "Text", "input"],
  ["transparent alias", 'type Text = Opaque<"string">;', "Text", "input"],
  ["inactive Maybe value", "import { Maybe, none } from CompactStandardLibrary;", 'Maybe<Opaque<"string">>', 'none<Opaque<"string">>()'],
  ["inactive Either branch", "import { Either, left } from CompactStandardLibrary;", 'Either<Field,Opaque<"string">>', 'left<Field,Opaque<"string">>(0 as Field)'],
] as const) test(`persistent hashing checks structural types: ${name}`, () => {
  rejected(`import { persistentHash } from CompactStandardLibrary; ${declarations} export circuit entry(input: ${type}): Bytes<32> { return persistentHash<${type}>(${expression}); }`);
});

for (const size of [0, 1]) test(`map validates native Opaque input even with ${size} iterations`, () => {
  rejected(`import { persistentHash } from CompactStandardLibrary; export circuit entry(input: Vector<${size},Opaque<"string">>): Vector<${size},Bytes<32>> { return map(persistentHash<Opaque<"string">>,input); }`);
});

test("native validation happens after lexical selection rather than falling back", () => {
  rejected('circuit persistentHash<T>(input: T): Bytes<32> { return default<Bytes<32>>; } module Library { import { persistentHash } from CompactStandardLibrary; export circuit run(input: Opaque<"string">): Bytes<32> { return persistentHash<Opaque<"string">>(input); } } import Library; export circuit entry(input: Opaque<"string">): Bytes<32> { return run(input); }');
});

test("generic helpers validate their specialized represented input", () => {
  rejected('import { persistentHash } from CompactStandardLibrary; circuit hash<T>(input: T): Bytes<32> { return persistentHash<T>(input); } export circuit entry(input: Opaque<"string">): Bytes<32> { return hash<Opaque<"string">>(input); }');
});

test("compiler-accepted opaque native alias remains an explicit qualification gap", () => {
  withFiles({ "main.compact": 'import { persistentHash as hash } from CompactStandardLibrary prefix Lib_; export circuit entry(input: Opaque<"string">): Bytes<32> { return Lib_hash<Opaque<"string">>(input); }' }, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST,file);
      assert.equal(validation.valid,true,validation.error);
    }
    const report = scanFile(file);
    assert.equal(report.status,"incomplete");
    assert.equal(report.diagnostics[0]?.code,"unsupported-opaque-intrinsic");
    assert.deepEqual(report.coverage.completedEntries,[]);
  });
});

test("user generic circuits with native names remain legal", () => {
  accepted('import { persistentHash } from CompactStandardLibrary; module Library { circuit persistentHash<T>(input: T): T { return input; } export circuit run(input: Opaque<"string">): Opaque<"string"> { return persistentHash<Opaque<"string">>(input); } } import Library; export circuit entry(input: Opaque<"string">): Opaque<"string"> { return run(input); }', facts => assert.ok(returnValue(facts).flows.some(flow => flow.source.name === "input" && flow.form === "raw")));
});

test("same-name nongeneric user overload does not acquire native restrictions", () => {
  accepted('import { persistentHash } from CompactStandardLibrary; circuit persistentHash(input: Opaque<"string">): Opaque<"string"> { return input; } export circuit entry(input: Opaque<"string">): Opaque<"string"> { return persistentHash(input); }', facts => assert.ok(returnValue(facts).flows.some(flow => flow.source.name === "input" && flow.form === "raw")));
});

test("nominal phantom arguments do not become represented fields", () => {
  accepted('import { persistentHash } from CompactStandardLibrary; new type Token<T> = Field; export circuit entry(input: Field): Bytes<32> { return disclose(persistentHash<Token<Opaque<"string">>>(input as Token<Opaque<"string">>)); }', privateHash);
});

for (const kind of ["string", "Uint8Array"]) test(`transient hashing remains legal for Opaque ${kind}`, () => {
  accepted(`import { transientHash } from CompactStandardLibrary; export circuit entry(input: Opaque<"${kind}">): Field { return disclose(transientHash<Opaque<"${kind}">>(input)); }`, privateHash);
});

test("transient commitment remains legal for Opaque inputs", () => {
  accepted('import { transientCommit } from CompactStandardLibrary; export circuit entry(input: Opaque<"string">, randomness: Field): Field { return disclose(transientCommit<Opaque<"string">>(input,randomness)); }', facts => assert.ok(returnValue(facts).flows.some(flow => flow.source.name === "input" && flow.form === "commitment")));
});

test("mapped persistent hashing accepts ordinary represented fields", () => {
  accepted('import { persistentHash } from CompactStandardLibrary; export circuit entry(input: Field): Bytes<32> { return disclose(map(persistentHash<Field>,[input])[0]); }', privateHash);
});

test("invalid imported native call preserves Unicode source offsets", () => {
  const source = 'module Library { import { persistentHash } from CompactStandardLibrary; /* Ω🚀 */ export circuit hash(input: Opaque<"string">): Bytes<32> { return persistentHash<Opaque<"string">>(input); } }';
  withFiles({ "main.compact": 'import "Library"; export circuit entry(input: Opaque<"string">): Bytes<32> { return hash(input); }', "Library.compact": source }, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) assert.match(validateWithCompiler(process.env.COMPACTC_TEST,file).error ?? "", /opaque JavaScript/);
    const diagnostic = scanFile(file).diagnostics[0];
    assert.equal(diagnostic.code,"unsupported-opaque-intrinsic");
    assert.equal(diagnostic.location!.file,resolve(directory,"Library.compact"));
    assert.equal(readFileSync(diagnostic.location!.file).subarray(diagnostic.location!.start,diagnostic.location!.end).toString(),'persistentHash<Opaque<"string">>(input)');
    assert.equal(diagnostic.location!.column,source.indexOf('persistentHash<Opaque') + 1);
  });
});
