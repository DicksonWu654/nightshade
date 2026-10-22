import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { AnalysisFacts, Dataflow, Program, detectors, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { TypeExportValidator } from "../src/semantic/type-exports.js";
import { AnalysisError, Span } from "../src/model.js";
import { semanticPaths, withFiles } from "./helpers.js";

const entry = "export circuit entry(secret: Field): Field { return secret; }";

function compare(source: string, check: (facts: AnalysisFacts) => void = () => {}, files: Record<string, string> = {}): void {
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
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(expanded));
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

const privateReturn = (facts: AnalysisFacts): void => {
  const results = facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return"));
  assert.ok(results.length > 0);
  assert.ok(results.every(sink => sink.value.flows.some(flow => flow.source.name === "secret")));
};

for (const [name, definitions] of [
  ["type parameter alias", "export type Identity<T> = T;"],
  ["nominal type parameter alias", "export new type Identity<T> = T;"],
  ["mixed parameters", "export struct Box<T,#N> { values: Vector<N,T>; bytes: Bytes<N>; }"],
  ["free width", "export type Word<#N> = Uint<N>;"],
  ["free range end", "export type Word<#N> = Uint<0..N>;"],
  ["free range start and end", "export type Word<#N> = Uint<N..N>;"],
  ["free range start", "export type Word<#N> = Uint<N..2>;"],
  ["type parameter in export size", "export type BytesFor<T> = Bytes<T>;"],
  ["natural parameter in export type", "export type Identity<#N> = N;"],
  ["tuple schema", "export type Pair<T> = [T,Vector<2,T>];"],
  ["concrete nested size", "type Sized<T,#N> = Vector<N,T>; export type Pair<T> = Sized<T,2>;"],
  ["forward alias", "export struct Box<T> { value: Later<T>; } type Later<U> = [U,Field];"],
  ["shadowed outer type", "type T = Missing; export struct Box<T> { value: T; }"],
  ["native fields", "import { Maybe as Optional } from CompactStandardLibrary; export type Box<T> = Optional<T>;"],
  ["native path with concrete size", "import { MerkleTreePath as Path } from CompactStandardLibrary; export type Proof<T> = Path<2,T>;"],
  ["native type wrapped in user alias", "import { JubjubPoint } from CompactStandardLibrary; export type Point = JubjubPoint;"],
  ["re-exported native generic struct", "import { Maybe as Optional } from CompactStandardLibrary; export { Optional };"],
  ["re-exported native sized struct", "import { MerkleTreePath } from CompactStandardLibrary; export { MerkleTreePath };"],
  ["re-exported native concrete struct", "import { ShieldedCoinInfo } from CompactStandardLibrary; export { ShieldedCoinInfo };"],
  ["unused unexported body stays lazy", "struct Unused<T> { value: Missing; } export struct Box<T> { value: T; }"],
  ["unused imported export stays lazy", "module Types { export struct Box<T> { value: Missing; } } import Types;"],
  ["defining lexical scope", "module Types { type Word = Field; export struct Box<T> { value: Word; other: T; } } import Types; type Word = Missing; export { Box };"],
  ["concrete module parameters", "module Types<#N> { export struct Box<T> { values: Vector<N,T>; } } import Types<2>; export { Box };"],
  ["inner parameter shadows module size", "module Types<#N> { export struct Box<#N,T> { values: Vector<N,T>; } } import Types<2>; export { Box };"],
  ["exported phantom parameter", "export struct Box<T> { value: Field; }"],
  ["decoded opaque type", 'export type Text<T> = [T,Opaque<"str\\x69ng">];'],
] as const) test(`compiler-valid export schema: ${name}`, () => compare(`${definitions} ${entry}`, privateReturn));

test("export validation does not poison concrete field or size caches", () => {
  compare("export struct Box<T,#N> { values: Vector<N,T>; } export circuit entry(secret: Field): Field { const first = Box<Field,2> { values: [0 as Field, secret] }; const second = Box<Boolean,1> { values: [false] }; return second.values[0] ? 0 as Field : first.values[1]; }", facts => {
    privateReturn(facts);
    const symbol = [...facts.program.symbols.values()].find(symbol => symbol.name === "Box")!;
    assert.deepEqual(facts.program.fieldsOf(`${symbol.id}<Field,2>`), { values: "Vector<2,Field>" });
    assert.deepEqual(facts.program.fieldsOf(`${symbol.id}<Boolean,1>`), { values: "Vector<1,Boolean>" });
  });
});

test("exported nominal aliases retain concrete provenance and nominal identity", () => {
  compare("export struct Box<T> { value: T; } export new type Key<T> = Box<T>; export circuit entry(secret: Field): Field { const wrapped = Box<Field> { value: secret } as Key<Field>; return (wrapped as Box<Field>).value; }", facts => {
    privateReturn(facts);
    assert.equal(facts.program.nominalTypes.size, 1);
  });
});

for (const [name, expression] of [
  ["nested generic target", "(secret as Tag<Tag<Field>>) as Field"],
  ["unparenthesized chained cast", "secret as Tag<Field> as Field"],
  ["natural cast argument", "(secret as Sized<8>) as Field"],
  ["radix natural cast argument", "(secret as Sized<0x8>) as Field"],
  ["generic cast before comparison", "secret as Tag<Uint<8>> < (3 as Tag<Uint<8>>) ? secret : secret"],
  ["nongeneric cast before less than", "secret as Word < 3 ? secret : secret"],
  ["nongeneric cast before greater than", "secret as Word > 3 ? secret : secret"],
  ["nongeneric cast before parenthesized comparison operand", "secret as Word < (3 as Word) ? secret : secret"],
  ["nongeneric cast before equality", "secret as Word == 3 ? secret : secret"],
] as const) test(`compiler-valid cast ambiguity: ${name}`, () => {
  compare(`export new type Tag<T> = T; export new type Sized<#N> = Uint<N>; type Word = Uint<8>; export circuit entry(secret: Field): Field { return ${expression}; }`, privateReturn);
});

test("generic casts retain exact Unicode source spans", () => {
  compare("export new type Tag<T> = T; export circuit entry(secret: Field): Field { /* Ω🚀 */ const value = secret as Tag<Field>; return value as Field; }", facts => {
    privateReturn(facts);
    const expression = facts.program.functions.get(facts.program.entries[0])!.cfg.nodes.find(node => node.expr?.kind === "cast" && node.expr.type?.includes("Tag<Field>"))!.expr!;
    const source = readFileSync(expression.span.file);
    assert.equal(source.subarray(expression.span.start, expression.span.end).toString(), "secret as Tag<Field>");
    assert.equal(expression.span.column, source.subarray(0, expression.span.start).toString().length + 1);
  });
});

test("exported schemas compose with witness disclosure and ledger writes", () => {
  compare('import { persistentHash } from CompactStandardLibrary; export struct Box<T> { value: T; } witness secret(): Field; export ledger cell: Field; export ledger digest: Bytes<32>; circuit unwrap<T>(value: Box<T>): T { return value.value; } export circuit entry(): Field { const value = secret(); assert(persistentHash<Field>(value) == digest, "bound"); cell = disclose(unwrap<Field>(Box<Field> { value })); return cell; }', facts => {
    privateReturn(facts);
    assert.equal(facts.paths[0].writes.length, 1);
    assert.ok(detectors.flatMap(detector => detector.run(facts)).some(finding => finding.detectorId === "ledger-bound-preimage-publication"));
  });
});

test("imported schema aliases retain original Unicode field spans", () => {
  compare('import { Box as Imported } from "Types" prefix Lib_; export { Lib_Imported }; export circuit entry(secret: Field): Field { const wrapped = Lib_Imported<Field> { value: secret }; return wrapped.value; }', facts => {
    privateReturn(facts);
    const symbol = [...facts.program.symbols.values()].find(symbol => symbol.name === "Box" && !symbol.id.includes("Types.compact::Box"))!;
    const location = symbol.declaration!.parameters[0].span;
    const source = readFileSync(location.file);
    assert.equal(source.subarray(location.start, location.end).toString(), "value: T");
    assert.equal(location.column, source.subarray(0, location.start).toString().length + 1);
  }, { "Types.compact": "module Types { /* Ω🚀 */ export struct Box<T> { value: T; } }" });
});

const rejected: [string, string, string][] = [
  ["unknown generic field type", "export struct Box<T> { value: Missing; }", "unresolved-type"],
  ["unknown phantom argument", "struct Inner<T> { value: Field; } export type Box<T> = Inner<Missing>;", "unresolved-type"],
  ["generic field arity", "export struct Box<T> { value: T<Field>; }", "generic-arity"],
  ["type argument receives natural", "struct Inner<T> { value: T; } export type Box<T> = Inner<2>;", "generic-kind"],
  ["natural argument receives free parameter", "type Inner<#N> = Bytes<N>; export type Box<#N> = Inner<N>;", "generic-kind"],
  ["native size argument receives free parameter", "import { MerkleTreePath } from CompactStandardLibrary; export type Proof<#N,T> = MerkleTreePath<N,T>;", "generic-kind"],
  ["ordinary generic argument is not a size binding", "type Inner<T> = Bytes<T>; export type Box<T> = Inner<T>;", "invalid-numeric-type"],
  ["concrete natural binding is not a type", "type Inner<#N> = N; export type Box<T> = Inner<2>;", "invalid-type-context"],
  ["nonzero range start", "export type Box<#N> = Uint<1..N>;", "invalid-numeric-type"],
  ["zero range end", "export type Box<T> = Uint<0..0>;", "invalid-numeric-type"],
  ["oversized width", "export type Box<T> = Uint<249>;", "invalid-numeric-type"],
  ["oversized sequence", "export type Box<T> = Vector<16777217,T>;", "invalid-numeric-type"],
  ["unresolved sequence size", "export type Box<T> = Bytes<Missing>;", "invalid-numeric-type"],
  ["duplicate type parameter", "export type Box<T,T> = T;", "duplicate-generic-parameter"],
  ["duplicate mixed parameter", "export type Box<T,#T> = T;", "duplicate-generic-parameter"],
  ["concrete exported ADT alias", "import { Counter } from CompactStandardLibrary; export type Count = Counter;", "ledger-type-context"],
  ["nominal exported ADT alias", "import { Counter } from CompactStandardLibrary; export new type Count<T> = Counter;", "ledger-type-context"],
  ["generic struct ADT field", "import { Counter } from CompactStandardLibrary; export struct Box<T> { value: Counter; }", "ledger-type-context"],
  ["native generic ADT element", "import { Maybe, Counter } from CompactStandardLibrary; export type Box<T> = Maybe<Counter>;", "ledger-type-context"],
  ["direct native export", "import { JubjubPoint } from CompactStandardLibrary; export { JubjubPoint };", "invalid-type-export"],
  ["direct ledger type export", "import { Counter } from CompactStandardLibrary; export { Counter };", "invalid-type-export"],
  ["re-export triggers lazy body validation", "module Types { export struct Box<T> { value: Missing; } } import Types; export { Box };", "unresolved-type"],
  ["generic schema cycle", "export struct Box<T> { value: Box<T>; }", "type-depth"],
  ["export alias cycle", "export type Box<T> = Inner<T>; type Inner<U> = Box<U>;", "type-depth"],
  ["concrete usage does not inherit export size erasure", "export type Box<T> = Bytes<T>; circuit unused(value: Box<Field>): [] {}", "invalid-numeric-type"],
  ["generic cast missing argument", "export new type Tag<T> = T; circuit cast(value: Field): [] { value as Tag; }", "generic-arity"],
  ["generic cast wrong argument kind", "export new type Tag<T> = T; circuit cast(value: Field): [] { value as Tag<2>; }", "generic-kind"],
  ["malformed generic cast arguments", "export new type Tag<T> = T; circuit cast(value: Field): [] { value as Tag<Field,,Field>; }", "parse-error"],
];

for (const [name, definitions, code] of rejected) test(`compiler-rejected export schema: ${name}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${definitions} ${entry}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, false);
      assert.ok(!compiled.error?.includes("Internal error"), compiled.error);
    }
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code, JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("invalid imported exported fields report the defining source", () => {
  withFiles({ "main.compact": 'import "Types"; export { Box }; ' + entry, "Types.compact": "module Types { /* Ω🚀 */ export struct Box<T> { value: Missing; } }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const diagnostic = scanFile(path).diagnostics[0];
    assert.equal(diagnostic.code, "unresolved-type");
    assert.equal(diagnostic.location.file, resolve(directory, "Types.compact"));
    const source = readFileSync(diagnostic.location.file);
    assert.equal(source.subarray(diagnostic.location.start, diagnostic.location.end).toString(), "value: Missing");
    assert.equal(diagnostic.location.column, source.subarray(0, diagnostic.location.start).toString().length + 1);
  });
});

test("compiler declarations erase natural schema dimensions without runtime instantiation", { skip: !process.env.COMPACTC_TEST }, () => {
  withFiles({ "main.compact": "pragma language_version >= 0.26.0; export struct Box<T,#N> { values: Vector<N,T>; bytes: Bytes<N>; } " + entry }, directory => {
    const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", resolve(directory, "main.compact"), resolve(directory, "output")], { encoding: "utf8", timeout: 30000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    const types = readFileSync(resolve(directory, "output/contract/index.d.ts"), "utf8");
    assert.match(types, /export type Box<T>\s*=\s*\{/);
    assert.match(types, /values: T\[\]/);
    assert.match(types, /bytes: Uint8Array/);
    assert.ok(!types.includes("Box<T, N>"));
  });
});

test("schema validation work is bounded independently of runtime type caches", () => {
  const location: Span = { file: "unit.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
  const validator = new TypeExportValidator(() => undefined);
  const symbol = { id: "unit::Word", name: "Word", kind: "type" as const, type: "Field", span: location, declaration: { kind: "type" as const, typeKind: "alias" as const, name: "Word", type: "Field", exported: true, parameters: [], span: location } };
  for (let index = 0; index < 2048; index++) validator.validate(symbol);
  assert.throws(() => validator.validate(symbol), (error: unknown) => error instanceof AnalysisError && error.diagnostic.code === "type-budget");
});
