import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void = () => {}): void {
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

const privateReturn = (facts: AnalysisFacts): void => {
  assert.equal(returned(facts).length, 1);
  assert.ok(returned(facts)[0].flows.some(flow => flow.source.name === "secret"));
};

test("selected and renamed native types retain canonical field provenance", () => {
  compare("import { Maybe as Optional, some as present } from CompactStandardLibrary; circuit unwrap(value: Optional<Field>): Field { return value.value; } export circuit entry(secret: Field): Field { return unwrap(present<Field>(secret)); }", facts => {
    privateReturn(facts);
    assert.equal([...facts.program.symbols.values()].find(symbol => symbol.name === "unwrap")!.declaration!.parameters[0].type, "standard-type::Maybe<Field>");
  });
});

test("native results cannot be recaptured by a user type with the same spelling", () => {
  compare("import { some } from CompactStandardLibrary; struct Maybe<T> { value: Boolean; } circuit pass(value: Field): Field { return value; } export circuit entry(secret: Field): Field { const wrapped = some<Field>(secret); return pass(wrapped.value); }", privateReturn);
});

test("a local value cannot recapture an already resolved native field identity", () => {
  compare("import { some } from CompactStandardLibrary; export circuit entry(secret: Field): Field { const Maybe = false; const wrapped = some<Field>(secret); return wrapped.value; }", privateReturn);
});

test("selected constructors do not require callers to import their result types", () => {
  compare("import { left, right } from CompactStandardLibrary; export circuit entry(secret: Field): Field { const first = left<Field, Boolean>(secret); const second = right<Boolean, Field>(secret); return first.left + second.right; }", privateReturn);
});

test("higher-order native results use the same canonical identity", () => {
  compare("import { some, Maybe as Optional } from CompactStandardLibrary; export circuit entry(secret: Field): Optional<Field> { return map(some<Field>, [secret])[0]; }", privateReturn);
});

test("prefixed native struct construction preserves Unicode source spans", () => {
  compare("import { Maybe } from CompactStandardLibrary prefix Native_; export circuit entry(secret: Field): Field { /* Ω🚀 */ const wrapped = Native_Maybe<Field> { is_some: true, value: secret }; return wrapped.value; }", facts => {
    privateReturn(facts);
    const expression = facts.program.functions.get(facts.program.entries[0])!.cfg.nodes.find(node => node.expr?.kind === "struct")!.expr!;
    const location = expression.span;
    const source = readFileSync(location.file);
    assert.equal(source.subarray(location.start, location.end).toString(), "Native_Maybe<Field> { is_some: true, value: secret }");
    assert.equal(location.column, source.subarray(0, location.start).toString().length + 1);
  });
});

test("native field prototypes are resolved in their defining library", () => {
  compare("import { MerkleTreePath as Path } from CompactStandardLibrary; struct MerkleTreePathEntry { sibling: Boolean; } export circuit entry(secret: Field): Field { const proof = default<Path<2, Field>>; return proof.path[0].sibling.field + secret; }", privateReturn);
});

test("curve intrinsic signatures do not require native type-name imports", () => {
  compare("import { constructJubjubPoint, ecAdd, jubjubPointX } from CompactStandardLibrary; export circuit entry(secret: Field): Field { const point = constructJubjubPoint(secret, 1 as Field); return jubjubPointX(ecAdd(point, point)); }", privateReturn);
});

test("native witness results have fields without an explicit result-type import", () => {
  compare("import { ownPublicKey } from CompactStandardLibrary; export circuit entry(): Bytes<32> { return ownPublicKey().bytes; }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "ownPublicKey"));
});

test("struct fields use their defining lexical scope rather than the caller's", () => {
  compare("module Types { type Word = Field; export struct Box { value: Word; } } import Types; type Word = Boolean; export circuit entry(secret: Field): Field { const wrapped = Box { value: secret }; return wrapped.value; }", privateReturn);
});

test("forward type references resolve before parameter names enter scope", () => {
  compare("struct Box { value: Later; } type Later = Field; export circuit entry(Later: Boolean, secret: Box): Field { return secret.value; }", privateReturn);
});

test("annotated lambda parameters resolve before value bindings enter scope", () => {
  compare("type Word = Field; export circuit entry(secret: Field): Field { return ((Word: Boolean, value: Word): Field => value)(false, secret); }", privateReturn);
});

test("generic struct fields are validated after substitution", () => {
  compare("struct Box<T, #N> { values: Vector<N,T>; } export circuit entry(secret: Field): Field { const wrapped = Box<Field,1> { values: [secret] }; return wrapped.values[0]; }", privateReturn);
});

test("Tuple is a legal user struct name rather than an internal tuple tag", () => {
  compare("struct Tuple { value: Field; } export circuit entry(secret: Tuple): Field { return secret.value; }", privateReturn);
});

test("generic user Tuple construction retains its fields", () => {
  compare("struct Tuple<T> { value: T; } export circuit entry(secret: Field): Field { const wrapped = Tuple<Field> { value: secret }; return wrapped.value; }", privateReturn);
});

test("a Tuple alias does not become an empty tuple", () => {
  compare("type Tuple = Field; circuit pass(value: Tuple): Tuple { return value; } export circuit entry(secret: Field): Field { return pass(secret); }", privateReturn);
});

test("user Counter structs and renamed native Counters have distinct effects", () => {
  compare("import { Counter as Count } from CompactStandardLibrary; struct Counter { value: Field; } export ledger count: Count; export ledger cell: Counter; export circuit entry(secret: Field): Field { count.increment(1); cell.write(Counter { value: disclose(secret) }); return cell.value; }", privateReturn);
});

test("an explicitly declared unknown type is not an inference sentinel", () => {
  compare("type unknown = Field; export circuit entry(secret: Field): Field { return ((value: unknown): unknown => value)(secret); }", privateReturn);
});

test("exported concrete types are checked even without value uses", () => {
  compare("export struct Box { value: Field; } export type Word = Field; export enum Mode { ready, done } export circuit entry(): [] {}");
});

test("uninstantiated imported type bodies stay lazy until re-export or use", () => {
  compare("module Types { export struct Box { value: Missing; } } import Types; export circuit entry(): [] {}");
});

for (const declaration of ["struct Unused { value: Missing; }", "type Unused = Missing;", "import CompactStandardLibrary; struct Unused { value: Counter; }"]) test(`unused unexported type body remains lazy: ${declaration}`, () => {
  compare(`${declaration} export circuit entry(secret: Field): Field { return secret; }`, privateReturn);
});

test("renamed ledger ADTs share typed nested region effects", () => {
  compare("import { Map as Table, Counter as Count } from CompactStandardLibrary; export ledger table: Table<Field, Count>; export circuit entry(): [] { table.insertDefault(0 as Field); table.lookup(0 as Field).increment(1); }", facts => {
    const entry = facts.program.functions.get(facts.program.entries[0])!;
    assert.equal(entry.writesState.size, 1);
    assert.equal(facts.paths[0].writes.length, 2);
  });
});

test("prefixed ledger ADTs preserve standard container results despite shadowing", () => {
  compare("import { List } from CompactStandardLibrary prefix Native_; struct Maybe<T> { value: Boolean; } export ledger queue: Native_List<Field>; export circuit entry(secret: Field): Field { queue.pushFront(disclose(secret)); return queue.head().value; }", privateReturn);
});

test("ADT defaults and typed local values can initialize nested storage", () => {
  compare("import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Map<Field,Field>>; export circuit entry(secret: Field): Field { const empty: Map<Field,Field> = default<Map<Field,Field>>; table.insert(0 as Field, empty); table.lookup(0 as Field).insert(1 as Field, disclose(secret)); return table.lookup(0 as Field).lookup(1 as Field); }", privateReturn);
});

test("ADT aliases are legal generic arguments when unused in ordinary positions", () => {
  compare("import { Counter } from CompactStandardLibrary; new type Count = Counter; circuit marker<T>(): Field { return 7 as Field; } export circuit entry(): Field { return marker<Count>(); }", facts => assert.equal(returned(facts)[0].constant, "7"));
});

test("Kernel is a legal imported top-level ledger type", () => {
  compare("import { Kernel } from CompactStandardLibrary; export ledger kernel: Kernel; export circuit entry(): [] {}", facts => assert.equal(facts.paths.length, 1));
});

for (const type of ["MerkleTree<2,Field>", "MerkleTree<32,Field>", "HistoricMerkleTree<2,Field>", "HistoricMerkleTree<32,Field>"]) test(`ledger type depth boundary ${type}`, () => {
  compare(`import CompactStandardLibrary; export ledger tree: ${type}; export circuit entry(): [] {}`);
});

for (const type of ['Opaque<"string">', "Opaque<'Uint8Array'>", 'Opaque<"str\\x69ng">']) test(`opaque type spelling ${type} preserves provenance`, () => {
  compare(`export circuit entry(secret: ${type}): ${type} { return secret; }`, privateReturn);
});

const rejected: [string, string, string][] = [
  ["undeclared parameter type", "export circuit entry(value: Missing): [] {}", "unresolved-type"],
  ["undeclared Tuple is not a builtin", "export circuit entry(value: Tuple): [] {}", "unresolved-type"],
  ["undeclared result type", "export circuit entry(): Missing {}", "unresolved-type"],
  ["unknown is not an inference keyword", "export circuit entry(value: unknown): [] {}", "unresolved-type"],
  ["unknown is not an inferred lambda annotation", "export circuit entry(): [] { map((value: unknown) => value, [1]); }", "unresolved-type"],
  ["unknown is not an inferred lambda return annotation", "export circuit entry(): [] { map((value): unknown => value, [1]); }", "unresolved-type"],
  ["missing Counter import", "export ledger count: Counter; export circuit entry(): [] {}", "unresolved-type"],
  ["missing Map import", "export ledger table: Map<Field,Field>; export circuit entry(): [] {}", "unresolved-type"],
  ["empty stdlib selection provides no types", "import {} from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] {}", "unresolved-type"],
  ["selected constructor does not import Maybe", "import { some } from CompactStandardLibrary; export circuit entry(value: Maybe<Field>): [] {}", "unresolved-type"],
  ["type renamed away", "import { Maybe as Optional } from CompactStandardLibrary; export circuit entry(value: Maybe<Field>): [] {}", "unresolved-type"],
  ["local value shadows a type", "type Word = Field; export circuit entry(): [] { const Word = 0; const value: Word = 1 as Field; }", "invalid-type-context"],
  ["parameter shadows a type in a local annotation", "type Word = Field; export circuit entry(Word: Field): [] { const value: Word = 1 as Field; }", "invalid-type-context"],
  ["circuit name is not a type", "circuit Helper(): [] {} export circuit entry(value: Helper): [] {}", "invalid-type-context"],
  ["ledger name is not a type", "export ledger Word: Field; export circuit entry(value: Word): [] {}", "invalid-type-context"],
  ["module name is not a type", "module Helper {} export circuit entry(value: Helper): [] {}", "invalid-type-context"],
  ["unused non-generic circuit signature is checked", "circuit unused(value: Missing): [] {} export circuit entry(): [] {}", "unresolved-type"],
  ["used struct field is checked", "struct Box { value: Missing; } export circuit entry(value: Box): [] {}", "unresolved-type"],
  ["exported struct is checked", "export struct Box { value: Missing; } export circuit entry(): [] {}", "unresolved-type"],
  ["exported alias is checked", "export type Word = Missing; export circuit entry(): [] {}", "unresolved-type"],
  ["re-exported struct is checked", "module Types { export struct Box { value: Missing; } } import Types; export { Box }; export circuit entry(): [] {}", "unresolved-type"],
  ["missing user struct type argument", "struct Box<T> { value: T; } export circuit entry(value: Box): [] {}", "generic-arity"],
  ["extra user struct type argument", "struct Box { value: Field; } export circuit entry(value: Box<Field>): [] {}", "generic-arity"],
  ["wrong struct generic kind", "struct Box<T> { value: T; } export circuit entry(value: Box<1>): [] {}", "generic-kind"],
  ["wrong natural struct generic kind", "struct Box<#N> { value: Vector<N,Field>; } export circuit entry(value: Box<Field>): [] {}", "generic-kind"],
  ["extra enum argument", "enum Mode { ready, done } export circuit entry(value: Mode<Field>): [] {}", "generic-arity"],
  ["missing standard struct argument", "import { Maybe } from CompactStandardLibrary; export circuit entry(value: Maybe): [] {}", "generic-arity"],
  ["extra native type argument", "import { JubjubPoint } from CompactStandardLibrary; export circuit entry(value: JubjubPoint<Field>): [] {}", "generic-arity"],
  ["missing ADT argument", "import { Map } from CompactStandardLibrary; export ledger table: Map<Field>; export circuit entry(): [] {}", "generic-arity"],
  ["extra ADT argument", "import { Counter } from CompactStandardLibrary; export ledger count: Counter<Field>; export circuit entry(): [] {}", "generic-arity"],
  ["circuit parameter ADT", "import { Counter } from CompactStandardLibrary; export circuit entry(value: Counter): [] {}", "ledger-type-context"],
  ["witness result ADT", "import { Counter } from CompactStandardLibrary; witness value(): Counter; export circuit entry(): [] {}", "ledger-type-context"],
  ["circuit result ADT", "import { Counter } from CompactStandardLibrary; export circuit entry(): Counter { return default<Counter>; }", "ledger-type-context"],
  ["lambda parameter ADT", "import { Counter } from CompactStandardLibrary; export circuit entry(): [] { map((value: Counter): [] => {}, []); }", "ledger-type-context"],
  ["aliased circuit parameter ADT", "import { Counter } from CompactStandardLibrary; new type Count = Counter; export circuit entry(value: Count): [] {}", "ledger-type-context"],
  ["tuple element ADT", "import { Counter } from CompactStandardLibrary; export ledger values: [Counter]; export circuit entry(): [] {}", "ledger-type-context"],
  ["vector element ADT", "import { Counter } from CompactStandardLibrary; export ledger values: Vector<1,Counter>; export circuit entry(): [] {}", "ledger-type-context"],
  ["struct field ADT", "import { Counter } from CompactStandardLibrary; struct Box { value: Counter; } export circuit entry(value: Box): [] {}", "ledger-type-context"],
  ["generic struct field ADT", "import { Counter } from CompactStandardLibrary; struct Box<T> { value: T; } export circuit entry(value: Box<Counter>): [] {}", "ledger-type-context"],
  ["Maybe element ADT", "import CompactStandardLibrary; export circuit entry(value: Maybe<Counter>): [] {}", "ledger-type-context"],
  ["Map key ADT", "import CompactStandardLibrary; export ledger values: Map<Counter,Field>; export circuit entry(): [] {}", "ledger-type-context"],
  ["List element ADT", "import CompactStandardLibrary; export ledger values: List<Counter>; export circuit entry(): [] {}", "ledger-type-context"],
  ["Set element ADT", "import CompactStandardLibrary; export ledger values: Set<Counter>; export circuit entry(): [] {}", "ledger-type-context"],
  ["Cell is not a stdlib export", "import { Cell } from CompactStandardLibrary; export circuit entry(): [] {}", "unsupported-stdlib-export"],
  ["nested Kernel", "import CompactStandardLibrary; export ledger table: Map<Field,Kernel>; export circuit entry(): [] {}", "nested-kernel-type"],
  ["aliased nested Kernel", "import CompactStandardLibrary; new type Core = Kernel; export ledger table: Map<Field,Core>; export circuit entry(): [] {}", "nested-kernel-type"],
  ["Kernel has no default", "import { Kernel } from CompactStandardLibrary; export circuit entry(): [] { const value = default<Kernel>; }", "invalid-default-type"],
  ["unsupported opaque kind", 'export circuit entry(value: Opaque<"Whatever">): [] {}', "unsupported-opaque-type"],
  ["Merkle depth below minimum", "import CompactStandardLibrary; export ledger tree: MerkleTree<1,Field>; export circuit entry(): [] {}", "invalid-merkle-depth"],
  ["Merkle depth above maximum", "import CompactStandardLibrary; export ledger tree: MerkleTree<33,Field>; export circuit entry(): [] {}", "invalid-merkle-depth"],
  ["historic depth below minimum", "import CompactStandardLibrary; export ledger tree: HistoricMerkleTree<1,Field>; export circuit entry(): [] {}", "invalid-merkle-depth"],
  ["historic depth above maximum", "import CompactStandardLibrary; export ledger tree: HistoricMerkleTree<33,Field>; export circuit entry(): [] {}", "invalid-merkle-depth"],
  ["recursive struct", "struct Box { value: Box; } export circuit entry(value: Box): [] {}", "type-depth"],
];

for (const [name, source, code] of rejected) test(`compiler-rejected type resolution: ${name}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code, JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("exported generic types are validated without instantiation", () => {
  compare("export struct Box<T> { value: T; } export circuit entry(): [] {}");
});
