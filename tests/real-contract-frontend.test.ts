import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, resolvePolicies, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, files: Record<string, string> = {}): void {
  withFiles({ ...files, "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
}
const returns = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));

test("MockSigner-shaped import overloads expose only the explicit wrapper", () => {
  compare(`module Signer<T> { export circuit check(value: T): T { return value; } }
import Signer<Field> prefix S_; import Signer<Field>;
export circuit check(value: Field): Field { return S_check(value); }`, facts => {
    assert.equal(facts.program.entries.length, 1);
    assert.equal(facts.program.symbols.get(facts.program.entries[0])!.id, facts.program.root + "::check");
    assert.equal(returns(facts)[0].flows[0].source.name, "value");
  });
});

test("same-signature local declarations may coexist with one explicit export", () => {
  compare(`circuit check(): Field { return 1 as Field; }
export circuit check(): Field { return 2 as Field; }`, facts => assert.equal(returns(facts)[0].constant, "2"));
});

test("module declaration exports do not include same-name imported circuits", () => {
  compare(`module First { export circuit check(): Field { return 1 as Field; } }
module Wrapper { import First; export circuit check(): Field { return 2 as Field; } }
import Wrapper; export circuit entry(): Field { return check(); }`, facts => assert.equal(returns(facts)[0].constant, "2"));
});

test("nested Counter reads have Uint64 value types while mutations keep Counter storage", () => {
  compare(`import CompactStandardLibrary;
export ledger counts: Map<Field, Counter>;
export circuit entry(): [Uint<64>, Field] {
  counts.insertDefault(0 as Field);
  counts.lookup(0 as Field).increment(1);
  const saved = counts.lookup(0 as Field);
  counts.lookup(0 as Field).increment(1);
  return [saved, counts.lookup(0 as Field) as Field];
}`, facts => {
    assert.deepEqual(returns(facts)[0].items!.map(value => value.constant), ["1", "2"]);
    const operations = facts.program.instructionCFG(facts.program.entries[0]).nodes.flatMap(node => node.instruction?.kind === "evaluate" && node.instruction.expression.name === "increment" ? [node.instruction] : []);
    assert.equal(operations.length, 2);
    assert.ok(operations.every(operation => operation.effects.includes("state-write") && operation.effects.includes("may-abort")));
  });
});

test("nested Counter numeric casts retain amount and lookup-key provenance", () => {
  compare(`import CompactStandardLibrary;
export ledger counts: Map<Field, Counter>;
export circuit entry(key: Field, amount: Uint<16>): Field {
  counts.insertDefault(disclose(key));
  counts.lookup(disclose(key)).increment(disclose(amount));
  return counts.lookup(disclose(key)) as Field;
}`, facts => {
    assert.deepEqual(new Set(returns(facts)[0].flows.map(flow => flow.source.name)), new Set(["key", "amount"]));
    assert.ok(facts.paths[0].writes.some(write => write.after.flows.some(flow => flow.source.name === "amount")));
  });
});

test("nested Counter casts share checked numeric rejection", () => {
  compare(`import CompactStandardLibrary;
export ledger counts: Map<Field, Counter>;
export circuit entry(): Uint<8> {
  counts.insertDefault(0 as Field); counts.lookup(0 as Field).increment(256);
  return counts.lookup(0 as Field) as Uint<8>;
}`, facts => assert.equal(facts.paths.length, 0));
});

test("Ciphertext value identity crosses physical imports without merging storage", () => {
  compare(`import "a/Cipher" prefix A_; import "b/Cipher" prefix B_;
export circuit entry(value: A_Ciphertext): B_Ciphertext {
  A_put(disclose(value)); B_put(default<B_Ciphertext>);
  return value as B_Ciphertext;
}`, facts => {
    assert.equal(new Set(facts.paths[0].writes.map(write => write.ledger)).size, 2);
    assert.equal(returns(facts)[0].fields!.payload.flows[0].source.name, "value");
  }, Object.fromEntries(["a", "b"].map(directory => [`${directory}/Cipher.compact`, `module Cipher {
export struct Ciphertext { payload: Field; nonce: Bytes<32>; }
export ledger state: Ciphertext;
export circuit put(value: Ciphertext): [] { state = disclose(value); }
}`])));
});

test("cross-module same-name structs compare represented fields, not phantom generics", () => {
  compare(`module A { export struct Value<T> { field: Field; } }
module B { export struct Value<T, #N> { field: Field; } }
import A prefix A_; import B prefix B_;
export circuit entry(value: A_Value<Field>): B_Value<Boolean, 7> { return value; }`, facts => assert.equal(returns(facts)[0].fields!.field.flows[0].source.name, "value"));
});

test("same-name nominal fields compare names and represented types across modules", () => {
  compare(`module A { export new type Word = Uint<8>; export struct Value { field: Word; } }
module B { export new type Word = Uint<8>; export struct Value { field: Word; } }
import A prefix A_; import B prefix B_;
export circuit entry(value: A_Value): B_Value {
  assert(value.field <= default<B_Word>, "bounded"); return value;
}`, facts => assert.equal(returns(facts)[0].fields!.field.flows[0].source.name, "value"));
});

test("native and user structs use the same declared-name and ordered-field equality", () => {
  compare(`import CompactStandardLibrary prefix S_;
struct ContractAddress { bytes: Bytes<32>; }
export circuit entry(value: ContractAddress): S_ContractAddress { return value; }`, facts => assert.equal(returns(facts)[0].fields!.bytes.flows[0].source.name, "value"));
});

test("equal enum declarations share constants, defaults and numeric casts across imports", () => {
  compare(`module A { export enum Choice { zero, one } }
module B { export enum Choice { zero, one } }
import A prefix A_; import B prefix B_;
export circuit entry(): [Boolean, Boolean, Uint<8>] {
  const one = A_Choice.one as B_Choice;
  return [one == B_Choice.one, default<A_Choice> == (0 as B_Choice), one as Uint<8>];
}`, facts => assert.deepEqual(returns(facts)[0].items!.map(value => value.constant), ["true", "true", "1"]));
});

for (const guarded of [false, true]) test(`transition policies preserve cross-import enum values (guarded=${guarded})`, () => {
  compare(`module A { export enum Phase { CLOSED, OPEN } }
module B { export enum Phase { CLOSED, OPEN } }
import A prefix A_; import B prefix B_;
export ledger phase: A_Phase;
export circuit entry(): [] {
  ${guarded ? 'assert(phase != B_Phase.CLOSED, "not closed");' : ''}
  phase = B_Phase.OPEN;
}`, facts => {
    const policies = resolvePolicies(facts.program, { transitions: [{ state: "phase", from: "Phase.CLOSED", to: "Phase.OPEN" }] });
    assert.equal(detectors.find(detector => detector.id === "forbidden-state-transition")!.run(facts, policies).length, guarded ? 0 : 1);
  });
});

test("constructed struct fields remain values rather than enum namespaces", () => {
  compare(`struct Pair { value: Field; }
export circuit entry(): Field { return Pair { value: 1 as Field }.value; }`, facts => {
    assert.equal(returns(facts)[0].constantKind, "integer");
    assert.equal(returns(facts)[0].constant, "1");
  });
});

test("projection from a constructed native struct retains private provenance", () => {
  compare(`import CompactStandardLibrary;
export circuit entry(value: Bytes<32>): Bytes<32> {
  return disclose(ContractAddress { bytes: value }.bytes);
}`, facts => {
    assert.equal(returns(facts)[0].flows[0].source.name, "value");
    assert.equal(returns(facts)[0].flows[0].form, "raw");
  });
});

const imported = `module M { export circuit check(): Field { return 1 as Field; } }`;
const rejected: [string, string, string][] = [
  ["imported/local equal signatures are ambiguous at the call", `${imported} import M; circuit check(): Field { return 2 as Field; } export circuit entry(): Field { return check(); }`, "overload-resolution"],
  ["declaration order does not disambiguate equal signatures", `${imported} circuit check(): Field { return 2 as Field; } import M; export circuit entry(): Field { return check(); }`, "overload-resolution"],
  ["export lists do not select one of two same-name functions", `${imported} import M; circuit check(): Field { return 2 as Field; } export {check};`, "overloaded-entrypoint"],
  ["Counter does not implicitly become Field", "import CompactStandardLibrary; export ledger counts: Map<Field,Counter>; export circuit entry(): Field { return counts.lookup(0 as Field); }", "return-type-mismatch"],
  ["Counter snapshots are ordinary values, not mutable storage", "import CompactStandardLibrary; export ledger counts: Map<Field,Counter>; export circuit entry(): [] { const saved = counts.lookup(0 as Field); saved.increment(1); }", "unsupported-state-operation"],
];
for (const [label, first, second] of [
  ["different struct names", "struct Value { field: Field; }", "struct Other { field: Field; }"],
  ["different field count", "struct Value { field: Field; }", "struct Value { field: Field; extra: Boolean; }"],
  ["different field order", "struct Value { first: Field; second: Boolean; }", "struct Value { second: Boolean; first: Field; }"],
  ["different field names", "struct Value { field: Field; }", "struct Value { other: Field; }"],
  ["different field types", "struct Value { field: Field; }", "struct Value { field: Boolean; }"],
] as const) rejected.push([label, `module A { export ${first} } module B { export ${second} } import A prefix A_; import B prefix B_; export circuit entry(value: A_Value): B_${label === "different struct names" ? "Other" : "Value"} { return value; }`, "return-type-mismatch"]);
rejected.push(["same-name nominal wrappers retain different representations", `module A { export new type Word = Field; } module B { export new type Word = Boolean; } import A prefix A_; import B prefix B_; export circuit entry(value: A_Word): B_Word { return value; }`, "nominal-type-mismatch"]);
for (const [name, declaration] of [["different enum names", "enum Other {zero, one}"], ["different enum order", "enum Choice {one, zero}"], ["different enum size", "enum Choice {zero, one, two}"]] as const) {
  rejected.push([name, `module A { export enum Choice {zero, one} } module B {export ${declaration}} import A prefix A_; import B prefix B_; export circuit entry(value: A_Choice): B_${name === "different enum names" ? "Other" : "Choice"} {return value;}`, "return-type-mismatch"]);
}

for (const [name, source, code] of rejected) test(name, () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, false);
    const result = scanFile(file);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code);
  });
});
