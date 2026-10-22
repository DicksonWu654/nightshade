import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, files: Record<string, string> = {}): void {
  withFiles({ ...files, "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(accepted.valid, true, accepted.error);
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
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    assert.ok([...program.symbols.values()].every(symbol => !symbol.overloads && !("functionGroups" in symbol)));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

function nested(outer: string, inner: string, expression: string, parameters = "value: Field", result = "Field", argumentsText = "value"): string {
  return `${outer} module Inner { ${inner} export circuit run(${parameters}): ${result} { return ${expression}; } } import { run } from Inner; export circuit entry(${parameters}): ${result} { return run(${argumentsText}); }`;
}

const outerIdentity = "circuit select(value: Field): Field { return value; }";
const innerBoolean = "circuit select(value: Boolean): Field { return 0 as Field; }";

test("incompatible inner singleton falls back without losing private provenance", () => {
  compare(nested(outerIdentity, innerBoolean, "select(value)"), facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "value");
    assert.equal(returned(facts)[0].flows[0].form, "raw");
    const run = [...facts.program.functions.values()].find(fn => fn.symbol.name === "run")!;
    const selected = facts.program.symbols.get([...run.calls][0])!;
    assert.equal(selected.declaration!.parameters[0].type, "Field");
    assert.equal(facts.program.findCallers(selected.id).some(fn => fn.symbol.id === run.symbol.id), true);
  });
});

test("nearest compatible scope wins rather than merging outer overloads", () => {
  compare(nested("circuit select(value: Uint<16>): Field { return 1 as Field; }", "circuit select(value: Uint<8>): Field { return 2 as Field; }", "select(0)", "", "Field", ""), facts => assert.equal(returned(facts)[0].constant, "2"));
});

test("a wider inner overload wins even when the outer overload is narrower", () => {
  compare(nested("circuit select(value: Uint<8>): Field { return 1 as Field; }", "circuit select(value: Uint<16>): Field { return 2 as Field; }", "select(0)", "", "Field", ""), facts => assert.equal(returned(facts)[0].constant, "2"));
});

test("outer overload accepts the wider argument rejected by the inner scope", () => {
  compare(nested("circuit select(value: Uint<16>): Field { return value as Field; }", "circuit select(value: Uint<8>): Field { return 0 as Field; }", "select(300 as Uint<16>)", "", "Field", ""), facts => assert.equal(returned(facts)[0].constant, "300"));
});

test("arity mismatch permits lexical fallback", () => {
  compare(nested("circuit select(first: Field, second: Field): Field { return first; }", outerIdentity, "select(value, 0 as Field)"), facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("generic kind mismatch permits lexical fallback", () => {
  compare(nested("circuit select<T>(value: T): T { return value; }", "circuit select<#N>(value: Vector<N, Field>): Field { return value[0]; }", "select<Field>(value)"), facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("generic count mismatch permits lexical fallback", () => {
  compare(nested("circuit select<T>(value: T): T { return value; }", outerIdentity, "select<Field>(value)"), facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("generic arguments resolve at the call site, not the candidate scope", () => {
  compare(nested("circuit select<T>(value: T): T { return value; }", "new type Token = Field; circuit select<#N>(value: Vector<N, Field>): Field { return value[0]; }", "select<Token>(value as Token) as Field"), facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("an incompatible inner overload group falls back to a singleton", () => {
  compare(nested(outerIdentity, `${innerBoolean} circuit select(value: Uint<8>): Field { return 1 as Field; }`, "select(value)"), facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("mapped references use lexical fallback and retain witness origins", () => {
  compare(nested("witness select(value: Field): Field;", innerBoolean, "disclose(map(select, [value])[0])"), facts => {
    const flow = returned(facts)[0].flows.find(flow => flow.source.kind === "witness")!;
    assert.equal(flow.form, "raw");
    assert.equal(readFileSync(flow.source.location.file).subarray(flow.source.location.start, flow.source.location.end).toString(), "select");
  });
});

test("fold result mismatch permits lexical fallback", () => {
  compare(nested("circuit select(total: Uint<16>, item: Uint<8>): Uint<16> { return (total + item) as Uint<16>; }", "circuit select(total: Uint<8>, item: Uint<8>): Boolean { return true; }", "fold(select, 0 as Uint<8>, [1 as Uint<8>, 2 as Uint<8>])", "", "Uint<16>", ""), facts => assert.equal(returned(facts)[0].constant, "3"));
});

test("inner witness shadows a compatible outer circuit", () => {
  compare(nested(outerIdentity, "witness select(value: Field): Field;", "disclose(select(value))"), facts => assert.equal(returned(facts)[0].flows.filter(flow => flow.source.kind === "witness").length, 1));
});

test("native functions participate in lexical generic fallback", () => {
  compare(nested("import CompactStandardLibrary;", "circuit persistentHash(value: Boolean): Bytes<32> { return default<Bytes<32>>; }", "disclose(persistentHash<Field>(value))", "value: Field", "Bytes<32>"), facts => assert.equal(returned(facts)[0].flows[0].form, "hash"));
});

test("inner imported native function takes priority over an outer circuit", () => {
  compare(nested("circuit persistentHash<T>(value: T): Bytes<32> { return default<Bytes<32>>; }", "import { persistentHash } from CompactStandardLibrary;", "disclose(persistentHash<Field>(value))", "value: Field", "Bytes<32>"), facts => assert.equal(returned(facts)[0].flows[0].form, "hash"));
});

test("native and user functions may overload in one scope", () => {
  compare("import { persistentHash } from CompactStandardLibrary; circuit persistentHash(value: Boolean): Bytes<32> { return default<Bytes<32>>; } export circuit entry(value: Field): [Bytes<32>, Bytes<32>] { return [disclose(persistentHash<Field>(value)), persistentHash(true)]; }", facts => {
    const items = returned(facts)[0].items!;
    assert.equal(items[0].flows[0].form, "hash");
    assert.equal(items[1].flows.length, 0);
  });
});

test("selected native aliases preserve signatures and mapped transformations", () => {
  compare("import { persistentHash as select } from CompactStandardLibrary prefix L_; circuit L_select(value: Boolean): Bytes<32> { return default<Bytes<32>>; } export circuit entry(value: Field): Bytes<32> { return disclose(map(L_select<Field>, [value])[0]); }", facts => assert.equal(returned(facts)[0].flows[0].form, "hash"));
});

test("native fold fallback checks the specialized result type", () => {
  compare(nested("import { transientCommit as select } from CompactStandardLibrary;", "circuit select<T>(total: T, item: Field): Boolean { return true; }", "fold(select<Field>, value, [0 as Field])"), facts => assert.equal(returned(facts)[0].flows[0].form, "commitment"));
});

test("repeated imports deduplicate the same callable identity", () => {
  compare("module Library { export circuit select(value: Field): Field { return value; } export circuit select(value: Boolean): Field { return 0 as Field; } } import Library; import Library; export circuit entry(value: Field): Field { return select(value); }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("a function exported into an ancestor remains one canonical symbol", () => {
  compare("circuit select(value: Boolean): Field { return 0 as Field; } module Library { export circuit select(value: Field): Field { return value; } export circuit run(value: Field): Field { return select(value); } } import Library; export circuit entry(value: Field): Field { return run(value); }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("selected prefixed circuit imports form their own lexical group", () => {
  compare("module Library { export circuit select(value: Boolean): Field { return 0 as Field; } } circuit L_select(value: Field): Field { return value; } module Inner { import { select } from Library prefix L_; export circuit run(value: Field): Field { return L_select(value); } } import { run } from Inner; export circuit entry(value: Field): Field { return run(value); }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"));
});

test("a non-callable scope barrier does not hide compatible inner functions", () => {
  compare("circuit select(value: Field): Field { return value; } module Barrier { type select = Field; module Inner { circuit select(value: Boolean): Field { return 7 as Field; } export circuit run(): Field { return select(true); } } import { run } from Inner; export { run }; } import { run } from Barrier; export circuit entry(): Field { return run(); }", facts => assert.equal(returned(facts)[0].constant, "7"));
});

test("external module functions use their definition scope rather than the importer", () => {
  compare("import Library; circuit select(value: Uint<8>): Field { return 0 as Field; } export circuit entry(value: Field): Field { return run(value); }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "value"), {
    "Library.compact": "module Library { circuit select(value: Field): Field { return value; } module Inner { circuit select(value: Boolean): Field { return 0 as Field; } export circuit run(value: Field): Field { return select(value); } } import { run } from Inner; export { run }; }",
  });
});

test("resolved outer mutation updates state, call graph and published provenance", () => {
  compare("export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } module Inner { circuit put(value: Boolean): [] {} export circuit run(value: Field): [] { put(value); } } import { run } from Inner; export circuit entry(value: Field): [] { run(value); }", facts => {
    assert.equal(facts.paths[0].writes[0].after.flows[0].source.name, "value");
    const state = [...facts.program.symbols.values()].find(symbol => symbol.kind === "ledger")!;
    assert.equal(facts.program.findStateWriters(state.id).some(fn => fn.symbol.id === facts.program.entries[0]), true);
  });
});

test("lexical fallback preserves ledger-bound preimage detector evidence", () => {
  compare('import CompactStandardLibrary; witness secret(): Field; export ledger digest: Bytes<32>; circuit check(value: Field): Field { assert(persistentHash<Field>(value) == digest, "bound"); return value; } module Inner { circuit check(value: Boolean): Field { return 0 as Field; } export circuit run(): Field { return disclose(check(secret())); } } import { run } from Inner; export circuit entry(): Field { return run(); }', facts => {
    assert.equal(detectors.find(detector => detector.id === "ledger-bound-preimage-publication")!.run(facts).length, 1);
  });
});

test("resolved guard identity retains authorization on an outer fallback", () => {
  compare('export ledger allowed: Boolean; export ledger stored: Field; circuit guard(value: Field): [] { assert(allowed, "allowed"); } module Inner { circuit guard(value: Boolean): [] {} export circuit run(value: Field): [] { guard(value); stored = disclose(value); } } import { run } from Inner; export circuit entry(value: Field): [] { run(value); }', facts => {
    const guard = [...facts.program.functions.values()].find(fn => fn.symbol.name === "guard" && fn.declaration.parameters[0].type === "Field")!;
    const policies = resolvePolicies(facts.program, { authorization: [{ state: "stored", guard: guard.symbol.id }] });
    assert.equal(detectors.find(detector => detector.id === "unguarded-sensitive-state-write")!.run(facts, policies).length, 0);
  });
});

const rejected = [
  ["ambiguous inner scope does not fall through", nested("circuit select(value: Uint<32>): Field { return 1 as Field; }", "circuit select(value: Uint<8>): Field { return 2 as Field; } circuit select(value: Uint<16>): Field { return 3 as Field; }", "select(0)", "", "Field", ""), "overload-resolution"],
  ["ambiguous outer scope remains ambiguous", nested("circuit select(value: Uint<8>): Field { return 1 as Field; } circuit select(value: Uint<16>): Field { return 2 as Field; }", innerBoolean, "select(0)", "", "Field", ""), "overload-resolution"],
  ["mapped ambiguity does not fall through", nested("circuit select(value: Uint<32>): Field { return 1 as Field; }", "circuit select(value: Uint<8>): Field { return 2 as Field; } circuit select(value: Uint<16>): Field { return 3 as Field; }", "map(select, [0])[0]", "", "Field", ""), "overload-resolution"],
  ["type binding blocks outer callable lookup", "circuit select(value: Field): Field { return value; } module Barrier { type select = Field; module Inner { circuit select(value: Boolean): Field { return 0 as Field; } export circuit run(value: Field): Field { return select(value); } } import { run } from Inner; export { run }; } import { run } from Barrier; export circuit entry(value: Field): Field { return run(value); }", "call-type-mismatch"],
  ["parameter binding blocks callable lookup", `${outerIdentity} export circuit entry(select: Field): Field { return select(0 as Field); }`, "invalid-call"],
  ["local binding blocks callable lookup", `${outerIdentity} export circuit entry(): Field { const select = 0 as Field; return select(0 as Field); }`, "invalid-call"],
  ["later block-local binding blocks callable lookup", `${outerIdentity} export circuit entry(): Field { const value = select(0 as Field); const select = 0 as Field; return value; }`, "use-before-binding"],
  ["no compatible scope is not a clean scan", nested(outerIdentity, innerBoolean, "select(default<Bytes<32>>)", "", "Field", ""), "overload-resolution"],
  ["singleton calls enforce argument subtyping", `${outerIdentity} export circuit entry(): Field { return select(0); }`, "call-type-mismatch"],
  ["native singleton calls enforce argument subtyping", "import CompactStandardLibrary; export circuit entry(): Bytes<32> { return persistentHash<Field>(0); }", "call-type-mismatch"],
  ["native singleton calls require generics", "import CompactStandardLibrary; export circuit entry(value: Field): Bytes<32> { return disclose(persistentHash(value)); }", "generic-arity"],
  ["distinct same-signature native and user bindings are ambiguous at a call", "import { persistentHash } from CompactStandardLibrary; circuit persistentHash<T>(value: T): Bytes<32> { return default<Bytes<32>>; } export circuit entry(value: Field): Bytes<32> { return disclose(persistentHash<Field>(value)); }", "overload-resolution"],
] as const;

for (const [name, source, code] of rejected) test(name, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const rejected = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(rejected.valid, false, name);
      assert.match(rejected.error!, /Exception:/);
    }
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code);
    assert.deepEqual(result.findings, []);
  });
});
