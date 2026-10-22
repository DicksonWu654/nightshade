import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Program, scanFile } from "../src/index.js";
import { analyze, withFiles } from "./helpers.js";

test("type and natural module arguments specialize loops and circuit parameters", () => {
  analyze("module M<T, #N> { export circuit pass(value: T): T { for (const index of 0..N) { assert(true, \"ok\"); } return value; } } import M<Field, 2>; export circuit entry(value: Field): Field { return pass(value); }", facts => {
    assert.equal(facts.paths[0].sinks[0].value.flows[0].form, "raw");
    assert.equal(facts.paths[0].path.filter(step => step.kind === "constraint").length, 2);
  });
});

test("generic circuits specialize independently and cache repeated signatures", () => {
  analyze("circuit pass<T>(value: T): T { return value; } export circuit entry(secret: Field): Field { const clean = pass<Boolean>(false); const first = pass<Field>(secret); return clean ? 0 as Field : pass<Field>(first); }", facts => {
    assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret");
    assert.equal([...facts.program.functions.values()].filter(fn => fn.symbol.name === "pass").length, 2);
  });
});

test("generic parameter shadowing does not use the module argument", () => {
  analyze("module M<T> { export circuit pass<T>(value: T): T { return value; } } import M<Boolean>; export circuit entry(secret: Field): Field { return pass<Field>(secret); }", facts => assert.equal(facts.paths[0].sinks[0].value.type, "Field"));
});

test("different module specializations have distinct state symbols", () => {
  analyze("module Store<#N> { export ledger value: Field; export circuit put(input: Field): [] { value = disclose(input); } } import Store<1> prefix A_; import Store<2> prefix B_; export circuit entry(secret: Field): Field { A_put(secret); B_put(0 as Field); return B_value; }", facts => {
    assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.flows.length, 0);
    const writes = [...facts.program.functions.values()].find(fn => fn.symbol.name === "entry")!.writesState;
    assert.equal(writes.size, 2);
  });
});

test("independent struct instantiations retain their own field layout", () => {
  analyze("module M<T> { export struct Box { value: T; } export witness box(): Box; } import M<Field> prefix A_; import M<Boolean> prefix B_; export circuit entry(): Field { const value = A_box(); return value.value; }", facts => assert.equal(facts.paths[0].sinks[0].value.type, "Field"));
});

test("structural aliases resolve before aggregate provenance", () => {
  analyze("type Values<T> = Vector<2, T>; export circuit entry(secret: Values<Field>): Field { return secret[1]; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows.length, 1));
});

test("includes preserve definition locations and lexical visibility", () => {
  withFiles({
    "main.compact": 'include "parts/entry";',
    "parts/entry.compact": 'include "helper"; export circuit entry(value: Field): Field { return pass(value); }',
    "parts/helper.compact": "circuit pass(value: Field): Field { return value; }",
  }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(program.files.size, 3);
    assert.equal(program.sources.inclusions.length, 2);
    assert.ok([...program.functions.values()].find(fn => fn.symbol.name === "pass")!.symbol.span.file.endsWith("helper.compact"));
    assert.equal(scanFile(resolve(directory, "main.compact")).status, "complete");
  });
});

test("include and module cycles fail with dedicated diagnostics", () => {
  withFiles({ "main.compact": 'include "other";', "other.compact": 'include "main";' }, directory => assert.equal(scanFile(resolve(directory, "main.compact")).diagnostics[0].code, "include-cycle"));
  withFiles({ "main.compact": 'import "Loop";', "Loop.compact": 'module Loop { import "Loop"; }' }, directory => assert.equal(scanFile(resolve(directory, "main.compact")).diagnostics[0].code, "import-cycle"));
});

test("repeated filesystem imports parse each physical source once", () => {
  withFiles({ "main.compact": 'import "Helper" prefix A_; import "Helper" prefix B_; export circuit entry(): Field { return A_pass(1 as Field) + B_pass(2 as Field); }', "Helper.compact": "module Helper { export circuit pass(value: Field): Field { return value; } }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(program.files.size, 2);
    assert.equal([...program.functions.values()].filter(fn => fn.symbol.name === "pass").length, 1);
    assert.equal(program.files.get(resolve(directory, "Helper.compact"))!.ast.declarations[0].scope!.declarations[0].parameters[0].symbol, undefined);
  });
});

test("local modules can reference lexically enclosing contract bindings", () => {
  analyze("export ledger value: Field; module M { export circuit get(): Field { return value; } } import M; export { get };", facts => assert.equal(facts.program.entries.length, 1));
});

test("module templates are not application entrypoints", () => {
  analyze("module M<T> { export circuit pass(value: T): T { return value; } }", facts => assert.equal(facts.program.entries.length, 0));
});

test("nominal identity is distinct from its primitive representation", () => {
  analyze("new type Value = Field; export circuit entry(value: Value): Value { return value; }", facts => {
    const type = facts.program.functions.get(facts.program.entries[0])!.symbol.type;
    assert.notEqual(type, "Field");
    assert.equal(facts.program.representationOf(type), "Field");
    assert.equal(facts.paths[0].sinks[0].value.flows[0].form, "raw");
  });
});

test("unused imported circuit effects do not block a supported application", () => {
  analyze("module Library { export circuit identity(value: Field): Field { return value; } export circuit unsupported(): [] { unknownEffect(); } } import Library; export circuit entry(value: Field): Field { return identity(value); }", facts => {
    assert.equal(facts.program.functions.size, 2);
    assert.equal(facts.completedEntries.length, 1);
  });
});

test("local shadowing begins at block entry, not at the initializer", () => {
  for (const body of ["{ const copy = value; const value = 0; }", "{ const value = value; }", "{ const [value, value] = [0, 1]; }"]) withFiles({ "main.compact": `export circuit entry(value: Field): [] { ${body} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.ok(["use-before-binding", "duplicate-symbol"].includes(result.diagnostics[0].code));
  });
});

test("repeated imports of the same module specialization share state and calls", () => {
  analyze("module Store { export ledger value: Field; export circuit put(input: Field): [] { value = disclose(input); } } import Store prefix A_; import Store prefix B_; export circuit entry(secret: Field): Field { A_put(secret); return B_value; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!;
    assert.equal(returned.value.flows[0].source.name, "secret");
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
  });
});

test("structural type aliases do not create distinct module state instances", () => {
  analyze("type Alias = Field; module Store<T> { export ledger value: T; export circuit put(input: T): [] { value = disclose(input); } } import Store<Field> prefix A_; import Store<Alias> prefix B_; export circuit entry(secret: Field): Field { A_put(secret); return B_value; }", facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.flows[0].source.name, "secret");
  });
});
