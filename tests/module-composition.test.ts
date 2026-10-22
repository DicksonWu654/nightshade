import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { AnalysisFacts, Dataflow, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

interface Composition {
  files?: Record<string, string>;
  links?: Record<string, string>;
  storage?: [string, string, boolean][];
}

function compare(source: string, check: (facts: AnalysisFacts) => void, options: Composition = {}): void {
  withFiles({ ...options.files, "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    for (const [name, target] of Object.entries(options.links ?? {})) symlinkSync(resolve(directory, target), resolve(directory, name), "dir");
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = process.env.COMPACTC_TEST;
      assert.equal(spawnSync(compiler, ["--version"], { encoding: "utf8", timeout: 30000 }).stdout.trim(), "0.34.0");
      assert.equal(spawnSync(compiler, ["--language-version"], { encoding: "utf8", timeout: 30000 }).stdout.trim(), "0.26.0");
      const output = resolve(directory, "output");
      const compiled = spawnSync(compiler, ["--skip-zk", path, output], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
      assert.equal(compiled.status, 0, String(compiled.error ?? compiled.stderr));
      const generated = readFileSync(resolve(output, "contract/index.js"), "utf8");
      for (const [first, second, same] of options.storage ?? []) {
        const index = (name: string) => new RegExp(`get ${name}\\(\\)[\\s\\S]*?\\.toValue\\((\\d+)n\\)`).exec(generated)?.[1];
        assert.notEqual(index(first), undefined, `Missing compiler ledger getter ${first}`);
        assert.notEqual(index(second), undefined, `Missing compiler ledger getter ${second}`);
        assert.equal(index(first) === index(second), same, `${first}/${second} compiler storage identity`);
      }
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
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

const storeBody = "export ledger value: Field; export circuit put(input: Field): [] { value = disclose(input); }";
const store = `module Store { ${storeBody} }`;
const entry = "export { First_value, Second_value }; export circuit entry(secret: Field): Field { First_put(secret); return Second_value; }";
const shared: Composition = { storage: [["First_value", "Second_value", true]] };
const separate: Composition = { storage: [["First_value", "Second_value", false]] };
const privateReturn = (facts: AnalysisFacts): void => assert.equal(returned(facts)[0].flows[0].source.name, "secret");

test("diamond imports share one ledger declaration and preserve private-derived writes", () => {
  compare(`${store} module Left { import Store; export { value, put }; } module Right { import Store; export { value, put }; } import Left prefix First_; import Right prefix Second_; ${entry}`, facts => {
    privateReturn(facts);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "put").length, 1);
  }, shared);
});

test("direct and transitive imports resolve to one state instance", () => {
  compare(`${store} module Wrapper { import Store; export { value, put }; } import Wrapper prefix First_; import Store prefix Second_; ${entry}`, privateReturn, shared);
});

test("distinct wrapper specializations still share the same external dependency", () => {
  compare(`module Wrapper<#N> { import Store; export { value, put }; } import Wrapper<1> prefix First_; import Wrapper<2> prefix Second_; ${entry}`, privateReturn, { ...shared, files: { "Store.compact": store } });
});

test("repeated exported-module aliases preserve nested declaration identity", () => {
  compare(`module Container<#N> { export module Store { ${storeBody} } } import Container<1> prefix C1_; import Container<1> prefix C2_; import C1_Store prefix First_; import C2_Store prefix Second_; ${entry}`, privateReturn, shared);
});

test("different enclosing specializations create distinct nested module declarations", () => {
  compare(`module Container<#N> { export module Store { ${storeBody} } } import Container<1> prefix C1_; import Container<2> prefix C2_; import C1_Store prefix First_; import C2_Store prefix Second_; ${entry}`, facts => {
    assert.equal(returned(facts)[0].flows.length, 0);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 2);
  }, separate);
});

test("nested generic modules capture outer arguments without replacing inner generics", () => {
  compare("module Container<T> { export module Store<U> { export ledger value: T; export circuit put(input: T, ignored: U): [] { value = disclose(input); } } } import Container<Field>; import Store<Boolean> prefix First_; import Store<Boolean> prefix Second_; export { First_value, Second_value }; export circuit entry(secret: Field): Field { First_put(secret, false); return Second_value; }", privateReturn, shared);
});

test("selected renamed prefixed nested modules can be reexported and imported", () => {
  compare(`module Container { export module Middle { export module Store { ${storeBody} } } } module Bridge { import { Middle as Sub } from Container prefix L_; import { Store as State } from L_Sub; export { State }; } import { State as Alias } from Bridge; import Alias prefix First_; import Alias prefix Second_; ${entry}`, privateReturn, shared);
});

test("module exports may forward an enclosing ledger and callable binding", () => {
  compare(`export ledger value: Field; circuit put(input: Field): [] { value = disclose(input); } module Bridge { export { value, put }; } import Bridge prefix First_; import Bridge prefix Second_; ${entry}`, privateReturn, shared);
});

for (const [name, first, second, equal, definitions] of [
  ["equivalent Uint bounds", "Uint<8>", "Uint<0..256>", true, ""],
  ["different Uint bounds", "Uint<8>", "Uint<16>", false, ""],
  ["tuple and vector equivalence", "[Field, Field]", "Vector<2, Field>", true, ""],
  ["equivalent nested sequence element bounds", "Vector<2, Uint<8>>", "[Uint<0..256>, Uint<8>]", true, ""],
  ["phantom struct generic equivalence", "Box<Field>", "Box<Boolean>", true, "struct Box<T> { value: Field; }"],
  ["distinct struct generic fields", "Box<Field>", "Box<Boolean>", false, "struct Box<T> { value: T; }"],
  ["same nominal through an alias", "Token", "Alias", true, "new type Token = Field; type Alias = Token;"],
  ["distinct nominal declarations", "First", "Second", false, "new type First = Field; new type Second = Field;"],
  ["phantom nominal generic equivalence", "Token<Field>", "Token<Boolean>", true, "new type Token<T> = Field;"],
  ["typed empty-vector identity", "Vector<0, Field>", "Vector<0, Boolean>", false, ""],
] as const) test(`module instance arguments use ${name}`, () => {
  compare(`${definitions} module Store<T> { ${storeBody} } import Store<${first}> prefix First_; import Store<${second}> prefix Second_; ${entry}`, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, equal ? 1 : 2);
    if (equal) privateReturn(facts);
    else assert.equal(returned(facts)[0].flows.length, 0);
  }, equal ? shared : separate);
});

test("repeated full imports deduplicate ledgers, types, modules and functions", () => {
  compare(`module Store { ${storeBody} export new type Token = Field; export module Inner { export circuit identity(value: Token): Token { return value; } } } import Store; import Store; import Inner; export circuit entry(secret: Token): Field { put(identity(secret) as Field); return value; }`, facts => {
    privateReturn(facts);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
  });
});

test("repeated standard-library imports reuse type and native identities", () => {
  compare("import CompactStandardLibrary; import CompactStandardLibrary; export circuit entry(secret: Field): Field { return some<Field>(secret).value; }", privateReturn);
});

test("physical modules with equal basenames retain distinct state", () => {
  compare(`import "first/Store" prefix First_; import "second/Store" prefix Second_; ${entry}`, facts => assert.equal(returned(facts)[0].flows.length, 0), { ...separate, files: { "first/Store.compact": store, "second/Store.compact": store } });
});

test("different path spellings retain distinct module identities with one parsed source", () => {
  compare(`import "Store" prefix First_; import "./Store" prefix Second_; ${entry}`, facts => {
    assert.equal(returned(facts)[0].flows.length, 0);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 2);
    assert.equal(facts.program.files.size, 2);
  }, { ...separate, files: { "Store.compact": store } });
});

test("imports in included text use the enclosing compilation-unit directory", () => {
  compare(`include "parts/imports"; import Store prefix Second_; ${entry}`, privateReturn, { ...shared, files: { "Store.compact": store, "parts/Store.compact": store, "parts/imports.compact": "import Store prefix First_;" } });
});

test("exported local modules resolve their imports in the first importing context", () => {
  compare(`import { Inner } from "library/Container"; import Inner prefix First_; import Store prefix Second_; ${entry}`, privateReturn, { ...shared, files: { "Store.compact": store, "library/Store.compact": store, "library/Container.compact": "module Container { export module Inner { import Store; export { value, put }; } }" } });
});

test("nested physical module dependencies retain their defining file directory", () => {
  compare(`import "library/Wrapper" prefix First_; import "library/Store" prefix Second_; ${entry}`, privateReturn, { ...shared, files: { "Store.compact": store, "library/Store.compact": store, "library/Wrapper.compact": "module Wrapper { import Store; export { value, put }; }" } });
});

test("symlinked module paths keep compiler identities separate from physical parsing", () => {
  compare(`import "Store" prefix First_; import "alias/Store" prefix Second_; ${entry}`, facts => {
    assert.equal(returned(facts)[0].flows.length, 0);
    assert.equal(facts.program.files.size, 2);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 2);
  }, { ...separate, files: { "Store.compact": store }, links: { alias: "." } });
});

test("nested imports retain the symlinked directory used by the compiler", () => {
  compare(`import "Wrapper" prefix First_; import "alias/Wrapper" prefix Second_; ${entry}`, facts => {
    assert.equal(returned(facts)[0].flows.length, 0);
    assert.equal(facts.program.files.size, 3);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 2);
  }, { ...separate, files: { "Store.compact": store, "Wrapper.compact": "module Wrapper { import Store; export { value, put }; }" }, links: { alias: "." } });
});

test("repeated include spans cannot collide across distinct module instantiations", () => {
  compare(`include "load"; ${store} include "load"; import "Store" prefix First_; import Store prefix Second_; ${entry}`, facts => {
    assert.equal(returned(facts)[0].flows.length, 0);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 2);
  }, { ...separate, files: { "Store.compact": store, "load.compact": "import {} from Store;" } });
});

test("a later enclosing module is not visible during an earlier transitive import", () => {
  compare("module Consumer { import Store; export circuit get(): Field { return answer(); } } import Consumer; module Store { export circuit answer(): Field { return 1 as Field; } } export circuit entry(): Field { return get(); }", facts => {
    assert.equal(returned(facts)[0].constant, "7");
    assert.ok([...facts.program.functions.values()].find(fn => fn.symbol.name === "answer")!.symbol.span.file.endsWith("Store.compact"));
  }, { files: { "Store.compact": "module Store { export circuit answer(): Field { return 7 as Field; } }" } });
});

test("cached imports retain their initial module resolution after later definitions", () => {
  compare("module Consumer { import Store; export circuit get(): Field { return answer(); } } import Consumer prefix First_; module Store { export circuit answer(): Field { return 1 as Field; } } import Consumer prefix Second_; import Store; export circuit entry(): [Field, Field, Field] { return [First_get(), Second_get(), answer()]; }", facts => assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["7", "7", "1"]), { files: { "Store.compact": "module Store { export circuit answer(): Field { return 7 as Field; } }" } });
});

test("an already visible module is used instead of the same-named physical file", () => {
  compare("module Consumer { import Store; export circuit get(): Field { return answer(); } } module Store { export circuit answer(): Field { return 1 as Field; } } import Consumer; export circuit entry(): Field { return get(); }", facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(facts.program.files.size, 1);
  }, { files: { "Store.compact": "module Store { export circuit answer(): Field { return 7 as Field; } }" } });
});

test("a local module can shadow the standard-library module name", () => {
  compare("module CompactStandardLibrary { export circuit answer(): Field { return 7 as Field; } } import CompactStandardLibrary; export circuit entry(): Field { return answer(); }", facts => {
    assert.equal(returned(facts)[0].constant, "7");
    assert.equal([...facts.program.symbols.values()].some(symbol => symbol.kind === "intrinsic"), false);
  });
});

test("quoted standard-library names refer to physical modules, not builtins", () => {
  compare('import "CompactStandardLibrary"; export circuit entry(): Field { return answer(); }', facts => assert.equal(returned(facts)[0].constant, "7"), { files: { "CompactStandardLibrary.compact": "module CompactStandardLibrary { export circuit answer(): Field { return 7 as Field; } }" } });
});

test("writing a shared imported predicate invalidates a prior guard", () => {
  compare('module Store { export ledger allowed: Boolean; export circuit guard(): [] { assert(allowed, "allowed"); } export circuit revoke(): [] { allowed = false; } } module Wrapper { import Store; export { revoke }; } import Store; import Wrapper prefix Wrapped_; export ledger stored: Field; export circuit entry(): [] { guard(); Wrapped_revoke(); stored = 1 as Field; }', facts => {
    const policies = resolvePolicies(facts.program, { authorization: [{ state: "stored", guard: "guard" }] });
    assert.equal(detectors.find(detector => detector.id === "unguarded-sensitive-state-write")!.run(facts, policies).length, 1);
  });
});

test("transitive aliases preserve ledger-bound preimage detector evidence", () => {
  compare('import CompactStandardLibrary; witness secret(): Field; module Store { export ledger digest: Bytes<32>; export circuit check(value: Field): Field { assert(persistentHash<Field>(value) == digest, "bound"); return value; } } module Wrapper { import Store; export { check }; } import Store prefix Direct_; import Wrapper; export circuit entry(): Field { return disclose(check(secret())); }', facts => assert.equal(detectors.find(detector => detector.id === "ledger-bound-preimage-publication")!.run(facts).length, 1));
});

const rejected: [string, string, string, Record<string, string>?][] = [
  ["prior type bindings block filesystem import lookup", "type Store = Field; import Store; export circuit entry(): [] {}", "invalid-import", { "Store.compact": store }],
  ["prior types can block the standard-library name", "type CompactStandardLibrary = Field; import CompactStandardLibrary; export circuit entry(): [] {}", "invalid-import"],
  ["private nested modules cannot be selectively imported", "module Container { module Inner {} } import { Inner } from Container; export circuit entry(): [] {}", "missing-export"],
  ["physical imports require the expected module name", 'import "Store"; export circuit entry(): [] {}', "invalid-module-file", { "Store.compact": "module Wrong {}" }],
  ["extra physical-file declarations are not an enclosing environment", 'import "Store"; export circuit entry(): Field { return get(); }', "invalid-module-file", { "Store.compact": "circuit hidden(): Field { return 0 as Field; } module Store { export circuit get(): Field { return hidden(); } }" }],
  ["physical files cannot import modules outside their single definition", 'import "Store"; export circuit entry(): [] {}', "invalid-module-file", { "Store.compact": "import CompactStandardLibrary; module Store {}" }],
  ["a physical module definition has no enclosing self-name binding", 'import "Store"; export circuit entry(): [] {}', "missing-export", { "Store.compact": "module Store { export { Store }; }" }],
  ["distinct ledger bindings still collide under one imported name", `module First { ${storeBody} } module Second { ${storeBody} } import First; import Second; export circuit entry(): [] {}`, "duplicate-symbol"],
  ["distinct module bindings still collide under one imported name", "module First { export module Inner {} } module Second { export module Inner {} } import First; import Second; export circuit entry(): [] {}", "duplicate-symbol"],
  ["cycles through a selected exported module stay incomplete", "module Outer { export module Inner { import Outer; import Inner; } } import Outer; import Inner; export circuit entry(): [] {}", "import-cycle"],
];

for (const [name, source, code, files] of rejected) test(name, () => {
  withFiles({ ...files, "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
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
