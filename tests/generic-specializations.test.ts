import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { AnalysisFacts, Dataflow, Policies, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, methods: Record<string, number>, check: (facts: AnalysisFacts) => void, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = process.env.COMPACTC_TEST;
      assert.equal(spawnSync(compiler, ["--version"], { encoding: "utf8", timeout: 30000 }).stdout.trim(), "0.34.0");
      assert.equal(spawnSync(compiler, ["--language-version"], { encoding: "utf8", timeout: 30000 }).stdout.trim(), "0.26.0");
      const output = resolve(directory, "output");
      const compiled = spawnSync(compiler, ["--skip-zk", path, output], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
      assert.equal(compiled.status, 0, String(compiled.error ?? compiled.stderr));
      const generated = readFileSync(resolve(output, "contract/index.js"), "utf8");
      for (const [name, count] of Object.entries(methods)) assert.equal([...generated.matchAll(new RegExp(`^  (?:async )?_${name}_\\d+\\(`, "gm"))].length, count, `${name} compiler specialization count`);
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
    const configured = resolvePolicies(program, policies);
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(expanded));
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

for (const [name, first, second, equal, definitions] of [
  ["equivalent Uint bounds", "Uint<8>", "Uint<0..256>", true, ""],
  ["spaced radix bounds", "Uint<0o10>", "Uint<0 .. 0X100>", true, ""],
  ["distinct Uint bounds", "Uint<8>", "Uint<16>", false, ""],
  ["tuple and vector equivalence", "[Field, Field]", "Vector<2, Field>", true, ""],
  ["nested equivalent sequence bounds", "Vector<2, Uint<8>>", "[Uint<0..256>, Uint<8>]", true, ""],
  ["phantom struct equivalence", "Box<Field>", "Box<Boolean>", true, "struct Box<T> { value: Field; }"],
  ["distinct struct fields", "Box<Field>", "Box<Boolean>", false, "struct Box<T> { value: T; }"],
  ["nominal aliases", "Token", "Alias", true, "new type Token = Field; type Alias = Token;"],
  ["distinct nominal declarations", "First", "Second", false, "new type First = Field; new type Second = Field;"],
  ["phantom nominal equivalence", "Token<Field>", "Token<Boolean>", true, "new type Token<T> = Field;"],
  ["typed empty-vector identity", "Vector<0, Field>", "Vector<0, Boolean>", false, ""],
] as const) {
  for (const witness of [false, true]) test(`${witness ? "witness" : "circuit"} specializations use ${name}`, () => {
    compare(`${definitions} ${witness ? "witness" : "circuit"} identity<T>(value: T): T ${witness ? ";" : "{ return value; }"} export circuit entry(): [${first}, ${second}] { return disclose([identity<${first}>(default<${first}>), identity<${second}>(default<${second}>)]); }`, { identity: equal ? 1 : 2 }, facts => {
      const symbols = facts.program.activeSymbols().filter(symbol => symbol.name === "identity");
      assert.equal(symbols.length, equal ? 1 : 2);
      assert.equal(facts.program.functions.get(facts.program.entries[0])!.calls.size, equal ? 1 : 2);
    });
  });
}

for (const number of ["0x8", "0X8", "0o10", "0O10", "0b1000", "0B1000"]) test(`natural argument ${number} shares decimal circuit and witness identities`, () => {
  compare(`circuit identity<#N>(value: Uint<N>): Uint<N> { return value; } witness fetch<#N>(value: Uint<N>): Field; export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>, Field, Field] { return disclose([identity<8>(secret), identity<${number}>(secret), fetch<8>(secret), fetch<${number}>(secret)]); }`, { identity: 1, fetch: 1 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "identity").length, 1);
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "fetch").length, 1);
    assert.ok(returned(facts)[0].items!.slice(0, 2).every(item => item.flows[0].source.name === "secret"));
  });
});

test("equivalent generic ordinary and mapped calls reuse pure summaries", () => {
  compare("circuit identity<T>(value: T): T { return value; } export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>] { return [identity<Uint<8>>(secret), map(identity<Uint<0..256>>, [secret])[0]]; }", { identity: 1 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "identity").length, 1);
    assert.ok(facts.metrics.summaryHits > 0);
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].source.name === "secret"));
  });
});

test("distinct natural arguments retain separate specializations and values", () => {
  compare("circuit size<#N>(): Field { return N as Field; } export circuit entry(): [Field, Field] { return [size<0X1>(), size<0B10>()]; }", { size: 2 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "size").length, 2);
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "2"]);
  });
});

test("mixed type and natural arguments compare each position independently", () => {
  compare("circuit identity<T, #N>(value: Vector<N, T>): Vector<N, T> { return value; } export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>, Uint<8>] { return [identity<Uint<8>, 1>([secret])[0], identity<Uint<0..256>, 0X1>([secret])[0], identity<Uint<0..256>, 2>([secret, secret])[0]]; }", { identity: 2 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "identity").length, 2);
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].source.name === "secret"));
  });
});

test("equivalent generic ordinary and folded calls share canonical callees", () => {
  compare("circuit select<T>(total: T, value: T): T { return value; } export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>] { return [select<Uint<8>>(default<Uint<8>>, secret), fold(select<Uint<0..256>>, default<Uint<8>>, [secret])]; }", { select: 1 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "select").length, 1);
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].source.name === "secret"));
  });
});

test("selected prefixed aliases reuse their generic declaration specialization", () => {
  compare("module Helpers { export circuit identity<T>(value: T): T { return value; } } import { identity as pass } from Helpers prefix First_; import Helpers prefix Second_; export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>] { return [First_pass<Uint<8>>(secret), Second_identity<Uint<0..256>>(secret)]; }", { identity: 1 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "identity").length, 1);
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].source.name === "secret"));
  });
});

test("distinct enclosing instances retain distinct generic call declarations", () => {
  compare("module Helpers<#N> { export circuit identity<T>(value: T): T { return value; } } import Helpers<1> prefix First_; import Helpers<2> prefix Second_; export circuit entry(secret: Uint<8>): [Uint<8>, Uint<8>] { return [First_identity<Uint<8>>(secret), Second_identity<Uint<0..256>>(secret)]; }", { identity: 2 }, facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.name === "identity").length, 2);
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].source.name === "secret"));
  });
});

test("equivalent witness declarations retain fresh invocation identities and exact spans", () => {
  const policies: Policies = { secrets: [{ witness: "fetch" }] };
  compare("witness fetch<T>(value: T): Field; export circuit entry(secret: Uint<8>): [Field, Field] { return disclose([/* Ω🚀 */ fetch<Uint<8>>(secret), fetch<Uint<0..256>>(secret)]); }", { fetch: 1 }, facts => {
    const witnesses = returned(facts)[0].items!.map(item => item.flows.find(flow => flow.source.kind === "witness")!);
    assert.equal(witnesses[0].source.symbol, witnesses[1].source.symbol);
    assert.notEqual(witnesses[0].source.id, witnesses[1].source.id);
    assert.deepEqual(witnesses.map(flow => {
      const location = flow.source.location;
      const source = readFileSync(location.file);
      assert.equal(location.column, source.subarray(0, location.start).toString().length + 1);
      return source.subarray(location.start, location.end).toString();
    }), ["fetch<Uint<8>>(secret)", "fetch<Uint<0..256>>(secret)"]);
    const resolved = resolvePolicies(facts.program, policies);
    assert.equal(resolved.secrets[0].symbol, witnesses[0].source.symbol);
    assert.equal(detectors.find(detector => detector.id === "declared-secret-publication")!.run(facts, resolved).length, 2);
  }, policies);
});

test("equivalent generic guards satisfy named authorization policies on both entrypoints", () => {
  const policies = { authorization: [{ state: "stored", guard: "guard" }] };
  compare('export ledger allowed: Boolean; export ledger stored: Field; circuit guard<T>(): [] { assert(allowed, "allowed"); } export circuit first(): [] { guard<Uint<8>>(); stored = 1 as Field; } export circuit second(): [] { guard<Uint<0..256>>(); stored = 2 as Field; }', { guard: 1 }, facts => {
    const resolved = resolvePolicies(facts.program, policies);
    assert.equal(facts.program.findCallers(resolved.authorization[0].guard).length, 2);
    assert.ok(facts.paths.every(path => path.writes[0].guards.includes(resolved.authorization[0].guard)));
    assert.equal(detectors.find(detector => detector.id === "unguarded-sensitive-state-write")!.run(facts, resolved).length, 0);
  }, policies);
});

test("equivalent stateful generic calls replay against current storage", () => {
  compare("export ledger stored: Uint<8>; circuit put<T>(value: T): [] { stored = disclose(value); } export circuit entry(secret: Uint<8>): Uint<8> { put<Uint<8>>(secret); stored = default<Uint<8>>; put<Uint<0..256>>(secret); return stored; }", { put: 1 }, facts => {
    assert.ok(facts.metrics.statefulSummaryHits > 0);
    assert.equal(facts.paths[0].writes.length, 3);
    assert.equal(facts.paths[0].writes[0].after.flows[0].source.name, "secret");
    assert.equal(facts.paths[0].writes[2].before.constant, "0");
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
  });
});

for (const witness of [false, true]) test(`genuinely distinct ${witness ? "witness" : "guard"} instances require explicit policy identities`, () => {
  const source = witness
    ? "witness fetch<T>(): Field; export circuit entry(): [Field, Field] { return disclose([fetch<Uint<8>>(), fetch<Uint<16>>()]); }"
    : 'export ledger allowed: Boolean; export ledger stored: Field; circuit guard<T>(): [] { assert(allowed, "allowed"); } export circuit entry(): [] { guard<Uint<8>>(); guard<Uint<16>>(); stored = 1 as Field; }';
  compare(source, witness ? { fetch: 2 } : { guard: 2 }, facts => {
    const policies = witness ? { secrets: [{ witness: "fetch" }] } : { authorization: [{ state: "stored", guard: "guard" }] };
    const result = scanFile(facts.program.root, { policies });
    assert.equal(result.diagnostics[0]?.code, "invalid-policy");
    assert.match(result.diagnostics[0].message, /resolves to 2/);
  });
});
