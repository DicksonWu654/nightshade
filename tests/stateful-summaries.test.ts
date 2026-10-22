import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { MutationCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function compare(source: string, check: (cached: ReturnType<Dataflow["analyze"]>, program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.deepEqual(expanded.diagnostics, []);
    assert.deepEqual(cached.paths, expanded.paths);
    assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(cached.completedEntries, expanded.completedEntries);
    assert.ok(cached.metrics.statefulSummaryHits > 0);
    assert.ok(cached.metrics.steps < expanded.metrics.steps);
    assert.ok(cached.metrics.summaryEntries <= 256);
    assert.ok(cached.metrics.summaryEffects <= 4096);
    check(cached, program);
  });
}

test("stateful summaries replay assignments against current storage, not cached before-values", () => {
  compare("export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } export circuit entry(secret: Field): Field { stored = 0 as Field; put(secret); stored = 9 as Field; put(secret); return stored; }", facts => {
    assert.equal(facts.metrics.statefulSummaryHits, 1);
    assert.equal(facts.paths[0].writes[3].before.constant, "9");
    assert.equal(facts.paths[0].sinks.at(-1)!.value.flows[0].source.name, "secret");
  });
});

test("nested mutation summaries preserve write and completion order with rebased callers", () => {
  compare("export ledger first: Field; export ledger second: Field; circuit scalar(value: Field): [] { first = disclose(value); } circuit pair(value: Field): [] { scalar(value); second = disclose(value); } circuit outer(): [] { pair(1 as Field); } export circuit entry(): [] { pair(1 as Field); outer(); }", (facts, program) => {
    const writes = facts.paths[0].writes;
    assert.equal(writes.length, 4);
    assert.deepEqual(writes.map(write => program.symbols.get(write.ledger)!.name), ["first", "second", "first", "second"]);
    assert.deepEqual(writes[2].callPath.map(id => program.symbols.get(id)!.name), ["entry", "outer", "pair", "scalar"]);
  });
});

test("summary replay rechecks caller guard invalidation at every mutation", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } circuit touch(): [] { authorized = false; sensitive = default<Field>; } export circuit entry(): [] { guard(); touch(); touch(); sensitive = 2 as Field; }', (facts, program) => {
    const policies = resolvePolicies(program, { authorization: [{ state: "sensitive", guard: "guard" }] });
    const findings = detectors.flatMap(detector => detector.run(facts, policies));
    assert.equal(findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 2);
  });
});

for (const stateful of [false, true]) test(`${stateful ? "stateful" : "pure"} cached summaries cannot bypass nested call-depth limits`, () => {
  const helpers = Array.from({ length: 30 }, (_, index) => `circuit chain${index}(): [] { ${index === 29 ? "helper" : `chain${index + 1}`}(); }`).join("\n");
  withFiles({ "main.compact": `export ledger stored: Field; circuit leaf(): [] {} circuit helper(): [] { ${stateful ? "stored = default<Field>;" : ""} leaf(); } ${helpers} export circuit entry(): [] { helper(); chain0(); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === "call-depth"));
    assert.deepEqual(cached.diagnostics, expanded.diagnostics);
    assert.deepEqual(cached.completedEntries, []);
    assert.deepEqual(cached.paths, expanded.paths);
  });
});

test("oversized mutation recordings fall back without dropping effects", () => {
  compare("export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } circuit many(value: Field): [] { for (const iteration of 0..128) { put(value); } } export circuit entry(secret: Field): [] { many(secret); many(secret); }", facts => {
    assert.equal(facts.paths[0].writes.length, 256);
    assert.equal(facts.metrics.statefulSummaryHits, 255);
    assert.equal(facts.metrics.summaryEntries, 1);
  });
});

test("cached mutation values preserve ambient private control on replay", () => {
  compare("export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } export circuit entry(secret: Field, flag: Boolean): [] { if (disclose(flag)) { put(secret); put(secret); } else { put(0 as Field); put(0 as Field); } }", facts => {
    assert.equal(facts.paths.length, 2);
    assert.ok(facts.paths.every(path => path.writes.length === 2));
    assert.ok(facts.paths.every(path => path.writes.every(write => write.after.flows.some(flow => flow.source.name === "flag"))));
  });
});

test("summary eligibility does not make incomplete callee analysis cacheable", () => {
  withFiles({ "main.compact": "struct Box { values: Vector<8, Field>; } export ledger stored: Box; circuit put(): [] { stored = default<Box>; } export circuit entry(): [] { put(); put(); }" }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact")), 20000, 256, 4).analyze();
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
    assert.equal(facts.metrics.statefulSummaryHits, 0);
    assert.equal(facts.metrics.summaryEntries, 0);
    assert.deepEqual(facts.completedEntries, []);
  });
});

test("aggregate summary writes preserve unrelated current ledger roots", () => {
  compare("struct Pair { first: Field; second: Field; } export ledger pair: Pair; export ledger other: Field; circuit setFirst(value: Field): [] { pair = Pair { first: disclose(value), second: default<Field> }; } export circuit entry(secret: Field): Field { setFirst(secret); other = 8 as Field; setFirst(secret); return other; }", facts => {
    assert.equal(facts.paths[0].sinks.at(-1)!.value.constant, "8");
    assert.equal(facts.paths[0].sinks.at(-1)!.value.flows.length, 0);
  });
});

test("Map summary mutations preserve public keys, wildcard joins and unrelated writes", () => {
  compare("import CompactStandardLibrary; export ledger table: Map<Field, Field>; circuit insert(key: Field, value: Field): [] { table.insert(disclose(key), disclose(value)); } export circuit entry(key: Field, secret: Field): Field { insert(key, secret); table.insert(2 as Field, 0 as Field); insert(key, secret); return table.lookup(2 as Field); }", facts => {
    const output = facts.paths[0].sinks.at(-1)!;
    assert.deepEqual([...new Set(output.value.flows.map(flow => flow.source.name))].sort(), ["key", "secret"]);
    assert.equal(facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation" && sink.name.endsWith(".insert")).length, 2);
  });
});

test("Counter mutation summaries recompute current receiver dependencies", () => {
  compare("import CompactStandardLibrary; export ledger count: Counter; circuit add(amount: Uint<16>): [] { count.increment(disclose(amount)); } export circuit entry(first: Uint<16>, second: Uint<16>): Uint<64> { add(first); add(second); add(first); return count.read(); }", facts => {
    assert.deepEqual([...new Set(facts.paths[0].sinks.at(-1)!.value.flows.map(flow => flow.source.name))].sort(), ["first", "second"]);
  });
});

test("Set and List summary operations use the current receiver and keep operation sinks", () => {
  compare("import CompactStandardLibrary; export ledger seen: Set<Field>; export ledger queue: List<Field>; circuit put(value: Field): [] { seen.insert(disclose(value)); queue.pushFront(disclose(value)); queue.popFront(); } export circuit entry(secret: Field): Uint<64> { put(secret); put(secret); return seen.size(); }", facts => {
    assert.equal(facts.paths[0].writes.length, 6);
    assert.equal(facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation").length, 4);
    assert.ok(facts.paths[0].sinks.at(-1)!.value.flows.some(flow => flow.source.name === "secret"));
  });
});

test("scalar method-write and reset summaries preserve strong update semantics", () => {
  compare("import CompactStandardLibrary; export ledger stored: Field; circuit put(value: Field): [] { stored.write(disclose(value)); stored.resetToDefault(); } export circuit entry(secret: Field): Field { put(secret); put(secret); return stored; }", facts => {
    assert.equal(facts.paths[0].writes.length, 4);
    assert.equal(facts.paths[0].sinks.at(-1)!.value.constant, "0");
    assert.equal(facts.paths[0].sinks.at(-1)!.value.flows.length, 0);
  });
});

test("mutation summaries preserve caller hash constraints without creating new bindings", () => {
  compare('import CompactStandardLibrary; export ledger digest: Bytes<32>; export ledger published: Field; circuit put(value: Field): [] { published = disclose(value); } export circuit entry(secret: Field): [] { assert(persistentHash<Field>(secret) == digest, "bound"); put(secret); put(secret); }', facts => {
    assert.equal(facts.paths[0].bindings.length, 1);
    assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 1);
  });
});

test("stateful summaries keep separately evaluated witness sources distinct", () => {
  compare("witness secret(): Field; export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } export circuit entry(): [] { const first = secret(); const second = secret(); put(first); put(second); put(first); }", facts => {
    const writes = facts.paths[0].writes;
    assert.equal(writes.length, 3);
    assert.notEqual(writes[0].after.flows[0].source.id, writes[1].after.flows[0].source.id);
    assert.equal(writes[0].after.flows[0].source.id, writes[2].after.flows[0].source.id);
  });
});

test("replayed writes cannot become successful paths after a caller abort", () => {
  compare('export ledger stored: Field; circuit guard(): [] { assert(stored != default<Field>, "guard"); } circuit put(): [] { stored = default<Field>; } export circuit entry(): [] { put(); put(); assert(false, "abort"); }', (facts, program) => {
    assert.deepEqual(facts.paths, []);
    assert.equal(facts.failedAssertions.length, 1);
    const policies = resolvePolicies(program, { authorization: [{ state: "stored", guard: "guard" }] });
    assert.equal(detectors.flatMap(detector => detector.run(facts, policies)).filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 0);
  });
});

test("effectful arguments replay in order before their enclosing receiver mutation", () => {
  compare("import CompactStandardLibrary; export ledger count: Counter; circuit inner(value: Uint<16>): Uint<16> { count.increment(disclose(value)); return value; } circuit outer(value: Uint<16>): [] { count.increment(disclose(inner(value))); } export circuit entry(secret: Uint<16>): Uint<64> { outer(secret); outer(secret); return count.read(); }", facts => {
    assert.equal(facts.paths[0].writes.length, 4);
    assert.equal(facts.paths[0].sinks.at(-1)!.value.flows[0].source.name, "secret");
  });
});

test("a cached mutation cannot carry a guard from a different invocation", () => {
  compare('export ledger authorized: Boolean; export ledger stored: Field; circuit guard(): [] { assert(authorized, "authorized"); } circuit put(): [] { stored = default<Field>; } export circuit first(): [] { guard(); put(); } export circuit second(): [] { put(); put(); }', (facts, program) => {
    const policies = resolvePolicies(program, { authorization: [{ state: "stored", guard: "guard" }] });
    const findings = detectors.flatMap(detector => detector.run(facts, policies)).filter(finding => finding.detectorId === "unguarded-sensitive-state-write");
    assert.ok(findings.length > 0);
    assert.ok(findings.every(finding => finding.callPath[0] === "second"));
  });
});

test("mutation summary eligibility excludes reads, constraints, branches, witnesses and dynamic addresses", () => {
  withFiles({ "main.compact": 'import CompactStandardLibrary; witness value(): Field; export ledger stored: Field; export ledger table: Map<Field, Map<Field, Field>>; circuit read(): [] { stored = stored + 1; } circuit guarded(): [] { assert(false, "abort"); stored = default<Field>; } circuit branch(flag: Boolean): [] { if (flag) { stored = default<Field>; } } circuit privateWrite(): [] { stored = disclose(value()); } circuit nested(key: Field): [] { table.lookup(key).insert(key, key); } export circuit entry(): [] {}' }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const eligibility = new MutationCircuitEligibility(program);
    for (const name of ["read", "guarded", "branch", "privateWrite", "nested"]) {
      const symbol = program.activeSymbols().find(symbol => symbol.name === name)!;
      program.ensureFunction(symbol.id);
      assert.equal(eligibility.allows(symbol.id), false, name);
    }
  });
});

test("stateful summary events remain charged to analysis budgets", () => {
  withFiles({ "main.compact": "export ledger value: Field; circuit put(): [] { value = default<Field>; } export circuit entry(): [] { for (const iteration of 0..64) { put(); } }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program, 100).analyze();
    assert.ok(facts.metrics.statefulSummaryHits > 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(facts.completedEntries, []);
  });
});
