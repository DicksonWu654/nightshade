import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { PureCircuitEligibility } from "../src/analysis/summaries.js";
import { withFiles } from "./helpers.js";

test("repeated pure calls reuse bounded context-specific summaries", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; circuit digest(value: Field): Bytes<32> { return persistentHash<Field>(value); } export circuit entry(secret: Field): Bytes<32> { for (const iteration of 0..32) { digest(secret); } return digest(secret); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.deepEqual(cached.paths, expanded.paths);
    assert.equal(cached.metrics.summaryHits, 32);
    assert.ok(cached.metrics.steps < expanded.metrics.steps);
    assert.ok(cached.metrics.summaryEntries <= 256);
  });
});

test("summaries preserve distinct argument provenance and current call-site traces", () => {
  withFiles({ "main.compact": "circuit identity(value: Field): Field { return value; } export circuit entry(first: Field, second: Field): [Field, Field, Field] { return [identity(first), identity(second), identity(first)]; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.deepEqual(cached.paths, expanded.paths);
    assert.equal(cached.metrics.summaryHits, 1);
    assert.deepEqual(cached.paths[0].sinks[0].value.items!.map(item => item.flows[0].source.name), ["first", "second", "first"]);
  });
});

test("witness, constraint, captured, stateful and branching circuits are excluded from pure summaries", () => {
  const source = 'witness privateValue(): Field; export ledger value: Field; circuit source(): Field { return privateValue(); } circuit guarded(flag: Boolean): [] { assert(flag, "guard"); } circuit read(): Field { return value; } circuit branch(flag: Boolean): Field { return flag ? 1 as Field : 2 as Field; } circuit write(): [] { value = 1 as Field; } export circuit entry(secret: Field): [] { map((item: Field): Field => secret, [0 as Field]); }';
  withFiles({ "main.compact": source }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const eligibility = new PureCircuitEligibility(program);
    for (const name of ["source", "guarded", "read", "branch", "write"]) {
      const symbol = program.activeSymbols().find(symbol => symbol.name === name)!;
      program.ensureFunction(symbol.id);
      assert.equal(eligibility.allows(symbol.id), false, name);
    }
    const anonymous = [...program.functions.values()].find(fn => fn.symbol.id.includes("::lambda:"));
    assert.ok(anonymous);
    assert.equal(eligibility.allows(anonymous.symbol.id), false);
  });
});

test("summary guard replay excludes calls in a zero-iteration loop", () => {
  withFiles({ "main.compact": "export ledger value: Field; circuit guard(): [] {} circuit helper(): [] { for (const iteration of 0..0) { guard(); } return []; } export circuit entry(): [] { helper(); helper(); value = 1 as Field; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const policies = resolvePolicies(program, { authorization: [{ state: "value", guard: "guard" }] });
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.ok(cached.metrics.summaryHits > 0);
    assert.deepEqual(cached.paths, expanded.paths);
    assert.equal(detectors.flatMap(detector => detector.run(cached, policies)).filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 1);
  });
});

test("summary reuse does not cross changed constraint or implicit-control contexts", () => {
  withFiles({ "main.compact": 'circuit identity(value: Field): Field { return value; } export circuit entry(secret: Field, flag: Boolean): [Field, Field] { const old = identity(secret); assert(secret == (1 as Field), "bound"); if (flag) { return [old, identity(secret)]; } return [old, identity(secret)]; }' }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.deepEqual(cached.paths, expanded.paths);
  });
});

test("summary hits still respect the caller analysis budget", () => {
  withFiles({ "main.compact": "circuit identity(value: Field): Field { return value; } export circuit entry(secret: Field): Field { for (const iteration of 0..32) { identity(secret); } return secret; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program, 60).analyze();
    assert.ok(facts.metrics.summaryHits > 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(facts.completedEntries, []);
  });
});

test("nested summary guard completion order matches expanded invocation", () => {
  withFiles({ "main.compact": "export ledger value: Field; circuit inner(): [] {} circuit outer(): [] { inner(); } export circuit first(): [] { outer(); } export circuit second(): [] { outer(); value = 1 as Field; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    assert.deepEqual(cached.diagnostics, []);
    assert.ok(cached.metrics.summaryHits > 0);
    assert.deepEqual(cached.paths, expanded.paths);
  });
});
