import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { AnalysisFacts, Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { GuardCover, guardsCover } from "../src/dataflow/guard-cover.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Policies } from "../src/policies.js";
import { withFiles } from "./helpers.js";

const profile = (...sets: string[][]): Set<string>[] => sets.map(guards => new Set(guards));

test("guard coverage is componentwise across current and historical writes", () => {
  assert.equal(guardsCover(profile(["first"], [], ["second"]), profile(["first", "second"], ["first"], ["second"])), true);
  assert.equal(guardsCover(profile(["first"], []), profile([], ["first"])), false);
  assert.equal(guardsCover(profile(["first"]), profile(["second"])), false);
  assert.equal(guardsCover(profile([]), profile([], [])), false);
});

test("guard cover preserves incomparable witnesses instead of intersecting fictitious paths", () => {
  const cover = new GuardCover();
  assert.equal(cover.covered("node", profile(["first"])), false);
  assert.equal(cover.covered("node", profile(["second"])), false);
  assert.equal(cover.covered("node", profile(["first", "second"])), true);
  assert.equal(cover.covered("node", profile([])), false);
  assert.equal(cover.covered("node", profile(["second"])), true);
  assert.equal(cover.covered("different-history", profile(["first", "second"])), false);
});

test("guard cover takes immutable snapshots and bounds entries and facts without pruning", () => {
  const cover = new GuardCover(1, 2);
  const original = profile(["first"]);
  assert.equal(cover.covered("node", original), false);
  original[0].clear();
  assert.equal(cover.covered("node", profile(["second"])), false);
  assert.equal(cover.covered("node", profile(["second"])), false);
  assert.equal(cover.covered("node", profile(["first", "second"])), true);
  assert.equal(cover.covered("other", profile([])), false);
  assert.equal(cover.covered("node", profile([])), false);
  assert.equal(cover.covered("node", profile(["second"])), true);
  const constrained = new GuardCover(256, 1);
  assert.equal(constrained.covered("node", profile(["first"])), false);
  assert.equal(constrained.covered("node", profile(["first"])), false);
});

function observations(facts: AnalysisFacts, policies: Policies = {}): string[] {
  return detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies))).map(finding => JSON.stringify({ id: finding.detectorId, fingerprint: finding.fingerprint, location: finding.location, source: finding.source, constraint: finding.constraint, message: finding.message })).sort();
}

function compare(source: string, check: (covered: AnalysisFacts, exact: AnalysisFacts) => void, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const exact = new Dataflow(program).analyze();
    const covered = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "guard-cover").analyze();
    const uncached = new Dataflow(program, 20000, 256, 50000, "instructions", false, false, "guard-cover").analyze();
    assert.deepEqual(exact.diagnostics, []);
    assert.deepEqual(covered.diagnostics, []);
    assert.deepEqual(covered.completedEntries, exact.completedEntries);
    assert.deepEqual(uncached.diagnostics, []);
    assert.deepEqual(covered.paths, uncached.paths);
    assert.deepEqual(covered.failedAssertions, uncached.failedAssertions);
    assert.deepEqual(observations(covered, policies), observations(exact, policies));
    assert.equal(exact.pathSemantics, "equivalent-states");
    assert.equal(covered.pathSemantics, "guard-cover");
    check(covered, exact);
  });
}

test("optional successful guards are subsumed only by real weaker predecessor states", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } sensitive = 1 as Field; }', (covered, exact) => {
    assert.equal(covered.metrics.guardSubsumptions, 1);
    assert.equal(covered.paths.length, 1);
    assert.equal(exact.paths.length, 2);
    assert.ok(exact.paths.some(path => JSON.stringify(path) === JSON.stringify(covered.paths[0])));
    assert.equal(covered.paths[0].writes[0].guards.length, 0);
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("incomparable guards and prior guard-at-write observations remain separate", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit first(): [] { assert(authorized, "authorized"); } circuit second(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean): [] { assert(authorized, "authorized"); if (disclose(flag)) { first(); } else { second(); } sensitive = 1 as Field; }', covered => {
    assert.equal(covered.paths.length, 2);
    assert.equal(covered.metrics.guardSubsumptions, 0);
    assert.ok(covered.paths.every(path => path.writes[0].guards.length === 1));
  }, { authorization: [{ state: "sensitive", guard: "first" }, { state: "sensitive", guard: "second" }] });
});

test("different authorization constraints cannot be erased at a join", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean): [] { if (disclose(flag)) { guard(); } sensitive = 1 as Field; }', covered => {
    assert.equal(covered.paths.length, 2);
    assert.equal(covered.metrics.guardSubsumptions, 0);
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("guarded-state subsumption preserves subsequent invalidation and summary replay", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } circuit put(): [] { sensitive = default<Field>; } export circuit entry(flag: Boolean): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } guard(); put(); authorized = false; put(); }', covered => {
    const guard = [...covered.program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
    assert.equal(covered.metrics.guardSubsumptions, 1);
    assert.ok(covered.metrics.statefulSummaryHits > 0);
    assert.ok(covered.paths[0].writes[0].guards.includes(guard));
    assert.equal(covered.paths[0].writes.at(-1)!.guards.includes(guard), false);
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("subsumption covers historical write guards without replacing them with later guards", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean, other: Boolean, secret: Field): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } sensitive = disclose(secret); disclose(flag); if (other) {} }', (covered, exact) => {
    assert.equal(covered.metrics.guardSubsumptions, 1);
    assert.equal(covered.paths.length, 1);
    assert.equal(exact.paths.length, 2);
    assert.equal(covered.paths[0].writes[0].guards.length, 0);
    assert.ok(exact.paths.some(path => JSON.stringify(path) === JSON.stringify(covered.paths[0])));
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("incomparable historical writes are retained even when current guards coincide", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit first(): [] { assert(authorized, "authorized"); } circuit second(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean, other: Boolean, secret: Field): [] { assert(authorized, "authorized"); if (disclose(flag)) { first(); } else { second(); } sensitive = disclose(secret); first(); second(); sensitive = disclose(secret); disclose(flag); if (other) {} }', covered => {
    assert.equal(covered.paths.length, 2);
    assert.equal(covered.metrics.guardSubsumptions, 0);
    assert.ok(covered.paths.every(path => path.writes[0].guards.length === 1 && path.writes[1].guards.length === 2));
  }, { authorization: [{ state: "sensitive", guard: "first" }, { state: "sensitive", guard: "second" }] });
});

test("branch guard correlations remain available to later captured predicates", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } const result = map((item: Boolean): Boolean => flag, [true]); assert(result[0], "guarded branch"); sensitive = 1 as Field; }', covered => {
    assert.equal(covered.paths.length, 1);
    assert.ok(covered.paths[0].writes[0].guards.some(guard => covered.program.symbols.get(guard)?.name === "guard"));
    assert.equal(covered.metrics.guardSubsumptions, 0);
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("later aborts eliminate all covered histories instead of inventing successful writes", () => {
  compare('export ledger authorized: Boolean; export ledger sensitive: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } sensitive = 1 as Field; assert(false, "reject"); }', covered => {
    assert.equal(covered.metrics.guardSubsumptions, 1);
    assert.deepEqual(covered.paths, []);
    assert.equal(covered.failedAssertions.length, 1);
  }, { authorization: [{ state: "sensitive", guard: "guard" }] });
});

test("mutually exclusive bindings and publications cannot manufacture a preimage finding", () => {
  compare('import CompactStandardLibrary; export ledger digest: Bytes<32>; export ledger published: Field; export circuit entry(flag: Boolean, secret: Field): [] { if (disclose(flag)) { assert(persistentHash<Field>(secret) == digest, "bound"); } else { published = disclose(secret); } }', covered => {
    assert.equal(covered.paths.length, 2);
    assert.equal(covered.metrics.guardSubsumptions, 0);
    assert.equal(detectors[0].run(covered).length, 0);
    assert.deepEqual(observations(covered).map(serialized => JSON.parse(serialized).id), ["write-only-ledger"]);
  });
});

test("a live branch flag and later assertion retain publication correlation", () => {
  compare('import CompactStandardLibrary; export ledger published: Field; export circuit entry(flag: Boolean, secret: Field): [] { if (disclose(flag)) { published = disclose(secret); } assert(!flag, "only false"); }', covered => {
    assert.equal(covered.paths.length, 1);
    assert.equal(covered.paths[0].writes.length, 0);
    assert.equal(covered.metrics.guardSubsumptions, 0);
  }, { secrets: [{ circuit: "entry", parameter: "secret" }] });
});

for (const field of ["trace", "guards"]) test(`user field ${field} is data, not analysis metadata discarded by state identity`, () => {
  compare(`struct Payload { ${field}: Field; } circuit choose(flag: Boolean): Payload { return flag ? Payload { ${field}: 1 as Field } : Payload { ${field}: 2 as Field }; } export circuit entry(flag: Boolean, other: Boolean): Field { const value = choose(flag); if (other) {} return value.${field}; }`, (covered, exact) => {
    assert.deepEqual([...new Set(covered.paths.map(path => path.sinks.at(-1)!.value.constant))].sort(), ["1", "2"]);
    assert.deepEqual([...new Set(exact.paths.map(path => path.sinks.at(-1)!.value.constant))].sort(), ["1", "2"]);
  });
});

test("guard cover does not erase distinct private sources or transformations", () => {
  compare('import CompactStandardLibrary; witness secret(): Field; export ledger output: Field; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { output = disclose(secret()); } else { output = disclose(secret() + 1); } }', covered => {
    assert.equal(covered.paths.length, 2);
    const sources = covered.paths.flatMap(path => path.writes.flatMap(write => write.after.flows.filter(flow => flow.source.name === "secret").map(flow => flow.source.id)));
    assert.equal(new Set(sources).size, 2);
  }, { secrets: [{ witness: "secret" }] });
});

test("guard cover retains same-branch hash bindings and implicit private publication", () => {
  compare('import CompactStandardLibrary; export ledger authorized: Boolean; export ledger digest: Bytes<32>; export ledger published: Field; circuit guard(): [] { assert(authorized, "authorized"); } export circuit entry(flag: Boolean, secret: Field): [] { assert(authorized, "authorized"); if (disclose(flag)) { guard(); } assert(persistentHash<Field>(secret) == digest, "bound"); published = disclose(secret); }', covered => {
    assert.equal(covered.metrics.guardSubsumptions, 1);
    assert.equal(covered.paths[0].bindings.length, 1);
    assert.equal(detectors[0].run(covered).length, 1);
  });
});

test("sequential optional checks complete under small budgets without general branch merging", () => {
  const source = `export ledger authorized: Boolean; export ledger sensitive: Field; ${Array.from({ length: 12 }, (_, index) => `circuit check${index}(): [] { assert(authorized, "authorized"); }`).join(" ")} export circuit entry(${Array.from({ length: 12 }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { assert(authorized, "authorized"); ${Array.from({ length: 12 }, (_, index) => `if (disclose(flag${index})) { check${index}(); }`).join(" ")} sensitive = 1 as Field; }`;
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const exact = new Dataflow(program).analyze();
    const covered = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "guard-cover").analyze();
    assert.ok(exact.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(covered.diagnostics, []);
    assert.equal(covered.metrics.guardSubsumptions, 12);
    assert.equal(covered.paths.length, 1);
    assert.equal(covered.paths[0].writes[0].guards.length, 0);
    assert.ok(covered.metrics.steps < 500);
    const repeatable = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "guard-cover");
    assert.deepEqual(repeatable.analyze(), repeatable.analyze());
    const repeated = new Dataflow(program, 5, 1, 50000, "instructions", true, true, "guard-cover").analyze();
    assert.ok(repeated.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(repeated.completedEntries, []);
  });
});

test("distinct stateful branch histories still report budget exhaustion with guard cover", () => {
  const source = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: 10 }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const facts = new Dataflow(new Program(path), 20000, 256, 50000, "instructions", true, true, "guard-cover").analyze();
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(facts.completedEntries, []);
    assert.equal(facts.metrics.guardSubsumptions, 0);
  });
});

test("all labeled corpus detector observations agree with guarded-state subsumption", () => {
  const manifest = JSON.parse(readFileSync(resolve("tests/corpus/manifest.json"), "utf8")) as { cases: { file: string; policies?: Policies }[] };
  const policyManifest = JSON.parse(readFileSync(resolve("tests/corpus/policies-manifest.json"), "utf8")) as { cases: { name: string; policies: Policies }[] };
  const cases = [...manifest.cases, ...policyManifest.cases.flatMap(entry => ["vulnerable", "safe"].map(label => ({ file: `${label}/${entry.name}.compact`, policies: entry.policies })))];
  assert.equal(cases.length, 29);
  for (const entry of cases) {
    const program = new Program(resolve("tests/corpus", entry.file));
    const exact = new Dataflow(program).analyze();
    const covered = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "guard-cover").analyze();
    assert.deepEqual(covered.diagnostics, exact.diagnostics, entry.file);
    assert.deepEqual(covered.completedEntries, exact.completedEntries, entry.file);
    assert.deepEqual(observations(covered, entry.policies), observations(exact, entry.policies), entry.file);
  }
});
