import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated, detectors } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { publicKeyMembershipObservations } from "../src/analysis/public-key-membership.js";
import { publicKeyMembershipAuthorization as rule } from "../src/detectors/public-key-membership.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const positive = readFileSync("tests/corpus/known-bugs/sdk-public-key-membership-positive.compact", "utf8");
const membershipBoundaries = (JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")) as {
  membershipIdentity34: { cases: { file: string; lines: number[] }[] };
}).membershipIdentity34.cases;
function flow(program: Program, engine: "instructions" | "expressions", cached: boolean): AnalysisFacts {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, true).analyze();
}
function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts) => void) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = flow(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(f => f.metadata.entry).sort(), expected);
      for (const finding of findings) {
        assert.equal(finding.severity, "high"); assert.equal(finding.confidence, "high");
        assert.equal(finding.metadata.soleGate, "unproven");
        assert.equal(finding.metadata.authenticationIntent, "unknown");
        assert.ok((finding.metadata.historyEvidence as unknown[]).length > 0);
      }
      oracle ??= findings;
      assert.deepEqual(findings, oracle, `${engine}/${cached}`);
      inspect?.(facts);
    }
  });
}

for (const boundary of membershipBoundaries) test(`owned membership identity boundary: ${boundary.file}`, async () => {
  const file = resolve("tests/corpus", boundary.file);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const program = new Program(file);
  let oracle: ReturnType<typeof rule.run> | undefined;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = flow(program, engine, cached), findings = rule.run(facts);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.deepEqual(findings.map(item => item.location.line), boundary.lines);
    oracle ??= findings;
    assert.deepEqual(findings, oracle, `${engine}/${cached}`);
  }
  const selected = scanFile(file, { detectors: [rule.id] });
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  // Scans analyze each observation entry separately; invocation counters may
  // differ from the direct all-entry pass. Preserve source sites and chains.
  const sites = (findings: ReturnType<typeof rule.run>) => findings.map(item => ({
    location: item.location, source: item.source, constraint: item.constraint,
    trace: item.trace, callPath: item.callPath, entry: item.metadata.entry,
  }));
  assert.deepEqual(sites(selected.findings), sites(oracle!));
  assert.deepEqual(selected.coverage.completedEntries, program.entries);
  const supervised = await scanFileIsolated(file, { detectors: [rule.id] });
  assert.equal(supervised.status, "complete", JSON.stringify(supervised.diagnostics));
  assert.deepEqual(supervised.findings, selected.findings);
  assert.deepEqual(supervised.coverage, selected.coverage);
});
const header = `import CompactStandardLibrary;
export ledger members: Set<ZswapCoinPublicKey>;
export ledger byteMembers: Set<Bytes<32>>;
export ledger otherMembers: Set<ZswapCoinPublicKey>;
export ledger operators: Map<Either<ZswapCoinPublicKey, ContractAddress>, Boolean>;
export ledger stored: Field;
export ledger changed: Field;
witness secret(): Bytes<32>;
witness supplied(): ZswapCoinPublicKey;
`;

test("native Set, bytes and active Either membership retain exact successful guards", () => {
  fixture(header + `
export circuit direct(next: Field): [] { assert(members.member(disclose(ownPublicKey())), "member"); stored = disclose(next); }
export circuit bytes(next: Field): [] { assert(byteMembers.member(disclose(ownPublicKey().bytes)), "member"); stored = disclose(next); }
export circuit either(next: Field): [] { assert(operators.member(disclose(left<ZswapCoinPublicKey, ContractAddress>(ownPublicKey()))), "role"); stored = disclose(next); }
export circuit relay(next: Field): [] { assert(!members.member(disclose(ownPublicKey())) == false, "member"); stored = disclose(next); }
export circuit late(next: Field): [] { stored = disclose(next); assert(members.member(disclose(ownPublicKey())), "atomic success"); }
`, ["bytes", "direct", "either", "relay"]);
});

test("optional, bypassed, ignored, negative and different query checks are quiet", () => {
  fixture(header + `
export circuit optional(next: Field, check: Boolean): [] { if (disclose(check)) { assert(members.member(disclose(ownPublicKey())), "member"); } stored = disclose(next); }
export circuit bypass(next: Field, permit: Boolean): [] { assert(members.member(disclose(ownPublicKey())) || permit, "either gate"); stored = disclose(next); }
export circuit ignored(next: Field): [] { const preview = members.member(disclose(ownPublicKey())); stored = disclose(next); }
export circuit absent(next: Field): [] { assert(!members.member(disclose(ownPublicKey())), "absent"); stored = disclose(next); }
export circuit anotherKey(next: Field): [] { const preview = members.member(disclose(ownPublicKey())); assert(members.member(disclose(supplied())), "different key"); stored = disclose(next); }
export circuit anotherReceiver(next: Field, suppliedKey: ZswapCoinPublicKey): [] { const preview = members.member(disclose(ownPublicKey())); assert(otherMembers.member(disclose(suppliedKey)), "different collection"); stored = disclose(next); }
export circuit retrieval(): Boolean { return disclose(members.member(disclose(ownPublicKey()))); }
`, []);
});

test("secret hashes, inactive native Either payloads and custom encodings are quiet", () => {
  fixture(header + `
struct Wrapped { key: ZswapCoinPublicKey; }
export ledger wrapped: Set<Wrapped>;
export circuit hashed(next: Field): [] { assert(byteMembers.member(disclose(persistentHash<Bytes<32>>(secret()))), "private identity"); stored = disclose(next); }
export circuit inactive(next: Field): [] {
  const account = Either<ZswapCoinPublicKey, ContractAddress> { is_left: false, left: ownPublicKey(), right: default<ContractAddress> };
  assert(operators.member(disclose(account)), "contract identity"); stored = disclose(next);
}
export circuit compound(next: Field): [] { assert(wrapped.member(disclose(Wrapped { key: ownPublicKey() })), "compound encoding"); stored = disclose(next); }
export circuit modified(next: Field): [] { assert(byteMembers.member(disclose(persistentHash<Bytes<32>>(ownPublicKey().bytes))), "transformed key"); stored = disclose(next); }
`, []);
  fixture(`module Namesake { export witness ownPublicKey(): Bytes<32>; }
import Namesake prefix N_;
import CompactStandardLibrary;
export ledger identities: Set<Bytes<32>>;
export ledger stored: Field;
export circuit namesake(next: Field): [] { assert(identities.member(disclose(N_ownPublicKey())), "user witness"); stored = disclose(next); }
`, []);
});

test("preexisting receiver and revision agreement reject fresh membership and stale live projections", () => {
  fixture(header + `
export circuit freshlyInserted(next: Field): [] { const pk = ownPublicKey(); members.insert(disclose(pk)); assert(members.member(disclose(pk)), "fresh member"); stored = disclose(next); }
export circuit reset(next: Field): [] { members.resetToDefault(); members.insert(disclose(ownPublicKey())); assert(members.member(disclose(ownPublicKey())), "fresh collection"); stored = disclose(next); }
export ledger nested: Map<Field, Set<ZswapCoinPublicKey>>;
circuit mutate(): ZswapCoinPublicKey { nested.lookup(0 as Field).insert(disclose(supplied())); return ownPublicKey(); }
export circuit staleReceiver(next: Field): [] { assert(nested.lookup(0 as Field).member(disclose(mutate())), "receiver evaluated before key mutation"); stored = disclose(next); }
export circuit changedKey(next: Field): [] { const original = ownPublicKey(); const preview = members.member(disclose(original)); const replacement = supplied(); assert(members.member(disclose(replacement)), "changed immutable key"); stored = disclose(next); }
`, []);
});

test("branch-only effects and nested summary replay quantify every actual effect invocation", () => {
  fixture(header + `
circuit store(next: Field): [] { stored = disclose(next); }
circuit nested(next: Field): [] { store(next); store(next); }
circuit allowed(pk: ZswapCoinPublicKey): Boolean { return members.member(disclose(pk)); }
export circuit grouped(next: Field, choice: Boolean): [] { assert(allowed(ownPublicKey()), "member"); if (disclose(choice)) { changed = disclose(next); } nested(next); nested(next); }
export circuit selected(next: Field, choice: Boolean): [] { if (disclose(choice)) { assert(allowed(ownPublicKey()), "member"); nested(next); } }
export circuit optionalAfterJoin(next: Field, choice: Boolean): [] { if (disclose(choice)) { assert(allowed(ownPublicKey()), "member"); } nested(next); }
`, ["grouped", "selected"], facts => {
    const actual = rule.run(facts);
    const grouped = actual.find(f => f.metadata.entry === "grouped")!;
    assert.equal((grouped.metadata.affectedEffects as unknown[]).length, 5);
    assert.equal(grouped.metadata.successfulReaches, 9);
    if (facts.metrics.summaryEntries) assert.ok(facts.metrics.statefulSummaryHits > 0);
  });
});

test("kernel operation chronology excludes prior effects even when no ledger writes exist", () => {
  fixture(header + `
circuit transfer(recipient: Either<ContractAddress, UserAddress>): [] { kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(default<Bytes<32>>), 1); kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(default<Bytes<32>>), disclose(recipient), 1); }
export circuit earlyKernel(recipient: Either<ContractAddress, UserAddress>): [] { assert(members.member(disclose(ownPublicKey())), "member"); transfer(recipient); }
export circuit lateKernel(recipient: Either<ContractAddress, UserAddress>): [] { transfer(recipient); assert(members.member(disclose(ownPublicKey())), "late member"); }
export circuit mixedKernel(recipient: Either<ContractAddress, UserAddress>): [] { transfer(recipient); assert(members.member(disclose(ownPublicKey())), "member between effects"); transfer(recipient); }
`, ["earlyKernel", "mixedKernel"], facts => {
    assert.ok(facts.paths.every(path => path.writes.length === 0));
    const mixed = rule.run(facts).find(f => f.metadata.entry === "mixedKernel")!;
    assert.ok((mixed.metadata.affectedEffects as { callSites: { column: number }[] }[]).every(effect => effect.callSites[1].column > 160));
  });
});

test("repeated lexical invocations retain occurrence identity and exact native witness calls", () => {
  fixture(header + `
circuit store(next: Field): [] { stored = disclose(next); }
export circuit repeated(next: Field): [] { assert(members.member(disclose(ownPublicKey())), "member"); for (const i of 0..2) { store(next); } }
`, ["repeated"], facts => {
    const finding = rule.run(facts)[0];
    assert.deepEqual((finding.metadata.affectedEffects as { occurrence: number }[]).map(effect => effect.occurrence), [0, 1]);
    assert.equal(finding.metadata.successfulReaches, 2);
    assert.ok((finding.metadata.historyEvidence as { witnessCalls: unknown[] }[]).every(item => item.witnessCalls.length));
  });
});

test("preview then required repeated query groups at one guard/circuit without multiplying reaches", () => {
  fixture(header + `
export circuit previewThenAssert(next: Field): [] {
  const pk = ownPublicKey();
  const preview = members.member(disclose(pk));
  assert(members.member(disclose(pk)), "required member");
  stored = disclose(next);
}
`, ["previewThenAssert"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal((finding.metadata.affectedEffects as unknown[]).length, 1);
    assert.equal(finding.metadata.successfulReaches, 1);
    assert.equal(finding.metadata.guardEffectRelations, 2);
    assert.equal(new Set((finding.metadata.historyEvidence as { queryLocation: { line: number } }[]).map(item => item.queryLocation.line)).size, 2);
  });
});

test("owned seed is registered, default-on and uses entry-scoped exact collection observations", () => {
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact");
    assert.ok(detectors.includes(rule)); assert.equal(rule.defaultEnabled, true);
    const baseline = scanFile(file, { detectors: [] }), selected = scanFile(file, { detectors: [rule.id] });
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.equal(selected.coverage.baselineStatus, baseline.status);
    assert.deepEqual(selected.coverage.completedEntries, baseline.coverage.completedEntries);
    assert.equal(selected.findings.length, 1);
    assert.equal(selected.findings[0].location.line, 17);
    assert.ok(selected.coverage.rules!.every(row => row.detectorId === rule.id && row.status !== "incomplete"));
    assert.equal(scanFile(file).findings.filter(f => f.detectorId === rule.id).length, 1);
    const experimental = scanFile(file, { detectors: [rule.id], experimentalCounterQueries: true });
    assert.equal(experimental.status, "complete", JSON.stringify(experimental.diagnostics));
    assert.deepEqual(experimental.findings, selected.findings);

    const missing = new Dataflow(new Program(file)).analyze();
    assert.deepEqual(rule.run(missing), []);
    assert.ok(missing.diagnostics.every(issue => issue.code === "membership-evidence-unavailable" && issue.scope?.detectorId === rule.id));
    for (const missing of ["query", "effect", "witnessCalls"] as const) {
      const partial = flow(new Program(file), "instructions", true);
      const path = partial.paths.find(path => path.entry.endsWith("::deposit"))!;
      if (missing === "query") delete path.operations!.find(operation => operation.kind === "collection-query" && operation.args[1]?.fields?.left)?.callSites;
      else if (missing === "effect") delete path.writes[0].callSites;
      else delete path.witnessCalls;
      assert.deepEqual(rule.run(partial), []);
      assert.ok(partial.diagnostics.some(issue => issue.code === "membership-evidence-unavailable" && issue.scope?.entry.endsWith("::deposit")));
    }
    const facts = flow(new Program(file), "instructions", true);
    const exhausted = publicKeyMembershipObservations(facts, 1);
    assert.deepEqual(exhausted.observations, []);
    assert.ok(exhausted.diagnostics.every(issue => issue.code === "membership-analysis-budget" && issue.scope?.detectorId === rule.id));
  });
});

test("direct consumers prove Map/Set absence before requiring collection observations", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger values: List<Field>;
export circuit entry(): [] { assert(!values.isEmpty(), "nonempty"); values.popFront(); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const facts = new Dataflow(new Program(file)).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.deepEqual(facts.diagnostics, []);
    const limited = publicKeyMembershipObservations(facts, 0);
    assert.deepEqual(limited.observations, []);
    assert.ok(limited.diagnostics.some(issue => issue.code === "membership-analysis-budget"));
  });
});

test("observation path budgets remain rule/entry scoped while baseline and independent entries complete", () => {
  withFiles({ "main.compact": header + `
witness flags(): Vector<10, Boolean>;
export circuit expensive(next: Field): [] { const selected = flags(); for (const i of 0..10) { if (disclose(selected[i])) { changed = i as Field; } } assert(members.member(disclose(ownPublicKey())), "member"); stored = disclose(next); }
export circuit independent(next: Field): [] { assert(members.member(disclose(ownPublicKey())), "member"); stored = disclose(next); }
` }, directory => {
    const file = resolve(directory, "main.compact"), report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "incomplete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(f => f.metadata.entry), ["independent"]);
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id && issue.scope.entry.endsWith("::expensive")));
    assert.deepEqual(report.coverage.rules!.map(row => row.status), ["incomplete", "complete"]);
  });
});
