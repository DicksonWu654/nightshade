import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { merkleMembershipNotEnforced as rule } from "../src/detectors/merkle-membership.js";
import { querySourceEntry, sourceQueryCandidate } from "../src/dataflow/source-queries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// Independent optional assertions (here four ban slots) double the exact
// histories; a Merkle membership proof follows. The scanner's exact pass observes
// Merkle evidence with all private predicates; the source query must certify the
// Merkle-membership findings it stands for.
const membership = (parameters: string, ledger: string, check: string) => `import CompactStandardLibrary;
export ledger used: Set<Bytes<32>>;
${ledger}
witness secretKey(): Bytes<32>;
witness memberPath(leaf: Bytes<32>): MerkleTreePath<4, Bytes<32>>;
circuit idOf(c: Bytes<32>, sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([c, sk]);
}
circuit notBanned(sk: Bytes<32>, communities: Vector<4, Bytes<32>>, bans: Vector<4, Bytes<32>>): [] {
  for (const i of 0..4) {
    if (bans[i] != pad(32, "")) {
      assert(idOf(communities[i], sk) != bans[i], "banned");
    }
  }
}
export circuit post(c: Bytes<32>, ${parameters}communities: Vector<4, Bytes<32>>, bans: Vector<4, Bytes<32>>): [] {
  const sk = secretKey();
  notBanned(sk, communities, bans);
  const idc = idOf(c, sk);
  const p = memberPath(idc);
  assert(p.leaf == idc, "path leaf");
  ${check}
  used.insert(disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "post"), idc])));
}
`;
// The supplied root is caller data: the computed root is not enforced against ledger roots.
const supplied = membership("root: Field, ", "export ledger posts: Counter;", `assert(merkleTreePathRoot<4, Bytes<32>>(p).field == root, "not a member");
  posts.increment(1);`);
// The computed root is checked against a ledger tree: enforced on every history.
const enforced = membership("", "export ledger members: MerkleTree<4, Bytes<32>>;", `assert(members.checkRoot(disclose(merkleTreePathRoot<4, Bytes<32>>(p))), "not a member");`);

function withProgram(source: string, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file), file);
  });
}
const engines = ["instructions", "expressions"] as const;
// Scanner-equivalent exact configuration with Merkle evidence.
const merkleFlow = (program: Program, engine: "instructions" | "expressions", cached: boolean, maxPaths = 256, maxSteps = 40000, maxValues = 50000) =>
  new Dataflow(program, maxSteps, maxPaths, maxValues, engine, cached, cached, "equivalent-states", false, true, "all-private", true);
const signatures = (findings: ReturnType<typeof rule.run>) => findings.map(item => JSON.stringify(item)).sort();
const scanned = (result: ReturnType<typeof scanFile>, detector: string) => result.findings.filter(item => item.detectorId === detector)
  .map(item => JSON.stringify(item)).sort();
const unscoped = (result: ReturnType<typeof scanFile>) => result.diagnostics.filter(item => !item.scope);

test("an exhausted exact path allowance falls back to a Merkle-certified source query with oracle findings", () => {
  withProgram(supplied, (program, file) => {
    const entry = program.entries.find(id => id.endsWith("::post"))!;
    const oracle = merkleFlow(program, "instructions", false).analyze();
    assert.deepEqual(oracle.diagnostics, []);
    assert.equal(oracle.paths.length, 16, "2^4 optional ban checks");
    const expected = signatures(rule.run(oracle));
    assert.equal(expected.length, 1);
    for (const engine of engines) for (const cached of [false, true]) {
      const exact = merkleFlow(program, engine, cached).analyze();
      assert.deepEqual(exact.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(signatures(rule.run(exact)), expected, `${engine}/${cached}`);
      // Eight paths cannot hold the sixteen histories.
      assert.ok(merkleFlow(program, engine, cached, 8).analyze().diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")), `${engine}/${cached}`);
      const query = querySourceEntry(merkleFlow(program, engine, cached, 8), entry);
      assert.equal(query.status, "covered", `${engine}/${cached}: ${query.status === "incomplete" ? query.reason : ""}`);
      assert.equal(query.status === "covered" && query.evidence.merkleCertified, true);
    }
    for (const cached of [false, true]) {
      const analysis = merkleFlow(program, "instructions", cached, 8).analyzeWithCorrelatedQueries([], true, true, true);
      assert.deepEqual(analysis.exact.diagnostics, [], `fallback discards the exhausted attempt (${cached})`);
      assert.deepEqual(analysis.exact.completedEntries, []);
      assert.equal(analysis.exact.paths.filter(path => path.entry === entry).length, 0, "no partial exact histories");
      assert.deepEqual(analysis.sources.map(source => [source.entry, source.merkleCertified]), [[entry, true]]);
      const facts: AnalysisFacts = { ...analysis.exact, diagnostics: [], sourceQueries: analysis.sources };
      assert.deepEqual(signatures(rule.run(facts)), expected, `cached=${cached}`);
      assert.deepEqual(facts.diagnostics, []);
      // An uncertified source query cannot stand for a Merkle-applicable entry.
      const uncertified: AnalysisFacts = { ...facts, diagnostics: [], sourceQueries: analysis.sources.map(({ merkleCertified: _, ...source }) => source) };
      assert.deepEqual(rule.run(uncertified), []);
      assert.ok(uncertified.diagnostics.some(item => item.message.startsWith("Source-query Merkle evidence was not certified")));
    }
    const projected = scanFile(file, { maxPaths: 8 }), exhaustive = scanFile(file);
    assert.equal(projected.coverage.baselineStatus, "complete", JSON.stringify(unscoped(projected)));
    assert.equal(exhaustive.coverage.baselineStatus, "complete", JSON.stringify(unscoped(exhaustive)));
    assert.deepEqual(projected.coverage.completedEntries, exhaustive.coverage.completedEntries);
    assert.equal(scanned(projected, rule.id).length, 1);
    assert.deepEqual(scanned(projected, rule.id), scanned(exhaustive, rule.id));
  });
});

test("source-query certification retains equality-derived proof-to-effect dependencies", () => {
  const source = supplied.replace("root: Field, ", "root: Field, nullifier: Bytes<32>, ")
    .replace('used.insert(disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "post"), idc])));',
      'assert(nullifier == persistentHash<Vector<2, Bytes<32>>>([pad(32, "post"), idc]), "matches"); used.insert(disclose(nullifier));');
  withProgram(source, program => {
    const entry = program.entries.find(id => id.endsWith("::post"))!;
    const oracle = merkleFlow(program, "instructions", false).analyze();
    assert.deepEqual(oracle.diagnostics, []);
    const expected = signatures(rule.run(oracle));
    assert.equal(expected.length, 1);
    for (const engine of engines) for (const cached of [false, true]) {
      const query = querySourceEntry(merkleFlow(program, engine, cached, 8), entry);
      assert.equal(query.status, "covered", query.status === "incomplete" ? query.reason : "");
      if (query.status !== "covered") continue;
      assert.equal(query.evidence.merkleCertified, true);
      const facts = { ...oracle, paths: [], completedEntries: [], diagnostics: [], sourceQueries: [query.evidence] };
      assert.deepEqual(signatures(rule.run(facts)), expected);
      assert.deepEqual(facts.diagnostics, []);
    }
  });
});

test("an enforced proof root is not certified and the exhausted entry stays incomplete", () => {
  withProgram(enforced, (program, file) => {
    const entry = program.entries.find(id => id.endsWith("::post"))!;
    for (const engine of engines) for (const cached of [false, true]) {
      const exact = merkleFlow(program, engine, cached).analyze();
      assert.deepEqual(exact.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(rule.run(exact), [], "the checked root is enforced on every history");
      // The conservative candidate ignores enforcement; no selected history reports it.
      const query = querySourceEntry(merkleFlow(program, engine, cached, 8), entry);
      assert.equal(query.status === "incomplete" && query.reason, "A possible Merkle membership finding lacks ordinary existence evidence", `${engine}/${cached}`);
    }
    for (const cached of [false, true]) {
      const analysis = merkleFlow(program, "instructions", cached, 8).analyzeWithCorrelatedQueries([], true, true, true);
      assert.deepEqual(analysis.sources, []);
      assert.deepEqual(analysis.exact.completedEntries, []);
      assert.ok(analysis.exact.diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")));
    }
    const projected = scanFile(file, { maxPaths: 8 });
    assert.equal(projected.coverage.baselineStatus, "incomplete");
    assert.ok(unscoped(projected).some(item => item.code === "analysis-budget"));
    assert.equal(scanFile(file).coverage.baselineStatus, "complete");
  });
});

test("only an attempt that exhausted just its path allowance falls back", () => {
  withProgram(supplied, program => {
    const entry = program.entries.find(id => id.endsWith("::post"))!;
    for (const cached of [false, true]) {
      // Step exhaustion is not a path-only failure: no source evidence replaces it.
      const starved = merkleFlow(program, "instructions", cached, 256, 2000).analyzeWithCorrelatedQueries([], true, true, true);
      assert.deepEqual(starved.sources, []);
      assert.ok(starved.exact.diagnostics.some(item => item.message.startsWith("Analysis step budget exhausted") || item.message.startsWith("Expression budget exhausted")));
      assert.deepEqual(starved.exact.completedEntries, []);
      // Without source queries the exhausted attempt is reported as before.
      const exact = merkleFlow(program, "instructions", cached, 8).analyzeWithCorrelatedQueries([], true, false, true);
      assert.deepEqual(exact.sources, []);
      assert.ok(exact.exact.diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")));
      assert.equal(exact.exact.completedEntries.includes(entry), false);
    }
  });
});

// Each element of a statically sized sequence loop re-expands the body's joined
// expressions, exactly like the counted form 0..4.
const slots = `import CompactStandardLibrary;
export ledger checks: Counter;
struct Slot { active: Boolean; fingerprint: Bytes<32>; }
witness slots(): Vector<4, Slot>;
export circuit check(): [] {
  const v = slots();
  assert(disclose(v[0].active), "registry cannot be empty");
  for (const slot of v) {
    assert(disclose(slot.active || slot.fingerprint == default<Bytes<32>>), "inactive slot must be zero");
  }
  checks.increment(1);
}
`;

test("sequence loops count their static length for source-query admission", () => {
  withProgram(slots, (program, file) => {
    const entry = program.entries.find(id => id.endsWith("::check"))!;
    let work = 0;
    assert.equal(sourceQueryCandidate(program, entry, 4, () => ++work <= 40000), true, "four elements reach a threshold of four");
    assert.equal(sourceQueryCandidate(program, entry, 5, () => true), false, "but not five");
    let tiny = 0;
    assert.equal(sourceQueryCandidate(program, entry, 4, () => ++tiny <= 2), false, "an exhausted scan never admits");
    // An unknown sequence size keeps the single-pass estimate.
    const body = program.functions.get(entry)!.declaration.body!;
    const loop = body.kind === "block" ? body.body.find(statement => statement.kind === "for") : undefined;
    assert.ok(loop?.kind === "for" && loop.sequence?.inferredType);
    const type = loop.sequence.inferredType;
    delete loop.sequence.inferredType;
    try { assert.equal(sourceQueryCandidate(program, entry, 2, () => true), false); }
    finally { loop.sequence.inferredType = type; }
    // The first slot is required active; the other three keep two alternatives each.
    for (const engine of engines) for (const cached of [false, true]) {
      const limited = new Dataflow(program, 40000, 4, 50000, engine, cached, cached).analyze();
      assert.ok(limited.diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")), `${engine}/${cached}`);
      assert.equal(new Dataflow(program, 40000, 8, 50000, engine, cached, cached).analyze().paths.length, 8, `${engine}/${cached}`);
      assert.equal(querySourceEntry(new Dataflow(program, 40000, 4, 50000, engine, cached, cached), entry).status, "covered", `${engine}/${cached}`);
    }
    // The admission threshold for four paths is three repeated joined expressions.
    const analysis = new Dataflow(program, 40000, 4, 50000).analyzeWithCorrelatedQueries([], true, true);
    assert.deepEqual(analysis.sources.map(source => source.entry), [entry], "admitted before any exact attempt");
    assert.deepEqual(analysis.exact.diagnostics, []);
    const projected = scanFile(file, { maxPaths: 4 }), exhaustive = scanFile(file);
    assert.equal(projected.coverage.baselineStatus, "complete", JSON.stringify(unscoped(projected)));
    assert.equal(exhaustive.coverage.baselineStatus, "complete", JSON.stringify(unscoped(exhaustive)));
    assert.ok(scanned(exhaustive, "spoofable-authorization").length > 0);
    const ordinary = exhaustive.findings.filter(item => item.detectorId === "spoofable-authorization");
    const selected = projected.findings.filter(item => item.detectorId === "spoofable-authorization");
    assert.equal(ordinary.length, 1);
    assert.equal(selected.length, 1);
    assert.deepEqual({ successfulReaches: ordinary[0].metadata?.successfulReaches, rawOnlyReaches: ordinary[0].metadata?.rawOnlyReaches,
      historyCoverage: ordinary[0].metadata?.historyCoverage }, { successfulReaches: 8, rawOnlyReaches: 8, historyCoverage: undefined });
    assert.deepEqual({ successfulReaches: selected[0].metadata?.successfulReaches, rawOnlyReaches: selected[0].metadata?.rawOnlyReaches,
      historyCoverage: selected[0].metadata?.historyCoverage }, { successfulReaches: 2, rawOnlyReaches: 2, historyCoverage: "shared-source-query-with-ordinary-witnesses" });
    // Reach counts describe retained ordinary witnesses, not exhaustive histories.
    // Explicitly expect these three differences and compare every other field.
    assert.deepEqual(selected[0], { ...ordinary[0], metadata: { ...ordinary[0].metadata,
      successfulReaches: 2, rawOnlyReaches: 2, historyCoverage: "shared-source-query-with-ordinary-witnesses" } });
  });
});

test("path fallback never clears an unsupported sibling route", () => {
  const mixed = supplied.replace("export ledger used:", "contract Peer { circuit notify(): []; }\nexport ledger peer: Peer;\nexport ledger used:")
    .replace("export circuit post(c:", "export circuit post(external: Boolean, c:")
    .replace("  const sk = secretKey();", "  if (disclose(external)) { peer.notify(); }\n  const sk = secretKey();");
  withProgram(mixed, program => {
    for (const cached of [false, true]) {
      const analysis = merkleFlow(program, "instructions", cached, 8).analyzeWithCorrelatedQueries([], true, true, true);
      assert.deepEqual(analysis.sources, []);
      assert.deepEqual(analysis.exact.completedEntries, []);
      assert.ok(analysis.exact.diagnostics.some(item => item.code === "unsupported-contract-call"));
      assert.ok(analysis.exact.diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")));
    }
  });
});

test("a path-exhausted attempt cannot spend fresh values or steps on its fallback", () => {
  withProgram(supplied, program => {
    for (const cached of [false, true]) {
      const exhausted = merkleFlow(program, "instructions", cached, 8).analyze();
      assert.ok(exhausted.diagnostics.some(item => item.message.startsWith("Abstract path budget exhausted")));
      // Leave only one value/step beyond the already charged ordinary attempt.
      // The conservative view and its ordinary witnesses need their own work.
      for (const [steps, values] of [[40000, exhausted.metrics.abstractValues + 1], [exhausted.metrics.steps + 1, 50000]]) {
        const analysis = merkleFlow(program, "instructions", cached, 8, steps, values).analyzeWithCorrelatedQueries([], true, true, true);
        assert.deepEqual(analysis.sources, [], `cached=${cached}, steps=${steps}, values=${values}`);
        assert.deepEqual(analysis.exact.completedEntries, []);
        assert.ok(analysis.exact.diagnostics.some(item => item.code === "analysis-budget" || item.code === "value-budget"));
      }
    }
  });
});

// The ordinary membership suite already covers changed tree revisions and
// wildcard receiver snapshots. Here repeated calls of one digest witness add
// the source-certificate boundary: equal declaration/site classes cannot supply
// exact enforcement for a different invocation.
const repeatedDigests = `import CompactStandardLibrary;
export ledger roots: Map<Field, MerkleTree<2, Field>>;
export ledger accepted: Field;
witness digest(): MerkleTreeDigest;
witness slots(): Vector<4, Boolean>;
export circuit post(key: Field, mutate: Boolean): [] {
  const flags = slots();
  for (const flag of flags) { if (disclose(flag)) { assert(key != (0 as Field), "optional"); } }
  const first = digest();
  const second = digest();
  assert(roots.lookup(disclose(key)).checkRoot(disclose(first)), "first digest only");
  if (disclose(mutate)) { roots.lookup(1 as Field).insert(7 as Field); }
  accepted = disclose(second.field);
}
`;

test("source certification cannot borrow a wildcard-tree check across digest invocations", () => {
  withProgram(repeatedDigests, program => {
    const entry = program.entries.find(id => id.endsWith("::post"))!;
    const oracle = merkleFlow(program, "instructions", false).analyze();
    assert.deepEqual(oracle.diagnostics, []);
    const expected = signatures(rule.run(oracle));
    assert.equal(expected.length, 1, "the second digest remains unchecked");
    for (const engine of engines) for (const cached of [false, true]) {
      const exact = merkleFlow(program, engine, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.deepEqual(signatures(rule.run(exact)), expected);
      const query = querySourceEntry(merkleFlow(program, engine, cached, 8), entry);
      // Refusal is conservative; covered evidence must reproduce complete objects.
      if (query.status === "covered") {
        const facts: AnalysisFacts = { ...exact, paths: [], completedEntries: [], sourceQueries: [query.evidence], diagnostics: [] };
        assert.deepEqual(signatures(rule.run(facts)), expected);
        assert.deepEqual(facts.diagnostics, []);
      } else assert.ok(query.reason.length > 0);
    }
  });
});
