import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { querySourceEntry } from "../src/dataflow/source-queries.js";
import { withFiles } from "./helpers.js";

// A trusted preimage check (a hashed private key compared with preexisting
// ledger data) can make a reach alternate-authenticated, so a source query cannot
// certify an unprotected reach of an effect with a required raw-witness guard.
// An effect without a required guard has no guard common to all of its reaches
// (optional guards need an ordinary counterexample), so the entry-wide
// authorization review cannot report that effect.
const source = `import CompactStandardLibrary;
export ledger attestor1: Bytes<32>;
export ledger attestor2: Bytes<32>;
export ledger round: Counter;
export ledger approvals: Map<Bytes<32>, Uint<64>>;
export ledger root: Bytes<32>;
export ledger yes: Counter;
export ledger no: Counter;
struct Step { sibling: Bytes<32>; goesLeft: Boolean; }
witness secret(): Bytes<32>;
witness authorized(): Boolean;
witness proof(): Vector<3, Step>;
circuit keyOf(sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "attestor:key"), sk]);
}
pure circuit node(lhs: Bytes<32>, rhs: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<3, Bytes<32>>>([pad(32, "attestor:node"), lhs, rhs]);
}
circuit countVotes(key: Bytes<32>): [] {
  const now = round.read();
  approvals.insert(disclose(key), now);
  const c1 = approvals.member(attestor1) && approvals.lookup(attestor1) == now;
  const c2 = approvals.member(attestor2) && approvals.lookup(attestor2) == now;
  if (disclose(((c1 ? 1 : 0) + (c2 ? 1 : 0)) as Uint<8> >= 2)) { round.increment(1); }
}
export circuit attest(newRoot: Bytes<32>): [] {
  const key = keyOf(secret());
  assert(disclose(key == attestor1) || disclose(key == attestor2), "attestor");
  countVotes(key);
  root = disclose(newRoot);
}
export circuit vote(support: Boolean): [] {
  const key = keyOf(secret());
  const top = fold((acc: Bytes<32>, step: Step): Bytes<32> => {
    const left = disclose(step.goesLeft) ? acc : step.sibling;
    const right = disclose(step.goesLeft) ? step.sibling : acc;
    return node(left, right);
  }, key, proof());
  assert(disclose(top == root), "membership");
  const creator = disclose(key == attestor1);
  const yesAdd = disclose(support && creator) ? 2 : 1;
  const noAdd = disclose(!support && creator) ? 2 : 1;
  if (disclose(support)) { yes.increment(yesAdd); } else { no.increment(noAdd); }
}
export circuit guarded(open: Boolean, newRoot: Bytes<32>): [] {
  assert(authorized(), "authorization");
  const key = keyOf(secret());
  assert(disclose(key == attestor1) || disclose(open), "attestor");
  countVotes(newRoot);
  root = disclose(newRoot);
}
`;

test("trusted preimage checks refuse source queries only for effects with a required raw-witness guard", () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    const entry = (name: string) => program.entries.find(item => item.endsWith(`::${name}`))!;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const label = `${engine}/${cached ? "cached" : "uncached"}`;
      // The ordinary interpreter is the oracle; eight paths cannot enumerate it.
      const exact = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, [], label);
      assert.deepEqual(exact.completedEntries, program.entries, label);
      const limited = new Dataflow(program, 40000, 8, 50000, engine, cached, cached).analyze();
      for (const name of ["attest", "vote", "guarded"]) assert.ok(!limited.completedEntries.includes(entry(name)), `${label}: ${name}`);
      // No raw-witness guard at all (alternative attestor keys), and only
      // optional raw-witness guards (proof direction bits) with a trusted root.
      for (const name of ["attest", "vote"]) {
        const query = querySourceEntry(new Dataflow(program, 40000, 8, 50000, engine, cached, cached), entry(name));
        assert.equal(query.status, "covered", `${label}: ${name}: ${query.status === "incomplete" ? query.reason : ""}`);
      }
      // A required raw-witness guard with a trusted preimage on some histories
      // keeps the refusal: the unkeyed history is unprotected in the oracle.
      const guarded = querySourceEntry(new Dataflow(program, 40000, 8, 50000, engine, cached, cached), entry("guarded"));
      assert.equal(guarded.status, "incomplete", label);
      assert.equal(guarded.status === "incomplete" && guarded.reason, "Selected history has a trusted preimage check", label);
    }
    const projected = scanFile(file, { maxPaths: 8 }), exact = scanFile(file);
    assert.equal(exact.coverage.baselineStatus, "complete", JSON.stringify(exact.diagnostics));
    assert.deepEqual(projected.coverage.completedEntries, [entry("attest"), entry("vote")]);
    const span = program.functions.get(entry("guarded"))!.declaration.span;
    const inGuarded = (location: { start: number; end: number }) => location.start >= span.start && location.end <= span.end;
    // The refused entry stays explicitly incomplete; it never becomes a clean scan.
    assert.ok(projected.diagnostics.some(issue => !issue.scope && issue.code === "analysis-budget" && inGuarded(issue.location)), JSON.stringify(projected.diagnostics));
    assert.ok(exact.findings.some(finding => finding.detectorId === "spoofable-authorization" && inGuarded(finding.location)));
    const signatures = (result: typeof exact) => result.findings.filter(finding => !inGuarded(finding.location))
      .map(finding => JSON.stringify(finding)).sort();
    assert.deepEqual(signatures(projected), signatures(exact));
  });
});


// Different effect sites preserve different universal guard obligations. The
// optional first effect cannot erase the required guard on the second one.
const mixedEffects = `import CompactStandardLibrary;
export ledger trusted: Bytes<32>;
export ledger optional: Counter;
export ledger required: Counter;
witness secret(): Bytes<32>;
witness authorized(): Boolean;
export circuit mixed(open: Boolean): [] {
  if (disclose(open)) { assert(authorized(), "optional gate"); }
  optional.increment(1);
  assert(authorized(), "required gate");
  const key = persistentHash<Bytes<32>>(secret());
  assert(disclose(key == trusted), "trusted preimage");
  required.increment(1);
}
`;

test("mixed effects retain the earlier unresolved preimage-binding refusal", () => {
  withFiles({ "main.compact": mixedEffects }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const entry = program.entries.find(id => id.endsWith("::mixed"))!;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const exact = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(exact.diagnostics, []);
      const query = querySourceEntry(new Dataflow(program, 40000, 8, 50000, engine, cached, cached), entry);
      assert.equal(query.status, "incomplete");
      // The direct hash equality creates a possible binding before per-effect
      // trusted-preimage certification. Refusing there is the stricter boundary;
      // the existing guarded fixture above isolates the later refusal instead.
      assert.equal(query.status === "incomplete" && query.reason, "Preimage binding alternatives require a dedicated query");
    }
  });
});
