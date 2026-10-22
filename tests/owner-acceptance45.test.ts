import test from "node:test";
import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { predicateEvidence } from "../src/dataflow/predicates.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const root = resolve("tests/corpus/drafts/coverage45/owner-acceptance");

function compare(name: string, check: (facts: AnalysisFacts) => void): void {
  const file = resolve(root, name);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const program = new Program(file, [], dirname(file), undefined, 3);
  for (const engine of ["instructions", "expressions"] as const) {
    let previous: AnalysisFacts | undefined;
    for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all").analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      if (previous) assert.deepEqual(facts.paths, previous.paths);
      previous = facts;
    }
  }
}

function enforcedPreimages(facts: AnalysisFacts, path: AnalysisFacts["paths"][number]) {
  const evidence = predicateEvidence(path, 100000);
  assert.equal(evidence.complete, true);
  return evidence.equalities.flatMap(({ equality, predicate }) => {
    if (!equality.equals) return [];
    return [[equality.left, equality.right], [equality.right, equality.left]].flatMap(([input, trusted]) => {
      const source = input.directHash?.source;
      return source && trusted.preexistingLedger?.size
        ? [{ witness: source.name, ledgers: [...trusted.preexistingLedger].map(id => facts.program.symbols.get(id)!.name),
          writesBefore: predicate.writesBefore }]
        : [];
    });
  });
}

test("Owner acceptance proposal leaves active authority untouched and activation enforces both preimages before its write", () => {
  compare("pending-owner-acceptance.compact", facts => {
    const names = (path: AnalysisFacts["paths"][number]) => path.writes.map(write => facts.program.symbols.get(write.ledger)!.name);
    const proposals = facts.paths.filter(path => facts.program.symbols.get(path.entry)!.name === "proposeOwnership");
    const activations = facts.paths.filter(path => facts.program.symbols.get(path.entry)!.name === "acceptOwnership");
    assert.equal(proposals.length, 1);
    assert.equal(activations.length, 1);
    assert.deepEqual(names(proposals[0]), ["pendingOwner", "hasPendingOwner"]);
    assert.deepEqual(enforcedPreimages(facts, proposals[0]), [
      { witness: "currentOwnerSecret", ledgers: ["activeOwner"], writesBefore: 0 },
    ]);
    assert.deepEqual(names(activations[0]), ["activeOwner", "pendingOwner", "hasPendingOwner"]);
    assert.deepEqual(enforcedPreimages(facts, activations[0]), [
      { witness: "currentOwnerSecret", ledgers: ["activeOwner"], writesBefore: 0 },
      { witness: "recipientSecret", ledgers: ["pendingOwner"], writesBefore: 0 },
    ]);
    const activation = activations[0];
    assert.equal(activation.writes[0].after.region?.root, activation.writes[1].ledger);
    assert.equal(activation.writes[1].after.constant, "0".repeat(64));
    assert.equal(activation.writes[2].after.constant, "false");
    assert.ok(activation.predicates!.some(predicate => predicate.truth
      && predicate.writesBefore === 0
      && [...predicate.value.preexistingLedger ?? []].some(id => facts.program.symbols.get(id)!.name === "hasPendingOwner")));
  });
});

test("Owner acceptance direct replacement lacks recipient proof while precommitted recovery checks a private preimage", () => {
  compare("direct-active-replacement.compact", facts => {
    const path = facts.paths.find(path => facts.program.symbols.get(path.entry)!.name === "transferOwnership")!;
    assert.equal(path.writes.length, 1);
    assert.equal(facts.program.symbols.get(path.writes[0].ledger)!.name, "activeOwner");
    assert.deepEqual(enforcedPreimages(facts, path), [
      { witness: "currentOwnerSecret", ledgers: ["activeOwner"], writesBefore: 0 },
    ]);
  });
  compare("precommitted-recovery-lookalike.compact", facts => {
    const path = facts.paths.find(path => facts.program.symbols.get(path.entry)!.name === "recoveryAction")!;
    assert.deepEqual(path.writes, []);
    assert.deepEqual(enforcedPreimages(facts, path), [
      { witness: "recoverySecret", ledgers: ["activeOwner"], writesBefore: 0 },
    ]);
  });
});
