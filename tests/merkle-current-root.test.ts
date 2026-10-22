import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
ledger tree: HistoricMerkleTree<2,Field>;
export ledger accepted: Field;
`;

function fixture(source: string, inspect: (facts: AnalysisFacts, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let expected: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all", true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      inspect(facts, file);
      const paths = semanticPaths(facts);
      expected ??= paths;
      assert.deepEqual(paths, expected);
    }
  });
}

function checks(facts: AnalysisFacts): { exclusive: boolean | undefined; revision: number; historyEpoch?: number }[] {
  assert.equal(facts.paths.length, 1);
  return facts.paths[0].operations!.filter(operation => operation.kind === "merkle-check")
    .map(operation => {
      const predicate = operation.result.merklePredicate;
      assert.ok(predicate);
      return { exclusive: predicate.exclusive, revision: predicate.revision, historyEpoch: predicate.historyEpoch };
    });
}

test("unknown historic storage does not become current-only through equal bookkeeping epochs", () => fixture(header + `
export circuit entry(): [] {
  assert(tree.checkRoot(MerkleTreeDigest { field: 0 as Field }), "first historical root");
  assert(tree.checkRoot(MerkleTreeDigest { field: 1 as Field }), "second historical root");
  accepted = 1 as Field;
}`, facts => {
  const observations = checks(facts);
  assert.equal(observations.length, 2);
  assert.ok(observations.every(item => item.exclusive === false && item.revision === item.historyEpoch));
  assert.equal(facts.failedAssertions.length, 0);
}));

test("cleared historic roots reject contradictory concrete membership and expose a default assertion finding", () => {
  for (const reset of ["tree.resetHistory();", "tree.resetToDefault();"]) {
    fixture(header + `
export circuit entry(): [] {
  ${reset}
  assert(tree.checkRoot(MerkleTreeDigest { field: 0 as Field }), "first current root");
  assert(tree.checkRoot(MerkleTreeDigest { field: 1 as Field }), "different current root");
  accepted = 1 as Field;
}`, (facts, file) => {
      assert.equal(facts.paths.length, 0);
      assert.equal(facts.failedAssertions.length, 1);
      const scan = scanFile(file, { detectors: ["impossible-assertion"] });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.equal(scan.findings.length, 1);
      assert.equal(scan.findings[0].location.line, 8);
    });
  }
});

test("cleared historic roots equate symbolic membership roots at the same snapshot", () => fixture(header + `
export circuit entry(first: MerkleTreeDigest, second: MerkleTreeDigest): [] {
  tree.resetHistory();
  assert(tree.checkRoot(disclose(first)),"first current root");
  assert(tree.checkRoot(disclose(second)),"second current root");
  assert(disclose(first.field) != disclose(second.field),"different roots");
  accepted = 1 as Field;
}`, facts => {
  assert.equal(facts.paths.length, 0);
  assert.equal(facts.failedAssertions.length, 1);
  assert.equal(facts.failedAssertions[0].location.line, 9);
}));

test("unknown historical storage does not equate distinct symbolic membership roots", () => fixture(header + `
export circuit entry(first: MerkleTreeDigest, second: MerkleTreeDigest): [] {
  assert(tree.checkRoot(disclose(first)),"first historical root");
  assert(tree.checkRoot(disclose(second)),"second historical root");
  assert(disclose(first.field) != disclose(second.field),"different roots");
  accepted = 1 as Field;
}`, facts => {
  assert.deepEqual(checks(facts).map(item => item.exclusive), [false, false]);
  assert.equal(facts.failedAssertions.length, 0);
}));

test("history reset certifies a fresh query without upgrading a captured earlier Boolean", () => fixture(header + `
export circuit entry(root: MerkleTreeDigest): [Boolean,Boolean] {
  const oldQuery = tree.checkRoot(disclose(root));
  tree.resetHistory();
  const freshQuery = tree.checkRoot(disclose(root));
  return [oldQuery,freshQuery];
}`, facts => {
  const observations = checks(facts);
  assert.deepEqual(observations.map(item => item.exclusive), [false, true]);
  assert.notEqual(observations[0].revision, observations[1].revision);
}));

test("every historic insertion forgets live exclusivity while retained Boolean snapshots keep their old proof", () => {
  for (const insertion of ["tree.insert(1 as Field);", "tree.insertHash(default<Bytes<32>>);",
    "tree.insertIndex(1 as Field,1);", "tree.insertHashIndex(default<Bytes<32>>,1);", "tree.insertIndexDefault(1);"]) {
    fixture(header + `
export circuit entry(root: MerkleTreeDigest): Boolean {
  tree.resetHistory();
  const oldQuery = tree.checkRoot(disclose(root));
  ${insertion}
  assert(oldQuery,"saved query");
  return tree.checkRoot(disclose(root));
}`, facts => {
      const observations = checks(facts);
      assert.deepEqual(observations.map(item => item.exclusive), [true, false]);
      assert.notEqual(observations[0].revision, observations[1].revision);
      const oldGuard = facts.paths[0].predicates!.find(predicate => predicate.value.merklePredicate?.exclusive);
      assert.ok(oldGuard?.truth);
      assert.equal(oldGuard.value.merklePredicate!.revision, observations[0].revision);
      assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
    });
  }
});

test("resetting after insertion establishes a new current-only snapshot", () => fixture(header + `
export circuit entry(root: MerkleTreeDigest): Boolean {
  tree.insert(1 as Field);
  tree.resetHistory();
  return tree.checkRoot(disclose(root));
}`, facts => assert.deepEqual(checks(facts).map(item => item.exclusive), [true])));

test("historical insertion can admit distinct roots again after a current-only segment", () => fixture(header + `
export circuit entry(): [] {
  tree.resetHistory();
  assert(tree.checkRoot(MerkleTreeDigest { field: 0 as Field }),"old current root");
  tree.insert(1 as Field);
  assert(tree.checkRoot(MerkleTreeDigest { field: 1 as Field }),"possible new root");
  accepted = 1 as Field;
}`, facts => assert.deepEqual(checks(facts).map(item => item.exclusive), [true, false])));

test("branch-local history clearing remains local to the actual histories", () => fixture(header + `
export circuit entry(clear: Boolean, root: MerkleTreeDigest): Boolean {
  if (disclose(clear)) { tree.resetHistory(); }
  return tree.checkRoot(disclose(root));
}`, facts => {
  assert.equal(facts.paths.length, 2);
  const observations = facts.paths.flatMap(path => path.operations!.filter(operation => operation.kind === "merkle-check"));
  assert.deepEqual(observations.map(operation => operation.result.merklePredicate!.exclusive).sort(), [false, true]);
}));

test("possible alias writes forget certificates and exact sibling writes preserve them", () => {
  for (const key of ["disclose(key)", "2 as Field"]) {
    fixture(`import CompactStandardLibrary;
ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit entry(key: Field, root: MerkleTreeDigest): [Boolean,Boolean] {
  trees.lookup(1 as Field).resetHistory();
  const before = trees.lookup(1 as Field).checkRoot(disclose(root));
  trees.lookup(${key}).insert(1 as Field);
  return [before,trees.lookup(1 as Field).checkRoot(disclose(root))];
}`, facts => {
      assert.deepEqual(checks(facts).map(item => item.exclusive), [true, key === "2 as Field"]);
    });
  }
});

test("a wildcard history reset cannot certify an unrelated concrete receiver", () => fixture(`import CompactStandardLibrary;
ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit entry(key: Field, root: MerkleTreeDigest): Boolean {
  trees.lookup(disclose(key)).resetHistory();
  return trees.lookup(1 as Field).checkRoot(disclose(root));
}`, facts => assert.deepEqual(checks(facts).map(item => item.exclusive), [false])));

test("explicit child defaults after parent reset or child replacement establish a new certificate", () => {
  for (const replacement of ["trees.resetToDefault(); trees.insertDefault(1 as Field);", "trees.insertDefault(1 as Field);"]) {
    fixture(`import CompactStandardLibrary;
ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit entry(root: MerkleTreeDigest): Boolean {
  trees.lookup(1 as Field).resetHistory();
  ${replacement}
  return trees.lookup(1 as Field).checkRoot(disclose(root));
}`, facts => assert.deepEqual(checks(facts).map(item => item.exclusive), [true]));
  }
});
