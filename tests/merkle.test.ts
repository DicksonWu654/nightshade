import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles, semanticPaths } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, incomplete = false): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      if (!incomplete) { assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries); }
      check(facts);
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
}

test("unchanged Merkle roots correlate repeated guards and reject distinct concrete roots", () => {
  compare(`ledger tree: MerkleTree<2,Field>;
circuit check(root: MerkleTreeDigest): Boolean { return tree.checkRoot(root); }
export circuit repeated(root: MerkleTreeDigest): [] {
  assert(check(disclose(root)),"membership"); assert(check(disclose(root)),"same root");
}
export circuit contradictory(): [] {
  assert(check(MerkleTreeDigest { field: 0 as Field }),"zero");
  assert(check(MerkleTreeDigest { field: 1 as Field }),"one");
}`, facts => {
    assert.equal(facts.paths.length, 1);
    assert.ok(facts.paths[0].entry.endsWith("repeated"));
    assert.equal(facts.failedAssertions.length, 1);
    assert.equal(facts.failedAssertions[0].message, '"one"');
  });
});

test("historical root membership survives insertions while negative answers become unknown", () => {
  compare(`ledger tree: HistoricMerkleTree<2,Field>;
export circuit entry(root: MerkleTreeDigest,leaf: Field): Boolean {
  const r = disclose(root);
  const present = tree.checkRoot(r);
  tree.insert(disclose(leaf));
  if (present) { return tree.checkRoot(r); }
  return tree.checkRoot(r);
}`, facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(facts.paths.map(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.constant).sort(), ["true",undefined].sort());
    assert.ok(facts.paths.every(path => path.writes.length === 1));
  });
});

test("Merkle indexed writes fill the final slot, replacement stays full, and reset frees capacity", () => {
  compare(`ledger tree: MerkleTree<2,Field>;
ledger history: HistoricMerkleTree<2,Field>;
export circuit entry(): [] {
  tree.resetToDefault(); history.resetToDefault();
  assert(!tree.isFull(),"empty");
  tree.insertIndex(7 as Field,3); history.insertHashIndex(default<Bytes<32>>,3);
  assert(tree.isFull(),"last slot"); assert(history.isFull(),"last historic slot");
  tree.insertIndexDefault(1); history.resetHistory();
  assert(tree.isFull(),"replacement cannot free the first-free index");
  assert(history.isFull(),"history reset retains capacity state");
  tree.resetToDefault(); assert(!tree.isFull(),"reset");
  for (const i of 0..4) { tree.insert(i as Field); }
  assert(tree.isFull(),"sequentially filled");
}
export circuit overflow(): [] { tree.resetToDefault(); tree.insertIndex(7 as Field,4); }
export circuit appendToFull(): [] { tree.resetToDefault(); tree.insertIndex(7 as Field,3); tree.insert(8 as Field); }
export circuit unknownInitialOverflow(): [] { for (const i of 0..5) { tree.insert(i as Field); } }
`, facts => {
    assert.equal(facts.paths.length, 1);
    assert.ok(facts.paths[0].entry.endsWith("entry"));
    assert.deepEqual(facts.failedAssertions, []);
  });
});

test("tree facts survive sibling writes and are invalidated by ancestor replacement and history reset", () => {
  compare(`ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit entry(root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  assert(trees.lookup(1 as Field).checkRoot(r),"old root");
  trees.lookup(2 as Field).insert(7 as Field);
  assert(trees.lookup(1 as Field).checkRoot(r),"sibling tree unchanged");
  trees.insertDefault(1 as Field);
  return trees.lookup(1 as Field).checkRoot(r);
}
export circuit history(root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  assert(trees.lookup(1 as Field).checkRoot(r),"past root");
  trees.lookup(1 as Field).resetHistory();
  return trees.lookup(1 as Field).checkRoot(r);
}`, facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.failedAssertions, []);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
  });
});

test("retained historical root queries exhaust an explicit bounded domain", () => {
  compare(`ledger tree: HistoricMerkleTree<2,Field>;
export circuit entry(): [] {
  for (const i of 0..256) { assert(tree.checkRoot(MerkleTreeDigest { field: i as Field }),"past root"); }
  assert(tree.checkRoot(MerkleTreeDigest { field: 256 as Field }),"one more root");
}`, facts => {
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "merkle-budget"));
    assert.deepEqual(facts.completedEntries, []);
  },true);
});


test("saved capacity queries cannot admit full-tree appends and saved root checks cannot cross history reset", () => {
  compare(`ledger tree: HistoricMerkleTree<2,Field>;
export circuit append(leaf: Field): Boolean {
  const before = tree.isFull(); tree.insert(disclose(leaf)); return before;
}
export circuit reset(root: MerkleTreeDigest): Boolean {
  const r = disclose(root); const before = tree.checkRoot(r);
  tree.resetHistory();
  if (before) { return tree.checkRoot(r); }
  return tree.checkRoot(r);
}`, facts => {
    assert.equal(facts.paths.length, 3);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, path.entry.endsWith("append") ? "false" : undefined);
  });
});

test("a sibling write cannot make two distinct concrete roots valid for an ordinary tree", () => {
  compare(`ledger trees: Map<Field,MerkleTree<2,Field>>;
export circuit entry(): [] {
  assert(trees.lookup(1 as Field).checkRoot(MerkleTreeDigest { field: 0 as Field }),"zero");
  trees.lookup(2 as Field).insert(7 as Field);
  assert(trees.lookup(1 as Field).checkRoot(MerkleTreeDigest { field: 1 as Field }),"one");
}`, facts => {
    assert.equal(facts.paths.length, 0);
    assert.equal(facts.failedAssertions.length, 1);
  });
});

test("Merkle mutations invalidate root proofs for possible alias receivers", () => {
  for (const [type, operation] of [["MerkleTree", "insert(7 as Field)"], ["HistoricMerkleTree", "resetHistory()"]]) {
    for (const [first, second] of [["1 as Field", "disclose(key)"], ["disclose(key)", "1 as Field"]]) {
      compare(`ledger trees: Map<Field,${type}<2,Field>>;
export circuit entry(key: Field, root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  assert(trees.lookup(${first}).checkRoot(r), "original root");
  trees.lookup(${second}).${operation};
  return trees.lookup(${first}).checkRoot(r);
}`, facts => {
        assert.equal(facts.paths.length, 1);
        assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
      });
    }
  }
});

test("indexed Merkle insertion invalidates possible alias capacity facts", () => compare(`
ledger trees: Map<Field,MerkleTree<2,Field>>;
export circuit entry(key: Field): Boolean {
  trees.insertDefault(1 as Field);
  trees.lookup(disclose(key)).insertIndex(7 as Field, 3);
  return trees.lookup(1 as Field).isFull();
}`, facts => {
  assert.equal(facts.paths.length, 1);
  assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
}));

test("saved tree queries survive sibling writes and capacity queries survive history reset", () => {
  compare(`ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit capacity(): Boolean {
  const before = trees.lookup(1 as Field).isFull();
  trees.lookup(2 as Field).insert(7 as Field);
  trees.lookup(1 as Field).resetHistory();
  trees.lookup(1 as Field).insert(8 as Field);
  if (before) { return false; } return true;
}
export circuit membership(root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  const before = trees.lookup(1 as Field).checkRoot(r);
  trees.lookup(2 as Field).insert(7 as Field);
  if (!before) { return !trees.lookup(1 as Field).checkRoot(r); }
  return true;
}`, facts => {
    assert.equal(facts.paths.length, 3);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
  });
});

test("a successful append refutes earlier full observations across indexed writes", () => {
  compare(`ledger tree: MerkleTree<2,Field>;
export circuit append(index: Uint<64>): Boolean {
  const before = tree.isFull();
  tree.insertIndex(7 as Field, disclose(index));
  tree.insert(8 as Field);
  if (before) { return false; } return true;
}
export circuit snapshot(index: Uint<64>): Boolean {
  const before = tree.isFull();
  tree.insertIndex(7 as Field, disclose(index));
  tree.insert(8 as Field);
  return before;
}
export circuit monotonic(index: Uint<64>): Boolean {
  const before = tree.isFull();
  tree.insertIndex(7 as Field, disclose(index));
  if (before) { return tree.isFull(); } return true;
}
export circuit replacement(): Boolean {
  const before = tree.isFull();
  tree.insertIndex(7 as Field, 1);
  if (before) { return tree.isFull(); } return !tree.isFull();
}`, facts => {
    assert.equal(facts.paths.length, 6);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, path.entry.endsWith("snapshot") ? "false" : "true");
  });
});

test("saved capacity observations remain monotonic in either later assumption order", () => {
  for (const reverse of [false, true]) compare(`ledger tree: MerkleTree<2,Field>;
export circuit entry(index: Uint<64>): Boolean {
  const first = tree.isFull();
  tree.insertIndex(7 as Field, disclose(index));
  const second = tree.isFull();
  tree.insertIndex(8 as Field, disclose(index));
  ${reverse ? "if (!second) { if (first) { return false; } }" : "if (first) { if (!second) { return false; } }"}
  return true;
}`, facts => {
    assert.equal(facts.paths.length, 2);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
  });
});

test("saved historical membership is monotonic while ordinary roots can change", () => {
  for (const type of ["MerkleTree", "HistoricMerkleTree"]) for (const reverse of [false, true]) compare(`ledger tree: ${type}<2,Field>;
export circuit entry(root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  const first = tree.checkRoot(r);
  tree.insertIndex(7 as Field, 0);
  const second = tree.checkRoot(r);
  tree.insertIndex(8 as Field, 0);
  ${reverse ? "if (!second) { if (first) { return false; } }" : "if (first) { if (!second) { return false; } }"}
  return true;
}`, facts => {
    const historic = type === "HistoricMerkleTree";
    assert.equal(facts.paths.length, historic ? 2 : 3);
    const constants = facts.paths.map(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.constant);
    assert.equal(constants.includes("false"), !historic);
  });
});

test("each wildcard tree query is immutable without equating separate observations", () => {
  compare(`ledger trees: Map<Field,MerkleTree<2,Field>>;
export circuit saved(key: Field, root: MerkleTreeDigest): Boolean {
  const before = trees.lookup(disclose(key)).isFull();
  const member = trees.lookup(disclose(key)).checkRoot(disclose(root));
  if (before) { if (!before) { return false; } }
  if (member == true) { if (member == false) { return false; } }
  return true;
}
export circuit separate(first: Field, second: Field): Boolean {
  const a = trees.lookup(disclose(first)).isFull();
  const b = trees.lookup(disclose(second)).isFull();
  if (a) { return b; } return b;
}`, facts => {
    const saved = facts.paths.filter(path => path.entry.endsWith("saved"));
    assert.equal(saved.length, 4);
    for (const path of saved) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
    const separate = facts.paths.filter(path => path.entry.endsWith("separate"));
    assert.equal(separate.length, 2);
    for (const path of separate) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
  });
});

test("tree reset erases current payload provenance while preserving writes, selection and control", () => {
  for (const type of ["MerkleTree", "HistoricMerkleTree"]) compare(`ledger tree: ${type}<2,Field>;
ledger trees: Map<Field,${type}<2,Field>>;
export circuit reset(leaf: Field, root: MerkleTreeDigest): Boolean {
  tree.insert(disclose(leaf)); tree.resetToDefault();
  return tree.checkRoot(disclose(root));
}
export circuit controlledReset(leaf: Field, root: MerkleTreeDigest, flag: Boolean, key: Field): Boolean {
  trees.lookup(1 as Field).insert(disclose(leaf));
  const k = disclose(key);
  assert(k == (1 as Field), "known selection");
  if (disclose(flag)) {
    trees.lookup(k).resetToDefault();
    return trees.lookup(1 as Field).checkRoot(disclose(root));
  }
  return trees.lookup(1 as Field).checkRoot(disclose(root));
}`, facts => {
    assert.equal(facts.paths.length, 3);
    for (const path of facts.paths) {
      assert.ok(path.writes[0].after.flows.some(flow => flow.source.name === "leaf"));
      assert.ok(path.sinks.some(sink => sink.kind === "ledger-operation" && sink.value.flows.some(flow => flow.source.name === "leaf")));
      const result = path.sinks.find(sink => sink.kind === "exported-return")!.value;
      const reset = path.writes.length === 2;
      assert.equal(result.flows.some(flow => flow.source.name === "leaf"), !reset);
      assert.ok(result.flows.some(flow => flow.source.name === "root"));
      if (reset) assert.equal(path.writes[1].after.flows.some(flow => flow.source.name === "leaf"), false);
      if (reset && path.entry.endsWith("controlledReset")) {
        for (const name of ["flag", "key"]) {
          assert.ok(result.flows.some(flow => flow.source.name === name));
          assert.ok(path.writes[1].after.flows.some(flow => flow.source.name === name));
        }
      }
    }
  });
});

test("alias writes and ancestor replacement cannot refine changed trees with saved queries", () => {
  compare(`ledger trees: Map<Field,HistoricMerkleTree<2,Field>>;
export circuit aliased(key: Field, root: MerkleTreeDigest): Boolean {
  const r = disclose(root);
  const before = trees.lookup(1 as Field).checkRoot(r);
  trees.lookup(disclose(key)).resetHistory();
  if (before) { return trees.lookup(1 as Field).checkRoot(r); }
  return trees.lookup(1 as Field).checkRoot(r);
}
export circuit replaced(): Boolean {
  const before = trees.lookup(1 as Field).isFull();
  trees.insertDefault(1 as Field);
  trees.lookup(1 as Field).insert(8 as Field);
  return before;
}`, facts => {
    assert.equal(facts.paths.length, 3);
    for (const path of facts.paths) assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
  });
});
