import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program } from "../src/index.js";
import { immutableCollectionAddress, immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { MERKLE_INSERT_OBSERVER } from "../src/semantic/merkle-targets.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

function inspect(source: string, callback: (facts: ReturnType<Dataflow["analyze"]>) => void) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    for (const [engine, cached] of [["instructions", true], ["instructions", false], ["expressions", false]] as const) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
        "all", false, true, false, false, false, false, false, false, false, false,
        new Set([MERKLE_INSERT_OBSERVER])).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      callback(facts);
    }
  });
}

test("Merkle insert observations retain immutable operands, receiver and original effect order", () => {
  inspect(`import CompactStandardLibrary;
export ledger tree: MerkleTree<3, Field>;
export ledger memberSet: Set<Field>;
export ledger selected: Field;
export circuit probe(value: Field, other: Field): [] {
  selected = disclose(value);
  const saved = selected;
  assert(!memberSet.member(saved), "absent");
  tree.insert(saved);
  selected = disclose(other);
  tree.insert(selected);
  memberSet.insert(saved);
}`, facts => {
    const path = facts.paths[0];
    const inserts = path.operations!.filter(op => op.kind === "merkle-insert");
    assert.equal(inserts.length, 2);
    const keys = inserts.map(op => immutableOperandKey(op.args[1]).key);
    assert.ok(keys[0]); assert.ok(keys[1]); assert.notEqual(keys[0], keys[1]);
    assert.equal(immutableOperandKey(path.operations!.find(op => op.kind === "collection-query")!.args[1]).key, keys[0]);
    assert.deepEqual(inserts.map(op => op.writesBefore), [1, 3]);
    assert.deepEqual(inserts.map(op => op.operationsBefore), [1, 2]);
    assert.equal(immutableCollectionAddress(inserts[0].args[0]).key, immutableCollectionAddress(inserts[1].args[0]).key);
    assert.equal(path.writes.length, 5);
  });
});

test("native Merkle insertion kinds and exact dynamic receivers remain distinct", () => {
  inspect(`import CompactStandardLibrary;
export ledger trees: Map<Field, HistoricMerkleTree<3, Field>>;
export circuit probe(a: Field, b: Field, value: Field, hash: Bytes<32>): [] {
  trees.lookup(disclose(a)).insert(disclose(value));
  trees.lookup(disclose(b)).insertHash(disclose(hash));
  trees.lookup(disclose(a)).insertIndex(disclose(value), 0);
  trees.lookup(disclose(a)).insertHashIndex(disclose(hash), 1);
}`, facts => {
    const inserts = facts.paths[0].operations!.filter(op => op.kind === "merkle-insert");
    assert.deepEqual(inserts.map(op => op.name), ["insert", "insertHash", "insertIndex", "insertHashIndex"]);
    const receivers = inserts.map(op => immutableCollectionAddress(op.args[0]).key);
    assert.ok(receivers[0]); assert.ok(receivers[1]); assert.notEqual(receivers[0], receivers[1]);
    assert.equal(receivers[0], receivers[2]); assert.equal(receivers[0], receivers[3]);
    assert.equal(inserts[2].args[2].constant, "0"); assert.equal(inserts[3].args[2].constant, "1");
  });
});

test("exclusive insertion histories cannot be merged by common dependency provenance", () => {
  inspect(`import CompactStandardLibrary;
export ledger tree: MerkleTree<3, Field>;
export circuit probe(values: Vector<2, Field>, flag: Boolean): [] {
  if (disclose(flag)) { tree.insert(disclose(values[0])); }
  else { tree.insert(disclose(values[1])); }
}`, facts => {
    assert.equal(facts.paths.length, 2);
    const operands = facts.paths.map(path => path.operations!.filter(op => op.kind === "merkle-insert")[0].args[1]);
    assert.notEqual(immutableOperandKey(operands[0]).key, immutableOperandKey(operands[1]).key);
    assert.deepEqual(operands[0].flows.map(flow => flow.source.symbol), operands[1].flows.map(flow => flow.source.symbol));
    for (const path of facts.paths) assert.equal(path.operations!.filter(op => op.kind === "merkle-insert").length, 1);
  });
});
