import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, Program, Dataflow } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const selected = ["merkle-membership-not-enforced", "nullifier-check-without-insert", "merkle-leaf-binding-review"];

test("owned bounded Merkle insert dedupe gap: compiler acceptance and selected-rule miss", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-merkle-insert-dedupe-${variant}.compact`);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiled.valid, true, compiled.error);
    }
    const scan = scanFile(file, { detectors: selected });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings, []);
    assert.deepEqual(scan.diagnostics, []);
  }
});

test("cached, uncached instruction and reference facts lack immutable Merkle insert operands", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-merkle-insert-dedupe-${variant}.compact`);
    const program = new Program(file);
    for (const [engine, cached] of [["instructions", true], ["instructions", false], ["expressions", false]] as const) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
        "all", true, true, false, false).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const entry = program.entries.find(id => program.symbols.get(id)?.name === "grant")!;
      const paths = facts.paths.filter(path => path.entry === entry);
      assert.equal(paths.length, 1);
      const path = paths[0];
      const treeWrites = path.writes.filter(write => program.symbols.get(write.ledger)?.name === "capacityTree");
      assert.equal(treeWrites.length, variant === "lookalike" ? 0 : 1);
      // Merkle mutations are state writes; no RuntimeOperation retains exact
      // receiver + insertion operand. Aggregate provenance is not equality.
      assert.equal((path.operations ?? []).some(op => op.name === "insert" && op.args[0]?.region?.type.startsWith("MerkleTree")), false);
      if (variant === "corrected") {
        assert.equal((path.operations ?? []).filter(op => op.kind === "collection-query" && op.name === "member").length, 1);
        assert.equal((path.operations ?? []).filter(op => op.kind === "collection-write" && op.name === "insert").length, 1);
        assert.ok(path.predicates?.length);
      }
    }
  }
});
