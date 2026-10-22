import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { lowEntropyHashDisclosure as rule } from "../src/detectors/small-domain-hash.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// Exact digest observation may join pure-fold callback alternatives whose values
// differ only in direct-digest input order (e.g. the standard-library Merkle
// path fold), behind the same elided-selector boundary as hash-order choices.
const header = `import CompactStandardLibrary;
export ledger root: Field;
export ledger digest: Bytes<32>;
witness path(): MerkleTreePath<4, Bytes<32>>;
`;

function withProgram(source: string, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file), file);
  });
}
// useFoldPartitions=false disables the join: the ordinary interpreter is the oracle.
function observe(program: Program, engine: "instructions" | "expressions", cached: boolean, joins = true, maxPaths = 256): AnalysisFacts {
  return new Dataflow(program, 40000, maxPaths, 50000, engine, cached, cached, "equivalent-states", false, joins, "witness", false, false, false, true, false, false, true).analyze();
}
const findings = (facts: AnalysisFacts) => JSON.stringify(rule.run(facts).map(item => [item.fingerprint, item.message, item.location]).sort());

test("permuted Merkle path fold alternatives join under digest observation and keep oracle findings", () => {
  withProgram(`export circuit prove(flag: Boolean): [] {
  const p = path();
  assert(disclose(merkleTreePathRoot<4, Bytes<32>>(p)).field == root, "root");
  digest = disclose(persistentHash<Boolean>(flag));
}
export circuit silent(): [] {
  const p = path();
  assert(disclose(merkleTreePathRoot<4, Bytes<32>>(p)).field == root, "root");
}`, (program, file) => {
    const oracle = observe(program, "instructions", false, false);
    assert.deepEqual(oracle.diagnostics, []);
    assert.equal(oracle.paths.length, 32, "2^4 ordinary callback histories per entry");
    const expected = findings(oracle);
    assert.equal(rule.run(oracle).length, 1);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.deepEqual(facts.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.paths.length, 2, "one joined history per entry");
      assert.equal(findings(facts), expected);
    }
    // Beyond the path allowance only the join completes; findings are unchanged.
    const limited = observe(program, "instructions", false, true, 8);
    assert.deepEqual(limited.diagnostics, []);
    assert.equal(findings(limited), expected);
    assert.ok(observe(program, "instructions", false, false, 8).diagnostics.some(item => item.code === "analysis-budget"));
    const scan = scanFile(file, { detectors: [rule.id], maxPaths: 8 });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
  });
});

test("a joined digest fold preserves the exact native hash input type", () => {
  withProgram(`circuit step(acc: Bytes<32>, choose: Boolean, sibling: Bytes<32>): Bytes<32> {
  if (choose) { return persistentHash<Vector<2, Bytes<32>>>([acc, sibling]); }
  else { return persistentHash<Vector<2, Bytes<32>>>([sibling, acc]); }
}
export circuit composed(choices: Vector<4, Boolean>, siblings: Vector<4, Bytes<32>>): [] {
  digest = disclose(fold(step, default<Bytes<32>>, choices, siblings));
}`, program => {
    const typed = (engine: "instructions" | "expressions", cached: boolean, joins: boolean) => new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, joins, "witness", false, false, false, false, false, false, true).analyze();
    const oracle = typed("instructions", false, false);
    assert.deepEqual(oracle.diagnostics, []); assert.equal(oracle.paths.length, 16);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = typed(engine, cached, true);
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.paths.length, 1);
      const digest = facts.paths[0].sinks.find(sink => sink.name === "digest")!.value.directDigest;
      assert.equal(digest?.primitive, "persistentHash");
      assert.equal(digest?.inputType, "Vector<2,Bytes<32>>");
    }
  });
});

test("pure-fold normalization cannot equate vector and tuple digest recipes", () => {
  withProgram(`circuit step(acc: Bytes<32>, choose: Boolean, sibling: Bytes<32>): Bytes<32> {
  if (choose) { return persistentHash<Vector<2, Bytes<32>>>([acc, sibling]); }
  else { return persistentHash<[Bytes<32>, Bytes<32>]>([sibling, acc]); }
}
export circuit distinctTypes(choices: Vector<4, Boolean>, siblings: Vector<4, Bytes<32>>): [] {
  digest = disclose(fold(step, default<Bytes<32>>, choices, siblings));
}`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
        "witness", false, false, false, false, false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.paths.length, 16, "different native hash input types retain ordinary histories");
      assert.deepEqual([...new Set(facts.paths.map(path => path.sinks.find(sink => sink.name === "digest")!.value.directDigest?.inputType))].sort(),
        ["Vector<2,Bytes<32>>", "[Bytes<32>,Bytes<32>]"].sort());
    }
  });
});

test("an elided Merkle selector reaching digest evidence or a relation keeps the observation incomplete", () => {
  withProgram(`export circuit published(): [] {
  const p = path();
  assert(disclose(merkleTreePathRoot<4, Bytes<32>>(p)).field == root, "root");
  digest = disclose(persistentHash<Boolean>(p.path[0].goes_left));
}
export circuit related(flag: Boolean): [] {
  const p = path();
  assert(disclose(merkleTreePathRoot<4, Bytes<32>>(p)).field == root, "root");
  assert(disclose(p.path[1].goes_left) == disclose(flag), "same");
  digest = disclose(persistentHash<Boolean>(flag));
}`, program => {
    // The oracle refines each selector to a constant on its own history: the
    // published selector digest is not reported, and the related flag is constant.
    const oracle = observe(program, "instructions", false, false);
    assert.deepEqual(oracle.diagnostics, []);
    assert.deepEqual(rule.run(oracle), []);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.ok(facts.diagnostics.some(item => item.code === "observation-compression-dependency"), `${engine}/${cached}`);
      assert.deepEqual(facts.completedEntries, [], `${engine}/${cached}`);
    }
  });
});

test("distinct callback digests keep ordinary fold histories", () => {
  withProgram(`circuit step(acc: Field, entry: MerkleTreePathEntry): Field {
  return entry.goes_left ? transientHash<Vector<2, Field>>([acc, entry.sibling.field]) : transientHash<Vector<2, Field>>([acc, acc]);
}
export circuit distinct(flag: Boolean): [] {
  const p = path();
  assert(disclose(fold(step, 0 as Field, p.path)) == root, "root");
  digest = disclose(persistentHash<Boolean>(flag));
}`, program => {
    const oracle = observe(program, "instructions", false, false);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, oracle.paths.length, "no join across different leaves");
      assert.equal(findings(facts), findings(oracle));
    }
  });
});
