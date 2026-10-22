import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { foldProvenance } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// The pure-fold join keeps only the common provenance prefix of its callback
// alternatives plus one choice marker. When every alternative still carries a
// marker created by an earlier iteration of the same join, the prefix before it
// is shared by reference and is taken directly. The per-step serialized
// comparison (shareMarkers=false) is the oracle: values, traces, diagnostics and
// findings must be identical; only the charged work may differ.
const source = (depth: number) => `import CompactStandardLibrary;
export ledger root: Field;
export ledger published: Field;
witness path(index: Uint<8>): MerkleTreePath<${depth}, Bytes<32>>;
witness secret(): Bytes<32>;
circuit member(index: Uint<8>): Field {
  const p = path(index);
  const digest = merkleTreePathRoot<${depth}, Bytes<32>>(p).field;
  assert(digest == root, "root");
  return digest;
}
export circuit prove(): [] {
  published = disclose(member(0) + member(1) + member(2));
}
export circuit keyed(): [] {
  const p = path(0);
  assert(p.leaf == persistentHash<Bytes<32>>(secret()), "leaf");
  published = disclose(merkleTreePathRoot<${depth}, Bytes<32>>(p).field);
}
`;

function withProgram(depth: number, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source(depth) }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file), file);
  });
}

function analyze(program: Program, engine: "instructions" | "expressions", cached: boolean, share: boolean, maxSteps = 40000): AnalysisFacts {
  foldProvenance.shareMarkers = share;
  try { return new Dataflow(program, maxSteps, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "witness").analyze(); }
  finally { foldProvenance.shareMarkers = true; }
}

// Paths, sinks and their flow traces, without work metrics.
const observable = (facts: AnalysisFacts) => JSON.stringify({ paths: facts.paths, diagnostics: facts.diagnostics, completed: facts.completedEntries },
  (_key, value) => value instanceof Set ? [...value] : value instanceof Map ? [...value] : value);

test("shared fold markers keep the exact provenance prefix of the per-step comparison", () => {
  withProgram(8, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const oracle = analyze(program, engine, cached, false);
      const facts = analyze(program, engine, cached, true);
      assert.deepEqual(oracle.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(facts.completedEntries, program.entries, `${engine}/${cached}`);
      assert.equal(observable(facts), observable(oracle), `${engine}/${cached}`);
      assert.ok(facts.metrics.steps < oracle.metrics.steps, `${engine}/${cached}: ${facts.metrics.steps} < ${oracle.metrics.steps}`);
      // Every flow of the published root keeps exactly one choice marker.
      const sink = facts.paths.find(path => path.entry.endsWith("::keyed"))!.sinks.find(item => item.name === "published")!;
      assert.ok(sink.value.flows.length > 0);
      for (const flow of sink.value.flows) {
        const markers = flow.trace.filter(step => step.kind === "fold-choice");
        assert.equal(markers.length, 1, JSON.stringify(flow.trace));
      }
    }
  });
});

test("a deep repeated Merkle fold completes within the ordinary budget only with shared markers", () => {
  withProgram(32, (program, file) => {
    const exhausted = analyze(program, "instructions", false, false);
    assert.ok(exhausted.diagnostics.some(item => item.code === "analysis-budget"), JSON.stringify(exhausted.diagnostics));
    // With a larger allowance the per-step oracle completes with the same observable result.
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const oracle = analyze(program, engine, cached, false, 400000);
      const facts = analyze(program, engine, cached, true);
      assert.deepEqual(oracle.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(facts.diagnostics, [], `${engine}/${cached}`);
      assert.deepEqual(facts.completedEntries, program.entries, `${engine}/${cached}`);
      assert.equal(observable(facts), observable(oracle), `${engine}/${cached}`);
    }
    const scan = scanFile(file);
    assert.equal(scan.coverage.baselineStatus, "complete", JSON.stringify(scan.diagnostics));
  });
});
