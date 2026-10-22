import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { repeatedCallCandidate, sourceQueryCandidate, querySourceEntry } from "../src/dataflow/source-queries.js";
import { withFiles } from "./helpers.js";

// Exact interpretation re-expands a branching helper at every call site and fold
// element. Admission counts that multiplicity; the source query still certifies.
const source = `import CompactStandardLibrary;
export ledger first: Uint<8>;
export ledger second: Uint<8>;
export ledger third: Uint<8>;
witness authorized(): Boolean;
witness seed(): Field;
pure circuit accept(acc: Uint<8>, b: Uint<8>): Uint<8> { return acc != 0 ? acc : (b < 200 ? b : 0 as Uint<8>); }
pure circuit pick(v: Vector<2, Uint<8>>): Uint<8> { return fold(accept, 0 as Uint<8>, v); }
export circuit roll(): [] {
  assert(authorized(), "authorization");
  const v = persistentHash<Field>(seed()) as Vector<32, Uint<8>>;
  first = disclose(pick([v[0], v[1]]));
  second = disclose(pick([v[2], v[3]]));
  third = disclose(pick([v[4], v[5]]));
}
`;

test("repeated branching helpers are admitted to source queries with unchanged findings", () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    const entry = program.entries[0], threshold = Math.floor(Math.log2(8)) + 1;
    let work = 0, repeated = 0;
    assert.equal(sourceQueryCandidate(program, entry, threshold, () => ++work <= 40000, true), false);
    assert.equal(repeatedCallCandidate(program, entry, threshold, () => ++repeated <= 40000, true), true);
    // Exhausting the scan allowance never admits.
    let tiny = 0;
    assert.equal(repeatedCallCandidate(program, entry, threshold, () => ++tiny <= 3, true), false);
    for (const engine of ["instructions", "expressions"] as const) {
      assert.ok(new Dataflow(program, 40000, 8, 50000, engine).analyze().diagnostics.some(item => item.code === "analysis-budget"));
      assert.equal(querySourceEntry(new Dataflow(program, 40000, 8, 50000, engine), entry).status, "covered", engine);
    }
    const projected = scanFile(file, { maxPaths: 8 }), exact = scanFile(file);
    assert.equal(projected.status, "complete", JSON.stringify(projected.diagnostics));
    assert.equal(exact.status, "complete", JSON.stringify(exact.diagnostics));
    const signatures = (result: typeof exact) => result.findings.map(finding => ({ detector: finding.detectorId, location: finding.location,
      fingerprint: finding.fingerprint, message: finding.message, effects: finding.metadata.affectedEffects, soleGate: finding.metadata.soleGate }))
      .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
    assert.deepEqual(signatures(projected), signatures(exact));
    assert.ok(projected.findings.some(finding => finding.detectorId === "spoofable-authorization"));
  });
});
