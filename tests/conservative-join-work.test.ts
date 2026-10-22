import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { querySourceEntry } from "../src/dataflow/source-queries.js";
import { withFiles } from "./helpers.js";
import { dataflowBeforeB1 } from "./fixtures/dataflow-before-b1.js";

// A sorting network over range-checked witness values. Every conservative join
// carries the same retained bounds and pinned truths; nested ternary joins
// re-materialize them, so the next join sees equal facts in different objects.
const source = `import CompactStandardLibrary;
export ledger best: Uint<16>;
witness hand(): Vector<5, Uint<16>>;
witness authorized(): Boolean;
witness limits(): Vector<24, Uint<16>>;
circuit cx(a: Uint<16>, b: Uint<16>): Vector<2, Uint<16>> { return a >= b ? [a, b] : [b, a]; }
circuit sort5(v: Vector<5, Uint<16>>): Vector<5, Uint<16>> {
  const p0 = cx(v[0], v[1]); const p1 = cx(p0[1], v[2]); const p2 = cx(p1[1], v[3]); const p3 = cx(p2[1], v[4]);
  const q0 = cx(p0[0], p1[0]); const q1 = cx(q0[1], p2[0]); const q2 = cx(q1[1], p3[0]);
  const r0 = cx(q0[0], q1[0]); const r1 = cx(r0[1], q2[0]); const s0 = cx(r0[0], r1[0]);
  return [s0[0], s0[1], r1[1], q2[1], p3[1]];
}
circuit bucket(key: Uint<16>): Uint<16> { return key >= 64 ? 4 : key >= 48 ? 3 : key >= 32 ? 2 : 1; }
export circuit rank(): [] {
  assert(authorized(), "authorization");
  const v = hand();
  for (const i of 0..5) { assert(v[i] < 100, "range"); }
  const w = limits();
  for (const i of 0..24) { assert(w[i] < 1000, "limit"); }
  const s = sort5(v);
  best = disclose(sort5([bucket(s[0]), bucket(s[1]), bucket(s[2]), bucket(s[3]), bucket(s[4])])[0]);
}
`;

test("conservative joins reuse facts retained by both inputs without changing the source query", () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), entry = program.entries[0];
    for (const engine of ["instructions", "expressions"] as const) {
      const evidence: unknown[] = [];
      for (const cache of [false, true]) {
        const view = new Dataflow(program, 40000, 256, 50000, engine, cache, cache).conservativeSourceView(entry);
        assert.equal(view.status, "available", `${engine}: ${JSON.stringify(view.diagnostics)}`);
        // Repeating implication queries for shared bounds and materializing
        // equality chains among pinned truths needed about 57k steps here.
        assert.ok(view.work.steps < 30000, `${engine}: ${view.work.steps}`);
        const query = querySourceEntry(new Dataflow(program, 40000, 256, 50000, engine, cache, cache), entry);
        assert.equal(query.status, "covered", `${engine}: ${query.status === "incomplete" ? query.reason : ""}`);
        if (query.status === "covered") evidence.push({ paths: query.evidence.paths.length, raw: [...query.evidence.rawOnlyEffects].sort(),
          guards: [...query.evidence.requiredGuards].map(([effect, guards]) => [effect, [...guards].sort()]).sort() });
      }
      assert.deepEqual(evidence[0], evidence[1], engine);
    }
    const signatures = (result: ReturnType<typeof scanFile>) => result.findings.map(finding => ({ detector: finding.detectorId, location: finding.location,
      fingerprint: finding.fingerprint, message: finding.message, effects: finding.metadata.affectedEffects, soleGate: finding.metadata.soleGate }))
      .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
    const defaults = scanFile(file), raised = scanFile(file, { maxSteps: 400000 });
    assert.equal(defaults.status, "complete", JSON.stringify(defaults.diagnostics));
    assert.equal(raised.status, "complete", JSON.stringify(raised.diagnostics));
    assert.deepEqual(signatures(defaults), signatures(raised));
    assert.ok(defaults.findings.some(finding => finding.detectorId === "spoofable-authorization"));
  });
});

test("prior B1 join agrees on full source views, selected evidence and digest/Either certificates", async () => {
  const Oracle = (await dataflowBeforeB1()).Dataflow;
  const certificateSource = `import CompactStandardLibrary;
export ledger stored: Bytes<32>;
export circuit active(flag: Boolean, a: Uint<8>, b: Uint<8>, payload: Bytes<32>): [] {
  assert(a < 100, "bound"); assert(b == 5, "pinned");
  const n = flag ? b : b;
  assert(n == 5, "retained");
  const selected = right<Bytes<32>, Bytes<32>>(payload);
  stored = disclose(selected.right);
}
export circuit candidate(flag: Boolean, a: Uint<8>, b: Uint<8>): [] {
  assert(a < 100, "bound"); assert(b == 5, "pinned");
  const n = flag ? b : b;
  stored = disclose(persistentHash<Uint<8>>(a));
}
export circuit inactive(flag: Boolean, payload: Bytes<32>): [] {
  const selected = flag ? right<Bytes<32>, Bytes<32>>(payload) : right<Bytes<32>, Bytes<32>>(payload);
  stored = disclose(selected.left);
}
`;
  for (const ownedSource of [source, certificateSource]) withFiles({ "main.compact": ownedSource }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    // Both implementations receive the same allowance. The prior join needs
    // more than the ordinary 40k for rank; this comparison measures semantics.
    const allowance = 400000;
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) for (const entry of program.entries) {
      const label = `${entry}/${engine}/${cache}`;
      const current = new Dataflow(program, allowance, 256, 50000, engine, cache, cache);
      const prior = new Oracle(program, allowance, 256, 50000, engine, cache, cache);
      const { work: currentWork, ...currentView } = current.conservativeSourceView(entry);
      const { work: priorWork, ...priorView } = prior.conservativeSourceView(entry);
      assert.equal(currentView.status, "available", label);
      assert.equal(priorView.status, "available", label);
      assert.ok(currentWork.joins > 0, `fixture must exercise joins: ${label}`);
      // Exclude only top-level work counters. Nested user fields, traces,
      // histories, assertions, choices and all current values remain intact.
      assert.deepEqual(currentView, priorView, label);
      const { steps: currentSteps, values: currentValues, sources: currentSources, ...currentQuery } = querySourceEntry(current, entry);
      const { steps: priorSteps, values: priorValues, sources: priorSources, ...priorQuery } = querySourceEntry(prior, entry);
      assert.deepEqual(currentQuery, priorQuery, `full selected evidence: ${label}`);
      if (ownedSource === source) {
        assert.equal(currentQuery.status, "covered", label);
        assert.ok(currentWork.steps < priorWork.steps, `removed work: ${label}`);
      }
      for (const kind of ["digest", "either"] as const) {
        const { work: currentCertificateWork, ...currentCertificate } = current.conservativeRuleCertificate(entry, kind);
        const { work: priorCertificateWork, ...priorCertificate } = prior.conservativeRuleCertificate(entry, kind);
        assert.notEqual(currentCertificate.status, "incomplete", `${kind}/${label}`);
        assert.deepEqual(currentCertificate, priorCertificate, `${kind}/${label}`);
        if (entry.endsWith("::candidate") && kind === "digest" || entry.endsWith("::inactive") && kind === "either")
          assert.equal(currentCertificate.status, "candidate", `${kind}/${label}`);
        if (entry.endsWith("::active")) assert.equal(currentCertificate.status, "absent", `${kind}/${label}`);
      }
    }
  });
});
