import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type CompilerVersion } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { identitySignatureKey as rule } from "../src/detectors/signature-key.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger count: Counter;
circuit verify(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean {
  return jubjubSchnorrVerify<1>(msg, sig, pk);
}
`;
function fixture(body: string, expected: string[], version: CompilerVersion = "0.34.0"): void {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.35.0" ? process.env.COMPACTC_035_TEST : version === "0.35.0-rc.1" ? process.env.COMPACTC_035_RC1_TEST : process.env.COMPACTC_TEST;
    if (compiler) {
      const compiled = validateWithCompiler(compiler, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, [], undefined, undefined, 2, version);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "witness", false, false, false, true, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], compilerVersion: version, experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(item => item.metadata.entry).sort(), [...expected].sort());
    }
  });
}

test("signature identity keys follow exact aliases, helpers, native zero and caller refinement", () => {
  fixture(`
export circuit direct(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const pk = default<JubjubPoint>;
  assert(verify(msg, sig, pk), "signature"); count.increment(1);
}
export circuit zero(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(verify(msg, sig, ecMulGenerator(0 as JubjubScalar)), "signature"); count.increment(1);
}
export circuit refined(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(pk == default<JubjubPoint>, "identity");
  assert(verify(msg, sig, pk), "signature"); count.increment(1);
}
export circuit corrected(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(pk != default<JubjubPoint>, "nonidentity");
  assert(verify(msg, sig, pk), "signature"); count.increment(1);
}
export circuit unknown(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify(msg, sig, pk), "signature"); count.increment(1);
}
`, ["direct", "zero", "refined"]);
});

test("signature calls retain distinct branch keys and drop histories rejected later", () => {
  fixture(`
export circuit branch(flag: Boolean, msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  if (disclose(flag)) { assert(verify(msg, sig, default<JubjubPoint>), "signature"); }
  else { assert(pk != default<JubjubPoint>, "nonidentity"); assert(verify(msg, sig, pk), "signature"); }
  count.increment(1);
}
export circuit rejected(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(verify(msg, sig, default<JubjubPoint>), "signature"); assert(false, "disabled");
}
export circuit repeated(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  for (const i of 0..2) { assert(verify(msg, sig, default<JubjubPoint>), "signature"); }
  count.increment(1);
}
`, ["branch", "repeated"]);
});

test("signature-key detection authenticates imported aliases and ignores a namesake circuit", () => {
  withFiles({
    "library.compact": `module library { import CompactStandardLibrary prefix CSL_; export circuit check(msg: Vector<1, Field>, sig: CSL_JubjubSchnorrSignature): Boolean { return CSL_jubjubSchnorrVerify<1>(msg, sig, default<CSL_JubjubPoint>); } }`,
    "main.compact": `import CompactStandardLibrary; import "library" prefix L_; export circuit entry(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): Boolean { return L_check(msg, sig); }`,
  }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiler.valid, true, compiler.error); }
    assert.equal(scanFile(file, { detectors: [rule.id] }).findings.length, 1);
  });
  fixture(`
module Checks { export circuit jubjubSchnorrVerify<#N>(msg: Vector<N, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean { return true; } }
import Checks prefix App_;
export circuit namesake(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(App_jubjubSchnorrVerify<1>(msg, sig, default<JubjubPoint>), "application check"); count.increment(1);
}
`, []);
});

test("pinned 0.35 stable and RC signature verifiers reject identity keys before a successful observation", () => {
  for (const version of ["0.35.0", "0.35.0-rc.1"] as const) fixture(`export circuit rejected(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(verify(msg, sig, default<JubjubPoint>), "signature"); count.increment(1);
}`, [], version);
});

test("signature observation capacity exhaustion stays explicitly incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
    assert(verify(msg, sig, default<JubjubPoint>), "first signature");
    assert(verify(msg, sig, default<JubjubPoint>), "second signature"); count.increment(1);
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const options = ["instructions", false, false, "equivalent-states", false, true, "witness", false, false, false, true] as const;
    const plain = new Dataflow(program, 40000, 256, 50000, ...options, false).analyze();
    const observed = new Dataflow(program, 40000, 256, plain.metrics.abstractValues, ...options, true).analyze();
    assert.ok(observed.diagnostics.some(item => ["effect-budget", "value-budget"].includes(item.code)), JSON.stringify(observed.diagnostics));
    assert.deepEqual(observed.completedEntries, []);
    const scan = scanFile(program.root, { detectors: [rule.id], maxValues: plain.metrics.abstractValues });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.length);
  });
});


test("default signature rule preserves source-query coverage when structurally absent", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger members: Map<Uint<8>, Field>; witness authorized(): Boolean; witness flags(): Vector<12, Boolean>;
export circuit grant(): [] { assert(authorized(), "authorization"); const selected=flags(); for(const i of 0..12){if(disclose(selected[i])){members.insert(i as Uint<8>,1 as Field);}} }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const scan = scanFile(file);
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.ok(scan.findings.some(item => item.detectorId === "spoofable-authorization"));
    assert.ok(!scan.findings.some(item => item.detectorId === rule.id));
  });
});

test("manual detector use refuses missing signature-call evidence", () => {
  withFiles({ "main.compact": header + `export circuit entry(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): Boolean {
    return verify(msg, sig, default<JubjubPoint>);
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(item => item.code === "signature-evidence-unavailable"));
  });
});


test("actual leaf summary hits preserve separate signature observations", () => {
  withFiles({ "main.compact": header + `
circuit identityKey(): JubjubPoint { return default<JubjubPoint>; }
export circuit entry(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const a = identityKey(); const b = identityKey();
  assert(verify(msg, sig, a), "first signature");
  assert(verify(msg, sig, b), "second signature"); count.increment(1);
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "witness", false, false, false, true, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths[0].operations?.filter(operation => operation.kind === "signature-verification").length, 2);
      if (cached) assert.ok(facts.metrics.summaryHits > 0);
      else assert.equal(facts.metrics.summaryHits, 0);
      const findings = rule.run(facts);
      assert.equal(findings.length, 1);
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
  });
});
