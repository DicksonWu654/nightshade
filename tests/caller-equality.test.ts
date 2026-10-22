import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, detectors } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { callerEqualityObservations } from "../src/analysis/caller-equality.js";
import { callerSuppliedLedgerEquality as rule } from "../src/detectors/caller-equality.js";
import { callerEqualityScope } from "../src/semantic/caller-equality-targets.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger admin: Bytes<32>;
export ledger stored: Field;
witness secret(): Bytes<32>;
`;
function flow(program: Program, engine: "instructions" | "expressions", cached: boolean) {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
    "all", false, false, false, false, false, false, true).analyze();
}
function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts) => void) {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = flow(program, engine, cached);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(f => f.metadata.entry).sort(), expected);
      assert.ok(findings.every(f => f.severity === "medium" && f.confidence === "high" && f.metadata.soleGate === "unproven"));
      oracle ??= findings;
      assert.deepEqual(findings, oracle, `${engine}/${cached}`);
      inspect?.(facts);
    }
  });
}

test("unchanged inputs, helper forwarding, Boolean relays and aggregate leaves retain exact ledger equality", () => {
  fixture(`
struct Claim { caller: Bytes<32>; unrelated: Bytes<32>; }
circuit allowed(caller: Bytes<32>): Boolean { return caller == admin; }
export circuit direct(caller: Bytes<32>): [] { assert(disclose(caller) == admin, "admin"); stored = (1 as Field); }
export circuit helper(caller: Bytes<32>): [] { assert(allowed(caller), "admin"); stored = (1 as Field); }
export circuit aggregate(claim: Claim): [] { assert(claim.caller == admin, "admin"); stored = (1 as Field); }
export circuit relay(caller: Bytes<32>): [] { assert((caller != admin) == false, "admin"); stored = (1 as Field); }
export circuit branch(caller: Bytes<32>): [] { if (disclose(caller != admin)) { assert(false, "not admin"); } stored = (1 as Field); }
export circuit refined(caller: Bytes<32>): [] { assert(caller == pad(32, "caller"), "input refinement"); assert(caller == admin, "admin"); stored = (1 as Field); }
export circuit constructed(): [] { assert(pad(32, "caller") == admin, "public configuration"); stored = (1 as Field); }
`, ["aggregate", "branch", "direct", "helper", "refined", "relay"]);
});

test("optional, disjunctive, discarded, negative, no-effect and after-effect checks stay quiet", () => {
  fixture(`
export circuit optional(caller: Bytes<32>, flag: Boolean): [] { if (disclose(flag)) { assert(caller == admin, "admin"); } stored = (1 as Field); }
export circuit bypass(caller: Bytes<32>, allow: Boolean): [] { assert(caller == admin || allow, "optional"); stored = (1 as Field); }
export circuit ignored(caller: Bytes<32>): [] { const valid = caller == admin; stored = (1 as Field); }
export circuit negative(caller: Bytes<32>): [] { assert(caller != admin, "not admin"); stored = (1 as Field); }
export circuit preview(caller: Bytes<32>): Boolean { return disclose(caller == admin); }
export circuit late(caller: Bytes<32>): [] { stored = (1 as Field); assert(caller == admin, "later"); }
constructor() { admin = pad(32, "setup"); }
`, []);
});

test("required possession controls suppress, optional or publicly-known preimages do not", () => {
  fixture(`
export circuit corrected(caller: Bytes<32>): [] { assert(caller == admin, "admin"); assert(persistentHash<Bytes<32>>(secret()) == admin, "secret"); stored = (1 as Field); }
export circuit laterProof(caller: Bytes<32>): [] { assert(caller == admin, "admin"); stored = (1 as Field); assert(persistentHash<Bytes<32>>(secret()) == admin, "atomic secret proof"); }
export circuit optionalProof(caller: Bytes<32>, flag: Boolean): [] { assert(caller == admin, "admin"); if (disclose(flag)) { assert(persistentHash<Bytes<32>>(secret()) == admin, "secret"); } stored = (1 as Field); }
export circuit knownPreimage(caller: Bytes<32>): [] { const key = secret(); assert(key == caller, "known preimage"); assert(caller == admin, "admin"); assert(persistentHash<Bytes<32>>(key) == admin, "public preimage"); stored = (1 as Field); }
export circuit publicHash(caller: Bytes<32>): [] { assert(caller == admin, "admin"); assert(persistentHash<Bytes<32>>(caller) == admin, "known preimage"); stored = (1 as Field); }
`, ["knownPreimage", "optionalProof", "publicHash"]);
});

test("new owner echoes and hashed inputs are not unchanged preexisting equality; old snapshots survive", () => {
  fixture(`
export circuit echo(caller: Bytes<32>): [] { admin = disclose(caller); assert(caller == admin, "self"); stored = (1 as Field); }
export circuit transformed(caller: Bytes<32>): [] { assert(persistentHash<Bytes<32>>(caller) == admin, "derived input"); stored = (1 as Field); }
export circuit oldSnapshot(caller: Bytes<32>, replacement: Bytes<32>): [] { const old = admin; admin = disclose(replacement); assert(caller == old, "old admin"); stored = (1 as Field); }
`, ["oldSnapshot"], facts => {
    const finding = rule.run(facts)[0];
    const history = finding.metadata.historyEvidence as { ledgerIdentity: string }[];
    assert.ok(history.every(item => item.ledgerIdentity.endsWith(":0")));
  });
});

test("bytewise-known preimages cannot suppress a supported caller guard as private possession", () => {
  withFiles({ "main.compact": header + `export circuit reconstructed(caller: Bytes<32>): [] {
    const key = secret();
    assert(caller == admin, "admin");
    assert((key as Vector<32, Uint<8>>) == (caller as Vector<32, Uint<8>>), "known preimage");
    assert(persistentHash<Bytes<32>>(key) == admin, "hash");
    stored = (1 as Field);
  }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = flow(new Program(file), engine, cached);
      assert.equal(facts.diagnostics.length, 0);
      assert.deepEqual(rule.run(facts), []);
      assert.deepEqual(facts.diagnostics.map(issue => issue.code), ["caller-equality-possession-unavailable"]);
      assert.ok(facts.diagnostics.every(issue => issue.scope?.kind === "rule" && issue.scope.detectorId === rule.id));
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "incomplete");
    assert.equal(scan.coverage.baselineStatus, "complete");
    assert.ok(scan.coverage.rules!.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  });
});

test("nested cached mutations and repeated occurrences keep real effect and invocation histories", () => {
  fixture(`
circuit check(caller: Bytes<32>): [] { assert(caller == admin, "admin"); }
circuit store(): [] { stored = (1 as Field); }
circuit twice(): [] { store(); store(); }
export circuit repeated(caller: Bytes<32>, flag: Boolean): [] { check(caller); if (disclose(flag)) { twice(); } twice(); for (const i of 0..2) { store(); } }
`, ["repeated"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal((finding.metadata.affectedEffects as unknown[]).length, 6);
    assert.ok((finding.metadata.historyEvidence as unknown[]).length >= 6);
    if (facts.metrics.summaryEntries) assert.ok(facts.metrics.statefulSummaryHits > 0);
  });
});

test("checkpoint prefixes cannot acquire a private proof or equality from a later segment", () => {
  fixture(`
export circuit early(caller: Bytes<32>): [] { assert(caller == admin, "admin"); stored = (1 as Field); kernel.checkpoint(); assert(persistentHash<Bytes<32>>(secret()) == admin, "later secret"); }
export circuit late(caller: Bytes<32>): [] { stored = (1 as Field); kernel.checkpoint(); assert(caller == admin, "later admin"); }
`, ["early"]);
});

test("unknown selectors, missing evidence and exhausted consumer budgets remain rule-scoped incomplete", () => {
  withFiles({ "main.compact": header + `export ledger owners: Map<Field, Bytes<32>>;
export circuit selected(caller: Bytes<32>, index: Field): [] { assert(caller == owners.lookup(disclose(index)), "admin"); stored = (1 as Field); }
export circuit direct(caller: Bytes<32>): [] { assert(caller == admin, "admin"); stored = (1 as Field); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const program = new Program(file);
    const facts = flow(program, "instructions", true);
    assert.deepEqual(facts.diagnostics, []);
    const result = callerEqualityObservations(facts);
    assert.deepEqual(result.observations.map(observation => program.symbols.get(observation.entry)!.name), ["direct"]);
    assert.ok(result.diagnostics.some(issue => issue.code === "caller-equality-evidence-unavailable" && issue.scope?.kind === "rule"));
    assert.ok(callerEqualityObservations(facts, 1).diagnostics.some(issue => issue.code === "caller-equality-analysis-budget"));
    assert.ok(callerEqualityObservations({ ...facts, predicateScope: "witness" }).diagnostics.every(issue => issue.scope?.kind === "rule"));
    assert.equal(callerEqualityScope(program, program.entries[0], 0).complete, false);
  });
});

test("public scanner isolates rule failures and keeps the intent-dependent rule opt-in", () => {
  assert.equal(detectors.find(item => item.id === rule.id)!.defaultEnabled, false);
  withFiles({ "main.compact": header + `export circuit entry(caller: Bytes<32>): [] { assert(caller == admin, "admin"); stored = (1 as Field); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const normal = scanFile(file, { profile: "hygiene" });
    const selected = scanFile(file, { detectors: [rule.id] });
    assert.equal(normal.status, "complete");
    assert.deepEqual(normal.findings.map(finding => finding.detectorId), ["unused-declaration"]);
    assert.ok(!normal.coverage.detectors.includes(rule.id));
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.equal(selected.findings.length, 1);
    assert.equal(selected.coverage.rules!.find(row => row.detectorId === rule.id)!.status, "complete");
    const limited = scanFile(file, { detectors: [rule.id], maxValues: 1 });
    assert.equal(limited.status, "incomplete"); assert.equal(limited.findings.length, 0);
    assert.ok(limited.diagnostics.some(issue => issue.scope?.detectorId === rule.id));
  });
});

test("entries without represented Bytes32 input leaves need no exact observation evidence", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
    struct Phantom<T> { value: Field; }
    export ledger stored: Field;
    export circuit numeric(value: Field): [] { assert(value == stored, "consistent"); stored = disclose(value); }
    export circuit phantom(value: Phantom<Bytes<32>>): [] { assert(value.value == stored, "consistent"); stored = disclose(value.value); }
    export circuit empty(value: Vector<0, Bytes<32>>): [] { stored = (1 as Field); }
  ` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const program = new Program(file);
    for (const entry of program.entries) assert.equal(callerEqualityScope(program, entry).applicable, false);
    const ordinary = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(ordinary), []);
    assert.deepEqual(ordinary.diagnostics, []);
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.ok(scan.coverage.rules!.every(row => row.status === "not-applicable"));
  });
});

test("owned Counter correction and lookalike stay quiet on five supported compiler profiles", () => {
  const cases = ["positive", "corrected", "lookalike"] as const;
  for (const [version, compiler] of [["0.30.0", process.env.COMPACTC_030_TEST], ["0.31.1", process.env.COMPACTC_031_TEST], ["0.33.0-rc.2", process.env.COMPACTC_033_RC2_TEST], ["0.34.0", process.env.COMPACTC_TEST], ["0.35.0", process.env.COMPACTC_035_TEST]] as const) {
    for (const name of cases) {
      const file = resolve(`tests/corpus/known-bugs/counter-caller-equality-${name}.compact`);
      if (compiler) assert.equal(validateWithCompiler(compiler, file, [], 30000, 2, version).valid, true, `${version}/${name}`);
      const report = scanFile(file, { compilerVersion: version, detectors: [rule.id] });
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.equal(report.findings.length, name === "positive" ? 1 : 0, `${version}/${name}`);
    }
  }
});
