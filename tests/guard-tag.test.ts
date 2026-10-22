import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { guardTagObservations } from "../src/analysis/guard-tags.js";
import { observeRules } from "../src/analysis/rule-observations.js";
import { resolvePolicies } from "../src/policies.js";
import { nativeHashScope } from "../src/semantic/hash-targets.js";
import { publiclyDerivedGuardTag as rule } from "../src/detectors/guard-tag.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger verifierKey: Bytes<32>;
export ledger stored: Field;
witness secret(): Bytes<32>;
witness tagWitness(): Bytes<32>;
witness choose(): Boolean;
circuit tagOf(key: Bytes<32>, message: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([key, message]);
}
`;
const body = `export circuit update(message: Bytes<32>, tag: Bytes<32>): [] {
  assert(tag == tagOf(verifierKey, message), "tag"); stored = (1 as Field);
}`;
function observe(program: Program, engine: "instructions" | "expressions", cached: boolean, maxValues = 50000) {
  return new Dataflow(program, 40000, 256, maxValues, engine, cached, cached, "equivalent-states", false, true,
    "all", false, false, false, true, false, false, true).analyze();
}
function fixture(body: string, entries: string[], inspect?: (facts: AnalysisFacts) => void) {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const validation = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(validation.valid, true, validation.error); }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(f => f.metadata.entry).sort(), entries);
      for (const finding of findings) {
        assert.equal(finding.confidence, "high"); assert.equal(finding.severity, "medium");
        assert.equal(finding.metadata.callerInputsPublic, "not-proven"); assert.equal(finding.metadata.soleGate, "unproven");
      }
      oracle ??= findings; assert.deepEqual(findings, oracle, `${engine}/${cached}`);
      inspect?.(facts);
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(f => f.metadata.entry).sort(), entries);
  });
}

test("public ledger keyed caller-input tags, nested hashes and raw witness tags retain required relations", () => {
  fixture(body + `
struct Message { payload: Bytes<32>; count: Uint<16>; }
export circuit nested(message: Message, tag: Bytes<32>): [] {
  assert(tag == tagOf(verifierKey, persistentHash<Message>(message)), "nested tag"); stored = (2 as Field);
}
export circuit witnessTag(message: Bytes<32>): [] { assert(tagWitness() == tagOf(verifierKey, message), "tag"); stored = (3 as Field); }
export circuit constantMessage(tag: Bytes<32>): [] { assert(tag == tagOf(verifierKey, pad(32, "domain")), "public tag"); stored = (1 as Field); }
`, ["constantMessage", "nested", "update", "witnessTag"]);
});

test("private witness ingredients, no trusted ledger and actual secret preimage checks stay quiet", () => {
  fixture(`
export circuit privateKey(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag == tagOf(secret(), message), "private key"); stored = (1 as Field); }
export circuit privateInput(tag: Bytes<32>): [] { assert(tag == tagOf(verifierKey, secret()), "secret"); stored = (1 as Field); }
export circuit noLedger(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag == tagOf(pad(32, "domain"), message), "checksum"); stored = (1 as Field); }
export circuit preimage(message: Bytes<32>): [] { assert(persistentHash<Bytes<32>>(secret()) == verifierKey, "credential"); stored = disclose(transientHash<Bytes<32>>(message)); }
`, []);
});

test("optional, bypassed, negative, discarded and post-effect guards stay quiet", () => {
  fixture(`
export circuit optional(message: Bytes<32>, tag: Bytes<32>, flag: Boolean): [] { if (disclose(flag)) { assert(tag == tagOf(verifierKey, message), "tag"); } stored = (1 as Field); }
export circuit bypass(message: Bytes<32>, tag: Bytes<32>, allow: Boolean): [] { assert(tag == tagOf(verifierKey, message) || allow, "optional"); stored = (1 as Field); }
export circuit negative(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag != tagOf(verifierKey, message), "not equal"); stored = (1 as Field); }
export circuit ignored(message: Bytes<32>, tag: Bytes<32>): [] { const valid = tag == tagOf(verifierKey, message); stored = (1 as Field); }
export circuit late(message: Bytes<32>, tag: Bytes<32>): [] { stored = (1 as Field); assert(tag == tagOf(verifierKey, message), "late"); }
export circuit preview(message: Bytes<32>, tag: Bytes<32>): Boolean { return disclose(tag == tagOf(verifierKey, message)); }
constructor() { const message = pad(32, "setup"); assert(tagWitness() == tagOf(verifierKey, message), "setup"); stored = (1 as Field); }
`, []);
});

test("current-state provenance excludes caller-written keys but preserves immutable old ledger snapshots", () => {
  fixture(`
export circuit replaced(message: Bytes<32>, key: Bytes<32>, tag: Bytes<32>): [] { verifierKey = disclose(key); assert(tag == tagOf(verifierKey, message), "self key"); stored = (1 as Field); }
export circuit snapshot(message: Bytes<32>, key: Bytes<32>, tag: Bytes<32>): [] { const old = verifierKey; verifierKey = disclose(key); assert(tag == tagOf(old, message), "old key"); stored = (1 as Field); }
export circuit derivedKey(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag == tagOf(persistentHash<Bytes<32>>(secret()), message), "private"); stored = (1 as Field); }
export circuit refinedWitness(message: Bytes<32>, tag: Bytes<32>): [] { const key = secret(); assert(key == pad(32, "constant"), "known"); assert(tag == tagOf(key, message), "not public"); stored = (1 as Field); }
export circuit witnessControl(message: Bytes<32>, tag: Bytes<32>): [] { const selected = disclose(choose()) ? verifierKey : pad(32, "other"); assert(tag == tagOf(selected, message), "private selector"); stored = (1 as Field); }
export circuit nestedControl(message: Bytes<32>, tag: Bytes<32>): [] { const selected = disclose(choose()) ? persistentHash<Bytes<32>>(message) : persistentHash<Bytes<32>>(verifierKey); assert(tag == tagOf(verifierKey, selected), "selected hash"); stored = (1 as Field); }
`, ["snapshot"]);
});

test("nested summary replay and loop occurrences group one guard per circuit without losing histories", () => {
  fixture(`
circuit check(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag == tagOf(verifierKey, message), "tag"); }
circuit store(): [] { stored = (1 as Field); }
circuit twice(): [] { store(); store(); }
export circuit repeated(message: Bytes<32>, tag: Bytes<32>, select: Boolean): [] { check(message, tag); if (disclose(select)) { twice(); } twice(); for (const i of 0..2) { store(); } }
`, ["repeated"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal((finding.metadata.affectedEffects as unknown[]).length, 6);
    assert.ok((finding.metadata.historyEvidence as unknown[]).length >= 6);
    if (facts.metrics.summaryEntries) assert.ok(facts.metrics.statefulSummaryHits > 0);
  });
});

test("checkpoint prefixes and effect positions cannot acquire guards from later segments", () => {
  fixture(`
export circuit lateCheckpoint(message: Bytes<32>, tag: Bytes<32>): [] { stored = (1 as Field); kernel.checkpoint(); assert(tag == tagOf(verifierKey, message), "later"); }
export circuit earlyCheckpoint(message: Bytes<32>, tag: Bytes<32>): [] { assert(tag == tagOf(verifierKey, message), "early"); stored = (1 as Field); kernel.checkpoint(); stored = (2 as Field); }
`, ["earlyCheckpoint"]);
});

test("Field tags, literal Boolean relays and kernel-write effects preserve the same relation", () => {
  fixture(`
struct Record { key: Bytes<32>; value: Field; }
export circuit fieldTag(value: Field, tag: Field): [] {
  assert((tag == transientHash<Record>(Record { key: verifierKey, value: value })) == true, "tag");
  kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(default<Bytes<32>>), 1);
}
`, ["fieldTag"], facts => {
    const finding = rule.run(facts)[0];
    assert.ok((finding.metadata.affectedEffects as { kind: string }[]).every(effect => effect.kind === "kernel-write"));
  });
});

test("native hash callbacks and lambdas cannot be certified structurally absent", () => {
  fixture(`
export circuit callback(message: Bytes<32>, tag: Bytes<32>): [] {
  const hashes = map(persistentHash<Vector<2, Bytes<32>>>, [[verifierKey, message]]);
  assert(tag == hashes[0], "tag"); stored = (1 as Field);
}
export circuit lambda(message: Bytes<32>, tag: Bytes<32>): [] {
  const hashes = map((input) => tagOf(verifierKey, input), [message]);
  assert(tag == hashes[0], "tag"); stored = (1 as Field);
}
`, ["callback", "lambda"], facts => {
    for (const entry of facts.program.entries) assert.equal(nativeHashScope(facts.program, entry).applicable, true);
  });
});

test("missing invocation evidence and incomplete baseline cannot become a clean rule result", () => {
  withFiles({ "main.compact": header + body }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = observe(program, "instructions", true);
    facts.paths[0].writes[0].callSites = undefined;
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(d => d.code === "guard-tag-evidence-unavailable" && d.scope?.entry === program.entries[0]));
    const missing = observeRules(program, [rule], resolvePolicies(program), {}, new Set());
    assert.deepEqual(missing.findings, []);
    assert.ok(missing.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable"));
    assert.ok(missing.diagnostics.every(d => d.code === "guard-tag-baseline-incomplete" && d.scope?.detectorId === rule.id));
    assert.equal(missing.work[0].metrics.steps, 0);
  });
});

test("rule observation/consumer budgets diagnose incomplete while preserving baseline completion", () => {
  const source = header + body.replace("assert(tag", 'assert(stored != (0 as Field), "public guard"); assert(tag');
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const ordinary = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(ordinary), []);
    assert.ok(ordinary.diagnostics.some(d => d.code === "guard-tag-evidence-unavailable" && d.scope?.detectorId === rule.id));
    const limited = guardTagObservations(observe(program, "instructions", true), 1);
    assert.deepEqual(limited.observations, []);
    assert.ok(limited.diagnostics.every(d => d.code === "guard-tag-analysis-budget" && d.scope?.detectorId === rule.id));
    const scan = scanFile(file, { detectors: [rule.id], maxValues: 7 });
    assert.equal(scan.status, "incomplete"); assert.equal(scan.coverage.baselineStatus, "complete");
    assert.ok(scan.diagnostics.every(d => d.scope?.detectorId === rule.id));
    assert.ok(scan.coverage.rules?.some(row => row.detectorId === rule.id && row.status === "incomplete"));
    const defaultScan = scanFile(file);
    assert.equal(rule.defaultEnabled, false); assert.ok(!defaultScan.coverage.detectors.includes(rule.id));
  });
});

test("real-source Counter guard-tag seed and corrected/lookalike compile and scan", () => {
  const registry = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8"));
  const seed = registry.cases.find((item: { id: string }) => item.id === "counter-guard-tag");
  for (const [path, expected] of [[seed.file, seed.expectedLines], [seed.corrected, []], [seed.lookalike, []]]) {
    const file = resolve("tests/corpus", path);
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, `${path}: ${compiled.error}`); }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(f => f.location.line), expected);
  }
});
