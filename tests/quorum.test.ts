import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { quorumSignerUniquenessReview as rule } from "../src/detectors/quorum.js";
import { quorumTargets } from "../src/semantic/quorum-targets.js";
import { quorumObservations } from "../src/dataflow/quorum.js";
import { ECDSA_VERIFIER } from "../src/semantic/signed-input-targets.js";
import { enforcedSignatureResults } from "../src/dataflow/signed-effect-input.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
const directory = "tests/corpus/synthetic-regressions/auth16";
const positive = readFileSync(resolve(directory, "quorum-signer-uniqueness-review-case-76-positive.compact"), "utf8");
function factsFor(program: Program, engine: "instructions" | "expressions" = "instructions", cached = true) {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
    "all", false, true, false, false, false, false, true, false, false, false, quorumTargets(program)).analyze();
}
function checkSource(source: string, expected: number, compiler = false) {
  withFiles({ "main.compact": source }, dir => {
    const file = resolve(dir, "main.compact");
    if (compiler && process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
      assert.equal(validation.valid, true, validation.error);
    }
    const program = new Program(file, [], undefined, undefined, 3);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = factsFor(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []); assert.equal(findings.length, expected);
      assert.ok(findings.every(finding => finding.severity === "info" && finding.metadata.reviewRequired));
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const report = scanFile(file, { detectors: [rule.id], zkirVersion: 3, experimentalCounterQueries });
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.equal(report.findings.length, expected);
    }
  });
}

test("owned full-shape quorum positive, pairwise corrected and two-claim lookalike", () => {
  for (const [name, expected] of [["positive",1],["corrected",0],["lookalike",0]] as const)
    checkSource(readFileSync(resolve(directory, `quorum-signer-uniqueness-review-case-76-${name}.compact`), "utf8"), expected, true);
});
test("generic owned quorum fold retains per-claim verification and gated caller effects", () => {
  const directory = resolve("tests/corpus/drafts/auth40/quorum-membership");
  for (const [variant, expected, width] of [["positive", 2, 3], ["corrected", 0, 3], ["lookalike", 0, 2]] as const) {
    const file = resolve(directory, `generic-${variant}.compact`);
    checkSource(readFileSync(file, "utf8"), expected, true);
    const program = new Program(file, [], undefined, undefined, 3);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = factsFor(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 2);
      for (const path of facts.paths) {
        const verifications = path.operations!.filter(operation => operation.kind === "circuit-invocation" && operation.name === ECDSA_VERIFIER);
        assert.equal(verifications.length, width, `${variant}/${engine}/${cached}/${path.entry}`);
        const consumer = facts.program.symbols.get(path.entry)!.name.startsWith("consume");
        assert.equal(path.writes.length, consumer ? 1 : 0);
        if (consumer) {
          const enforced = enforcedSignatureResults(path, 0, 200000);
          assert.equal(enforced.complete, true);
          assert.ok(verifications.every(operation => operation.result.identity && enforced.identities.has(operation.result.identity)));
        }
      }
    }
  }
});
test("owned Counter scaffold quorum seed preserves exact sites and quiet controls", () => {
  for (const [kind, lines] of [["positive", [34]], ["corrected", []], ["lookalike", []]] as const) {
    const file = resolve("tests/corpus/quorum-review", `${kind}.compact`);
    checkSource(readFileSync(file, "utf8"), lines.length, true);
    const report = scanFile(file, { detectors: [rule.id], zkirVersion: 3 });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(finding => finding.location.line), lines);
  }
});
test("quorum and enrolled-key selections preserve both observations in exact and legacy modes", () => {
  withFiles({ "main.compact": positive + `
export ledger enrolled: JubjubPoint;
export circuit verifyEnrolled(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(jubjubSchnorrVerify<1>(msg, sig, enrolled), "enrolled signature");
}
` }, directory => {
    const file = resolve(directory, "main.compact"), enrolled = "enrolled-signature-key-review";
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
      assert.equal(compiled.valid, true, compiled.error);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const options = { zkirVersion: 3 as const, experimentalCounterQueries };
      const mixed = scanFile(file, { ...options, detectors: [rule.id, enrolled] });
      assert.equal(mixed.status, "complete", JSON.stringify(mixed.diagnostics));
      assert.deepEqual(mixed.findings.map(finding => finding.detectorId).sort(), [rule.id, enrolled].sort());
      for (const detector of [rule.id, enrolled]) {
        const selected = scanFile(file, { ...options, detectors: [detector] });
        assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
        assert.deepEqual(mixed.findings.filter(finding => finding.detectorId === detector), selected.findings);
      }
    }
  });
});
test("ordinary sequences, custom verifier names and missing full-shape guards do not qualify", () => {
  checkSource(`export circuit sequence(values: Vector<3, Bytes<32>>, threshold: Uint<8>): [] {
    assert(values[0] != values[1], "adjacent"); assert(values[1] != values[2], "adjacent"); assert(3 >= threshold, "threshold");
  }`, 0, true);
  checkSource(positive.replace(/  assert\(registered\.member[^\n]+\n/g, ""), 0, true);
  checkSource(positive.replace(/  assert\(claims\[\d\]\.commitment ==[^\n]+\n/g, ""), 0, true);
  checkSource(positive.replace('  assert(accepted >= threshold, "threshold");', ''), 0, true);
  checkSource(positive.replace(/assert\((secp256k1EcdsaVerify[^\n]+\)), "signature (\d)"\);/g,
    (_match, expression: string, index: string) => `const ignored${index} = ${expression};`), 0, true);
});
test("same-named application verifiers are excluded by canonical identity", () => {
  const source = positive.replace('export ledger registered:', `module Application {
    export circuit secp256k1EcdsaVerify(msg: Bytes<32>, signature: Secp256k1EcdsaSignature, key: Secp256k1Point): Boolean { return true; }
  }
  import Application prefix App_;
  export ledger registered:`).replaceAll('assert(secp256k1EcdsaVerify(', 'assert(App_secp256k1EcdsaVerify(');
  checkSource(source, 0, true);
});
test("snapshot aliases retain exact operands and required Boolean outcome bindings", () => {
  const source = positive.replace('  assert(secp256k1EcdsaVerify(keccak256<Bytes<32>>(claims[0].commitment), claims[0].signature, claims[0].key), "signature 0");', `
  const claim = claims[0];
  const outcome = secp256k1EcdsaVerify(keccak256<Bytes<32>>(claim.commitment), claim.signature, claim.key);
  const alias = outcome; assert(alias == true, "signature 0");`);
  checkSource(source, 1, true);
});
test("conditional outcome enforcement is required only in its successful branch history", () => {
  checkSource(positive.replace('threshold: Uint<8>', 'threshold: Uint<8>, optional: Boolean')
    .replace('  assert(secp256k1EcdsaVerify(keccak256<Bytes<32>>(claims[2].commitment), claims[2].signature, claims[2].key), "signature 2");',
      '  const outcome = secp256k1EcdsaVerify(keccak256<Bytes<32>>(claims[2].commitment), claims[2].signature, claims[2].key); if (optional) { assert(outcome, "signature 2"); }'), 1, true);
  // Only the true branch has the full required relationship. The observation is
  // scoped to that history; it never calls the optional verifier a universal gate.
});
test("exact registry revisions, key recipes and transitive pairwise inequality binding", () => {
  checkSource(positive.replace('export ledger registered: Set<Bytes<32>>;', 'export ledger registered: Set<Bytes<32>>; export ledger other: Set<Bytes<32>>;')
    .replace('registered.member(disclose(claims[2].commitment))', 'other.member(disclose(claims[2].commitment))'), 0, true);
  checkSource(positive.replace('  assert(registered.member(disclose(claims[1].commitment))',
    '  registered.insert(default<Bytes<32>>);\n  assert(registered.member(disclose(claims[1].commitment))'), 0, true);
  checkSource(positive.replace('signerCommitment(claims[2].key)', 'signerCommitment(claims[1].key)'), 0, true);
  checkSource(positive.replace('threshold: Uint<8>', 'threshold: Uint<8>, bound: Bytes<32>')
    .replace('  const accepted:', '  assert(bound == claims[0].commitment, "bound snapshot"); assert(bound != claims[2].commitment, "non-adjacent unique");\n  const accepted:'), 0, true);
});
test("wildcard regions cannot suppress a missing pair, and observer budgets diagnose incompleteness", () => {
  withFiles({ "main.compact": positive }, dir => {
    const program = new Program(resolve(dir,"main.compact"), [], undefined, undefined, 3), facts = factsFor(program);
    const path = facts.paths[0];
    assert.equal(quorumObservations(path, 1).complete, false);
    const changed = structuredClone(path);
    const adjacent = changed.predicates!.find(predicate => predicate.value.comparison?.operator === "!=")!.value.comparison!;
    const entry = changed.operations!.find(operation => operation.name === path.entry)!;
    const first = entry.args[0].items![0].fields!.commitment, third = entry.args[0].items![2].fields!.commitment;
    const region = { root: "storage", path: ["*"], type: "Bytes<32>" };
    changed.predicates!.push({ ...changed.predicates![0], value: { type: "Boolean", flows: [], ledger: new Set(), comparison: {
      operator: "!=", left: { ...first, region }, right: { ...third, region } } }, truth: true });
    assert.equal(quorumObservations(changed, 1000000).observations.length, 1);
    assert.equal(adjacent.left.region, undefined);
    const knownDistinct = structuredClone(path);
    for (const [value, constant] of [[first,"00".repeat(32)],[third,"01".repeat(32)]] as const) knownDistinct.predicates!.push({ ...path.predicates![0], truth: true,
      value: { type:"Boolean", flows:[], ledger:new Set(), comparison: { operator:"==", left:value,
        right: { type:"Bytes<32>", flows:[], ledger:new Set(), constantKind:"bytes", constant } } } });
    assert.equal(quorumObservations(knownDistinct, 1000000).observations.length, 0);
    const oversized = structuredClone(path);
    const sequence = oversized.operations!.find(operation => operation.name === path.entry)!.args[0];
    sequence.items = Array.from({length:17}, () => sequence.items![0]);
    assert.equal(quorumObservations(oversized, 1000000).complete, false);
    const unavailable = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(unavailable), []);
    assert.ok(unavailable.diagnostics.some(issue => issue.scope?.detectorId === rule.id));
    const lost = factsFor(program); lost.paths[0].predicates![0].value.predicateStructureLost = true;
    assert.deepEqual(rule.run(lost), []);
    assert.ok(lost.diagnostics.some(issue => issue.scope?.detectorId === rule.id));
    const limited = scanFile(resolve(dir,"main.compact"), { detectors: [rule.id], zkirVersion:3, maxSteps:1 });
    assert.equal(limited.status, "incomplete"); assert.equal(limited.findings.length, 0);
  });
});
test("quorum review remains opt-in", () => {
  assert.equal(rule.defaultEnabled, false);
  const report = scanFile(resolve(directory,"quorum-signer-uniqueness-review-case-76-positive.compact"), { zkirVersion: 3 });
  assert.ok(!report.findings.some(finding => finding.detectorId === rule.id));
});
