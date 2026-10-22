import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { observeRules } from "../src/analysis/rule-observations.js";
import { resolvePolicies } from "../src/policies.js";
import type { Diagnostic } from "../src/model.js";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { redundantSelfShieldedReceive as rule } from "../src/detectors/redundant-receive.js";
import { selfCoinSequences } from "../src/dataflow/self-coin-sequence.js";
import { SELF_COIN_TARGETS } from "../src/semantic/redundant-receive-targets.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
const header = `import CompactStandardLibrary;
`;
const mint = `const coin = mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>, right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));`;
function check(source: string, expected: number) {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file); let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, false, false, true, false, false, false, false, true, false, SELF_COIN_TARGETS).analyze();
      const findings = rule.run(facts);
      for (const path of facts.paths) assert.equal(selfCoinSequences(path, 0).complete, !(path.operations?.length));
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(findings.length, expected); baseline ??= findings; assert.deepEqual(findings, baseline);
      const unavailable = { ...facts, diagnostics: [] as Diagnostic[], invocationEvidence: undefined }; assert.deepEqual(rule.run(unavailable), []);
      if (unavailable.diagnostics.length) assert.match(unavailable.diagnostics[0].message, /incomplete/);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics)); assert.equal(result.findings.length, expected);
    }
  });
}
test("owned mint exact returned snapshot, alias and fixed sequence", () => {
  check(`export circuit probe(): [] { ${mint} const alias = coin; receiveShielded(alias); }`, 1);
  check(`export circuit probe(): ShieldedCoinInfo { ${mint} return coin; }`, 0);
  check(`export circuit probe(other: ShieldedCoinInfo): [] { ${mint} receiveShielded(disclose(other)); }`, 0);
});
test("owned canonical send returned sent field", () => {
  check(`export circuit probe(input: QualifiedShieldedCoinInfo): [] { const result = sendShielded(disclose(input), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()), 1); receiveShielded(result.sent); }`, 1);
});
test("separate histories, rejected continuations and nonself recipients", () => {
  check(`export circuit probe(flag: Boolean): [] { if (disclose(flag)) { ${mint} } else { receiveShielded(default<ShieldedCoinInfo>); } }`, 0);
  check(`export circuit probe(): [] { ${mint} receiveShielded(coin); assert(false, "disabled"); }`, 0);
  check(`export circuit probe(): [] { const coin = mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>, left<ZswapCoinPublicKey, ContractAddress>(default<ZswapCoinPublicKey>)); receiveShielded(coin); }`, 0);
});
test("bounded equality helper and owned pinned Counter triplet", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-redundant-receive-${variant}.compact`);
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics)); assert.deepEqual(result.findings.map(item => item.location.line), variant === "positive" ? [30] : []);
    }
    assert.equal(scanFile(file).findings.filter(item => item.detectorId === rule.id).length, variant === "positive" ? 1 : 0);
  }
});

test("immediate sent metadata, modifications and local namesake exclusion", () => {
  check(`export circuit probe(input: ShieldedCoinInfo): [] { const result = sendImmediateShielded(disclose(input), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()), 1); receiveShielded(result.sent); }`, 1);
  check(`export circuit probe(): [] { ${mint} const changed = ShieldedCoinInfo { nonce: coin.nonce, color: coin.color, value: 2 }; receiveShielded(changed); }`, 0);
  check(`module Fake { export circuit mintShieldedToken(): ShieldedCoinInfo { return default<ShieldedCoinInfo>; } } import Fake prefix F_; export circuit probe(): [] { const coin = F_mintShieldedToken(); receiveShielded(coin); }`, 0);
});
test("checkpoint snapshots are explicitly incomplete", () => {
  withFiles({ "main.compact": header + `export circuit probe(): [] { ${mint} receiveShielded(coin); kernel.checkpoint(); assert(false, "fallible"); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "incomplete"); assert.deepEqual(scan.findings, []);
      assert.ok(scan.diagnostics.some(issue => /checkpoint/i.test(issue.message) && /incomplete/.test(issue.message)));
    }
  });
});

test("exact helper invocations retain distinct caller histories", () => {
  check(`circuit receipt(coin: ShieldedCoinInfo): [] { receiveShielded(coin); } export circuit probe(other: ShieldedCoinInfo): [] { ${mint} receipt(coin); receipt(disclose(other)); }`, 1);
  check(`export circuit probe(): [] { ${mint} const second = mintShieldedToken(default<Bytes<32>>, 2, default<Bytes<32>>, right<ZswapCoinPublicKey, ContractAddress>(kernel.self())); receiveShielded(coin); }`, 1);
});


test("missing returned snapshots and unfinished baseline stay rule-scoped incomplete", () => withFiles({ "main.compact": header + `export circuit probe(): [] { ${mint} receiveShielded(coin); }` }, directory => {
  const program = new Program(resolve(directory, "main.compact"));
  const observed = observeRules(program, [rule], resolvePolicies(program, {}), {}, new Set());
  assert.equal(observed.work[0].metrics.steps, 0);
  assert.equal(observed.findings.length, 0);
  assert.ok(observed.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
  assert.ok(observed.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable"));
  const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "all", false, false, false, true, false, false, false, false, true, false, SELF_COIN_TARGETS).analyze();
  const producer = facts.paths[0].operations!.find(operation => operation.kind === "circuit-invocation" && operation.name === "standard-library::mintShieldedToken")!;
  producer.result = { ...producer.result, identity: undefined, fields: undefined, items: undefined };
  assert.deepEqual(rule.run(facts), []);
  assert.ok(facts.diagnostics.some(issue => issue.scope?.detectorId === rule.id && /incomplete/.test(issue.message)));
}));
