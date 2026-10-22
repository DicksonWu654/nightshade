import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { exportedShieldedDescriptor as rule } from "../src/detectors/exported-shielded-descriptor.js";
import { exportedShieldedDescriptors } from "../src/analysis/exported-shielded-descriptor.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = `pragma language_version >= 0.26.0; import CompactStandardLibrary;\n`;
const parameters = `coin: QualifiedShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey, ContractAddress>`;
const send = `sendShielded(disclose(coin), disclose(recipient), 1)`;
function check(body: string, count: number, incomplete = false, prefix = header) {
  withFiles({ "main.compact": prefix + body }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cache, cache).analyze();
      const findings = rule.run(facts);
      assert.equal(findings.length, count);
      assert.equal(facts.diagnostics.some(issue => issue.scope?.detectorId === rule.id), incomplete);
      const outcome = { findings, diagnostics: facts.diagnostics.filter(issue => issue.scope?.detectorId === rule.id) };
      oracle ??= outcome; assert.deepEqual(outcome, oracle);
      for (const finding of findings) { assert.equal(finding.severity, "info"); assert.equal(finding.metadata.visibility, "application-output"); assert.equal(finding.metadata.secrecyPolicyViolation, "not-claimed"); }
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, incomplete ? "incomplete" : "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, count);
    assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false);
  });
}

test("owned shielded result source trio has the declared static fact only in the positive", async () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/synthetic-regressions/privacy16/shielded-result-return/${kind}.compact`);
    const direct = scanFile(file, { detectors: [rule.id] });
    assert.equal(direct.status, "complete");
    assert.deepEqual(direct.findings.map(f => f.location.line), kind === "positive" ? [3] : []);
    const isolated = await scanFileIsolated(file, { detectors: [rule.id] });
    assert.deepEqual(isolated.findings, direct.findings); assert.deepEqual(isolated.coverage, direct.coverage);
  }
});

test("raw descriptors, selected fields, immutable aliases and actual helper parameters retain provenance", () => {
  check(`export circuit run(${parameters}): ShieldedSendResult { const result = ${send}; const alias = result; return alias; }`, 1);
  check(`export circuit run(${parameters}): Uint<128> { const result = ${send}; return result.sent.value; }`, 1);
  check(`circuit forward(result: ShieldedSendResult): ShieldedSendResult { const alias = result; return alias; } export circuit run(${parameters}): Bytes<32> { return forward(${send}).sent.nonce; }`, 1);
  check(`circuit pick(coin: QualifiedShieldedCoinInfo, unrelated: Uint<128>): Uint<128> { return coin.value; } export circuit run(${parameters}): Uint<128> { return pick(coin, 1); }`, 1);
  check(`struct Output { publicValue: Uint<128>; } export circuit run(${parameters}): Output { return Output { publicValue: coin.value }; }`, 1);
  check(`export circuit run(${parameters}): [Bytes<32>, Uint<128>] { return [coin.color, coin.value]; }`, 1);
  check(`export circuit raw(coin: ShieldedCoinInfo): ShieldedCoinInfo { return coin; }`, 1);
  check(`export circuit immediate(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey, ContractAddress>): ShieldedSendResult { return sendImmediateShielded(disclose(coin), disclose(recipient), 1); }`, 1);
  check(`export circuit renamed(${parameters}): ShieldedSendResult { return renamedSend(disclose(coin), disclose(recipient), 1); }`, 1, false, header + `import { sendShielded as renamedSend } from CompactStandardLibrary;\n`);
  check(`circuit choose(coin: ShieldedCoinInfo, flag: Boolean): ShieldedCoinInfo { if (flag) { return coin; } return coin; } export circuit raw(coin: ShieldedCoinInfo, flag: Boolean): Uint<128> { return choose(coin, flag).value; }`, 1);
});

test("canonical identity excludes namesakes and unrelated helper operands", () => {
  check(`struct ShieldedCoinInfo { value: Uint<128>; } export circuit run(coin: ShieldedCoinInfo): Uint<128> { return coin.value; }`, 0, false, "pragma language_version >= 0.26.0;\n");
  check(`circuit pick(coin: QualifiedShieldedCoinInfo, unrelated: Uint<128>): Uint<128> { return unrelated; } export circuit run(${parameters}): Uint<128> { return pick(coin, 1); }`, 0);
  check(`struct Output { secret: Uint<128>; benign: Uint<128>; } export circuit run(${parameters}): Uint<128> { const result = Output { secret: coin.value, benign: 1 }; return result.benign; }`, 0);
  check(`struct ShieldedSendResult { sent: Uint<128>; } circuit sendShielded(): ShieldedSendResult { return ShieldedSendResult { sent: 1 }; } export circuit run(): ShieldedSendResult { return sendShielded(); }`, 0, false, "pragma language_version >= 0.26.0;\n");
  check(`export circuit run(${parameters}): Boolean { const result = ${send}; return result.change.is_some; }`, 0);
  check(`export circuit run(${parameters}): Bytes<32> { return persistentHash<Uint<128>>(coin.value); }`, 0);
  check(`export circuit run(${parameters}): Uint<128> { return (coin.value + 1) as Uint<128>; }`, 0);
});

test("source routes do not claim successful execution or disqualify intentional metadata APIs", () => {
  check(`export circuit metadata(${parameters}): ShieldedSendResult { assert(false, "unreachable"); return ${send}; }`, 1);
  check(`export circuit walletMetadata(${parameters}): Bytes<32> { return coin.nonce; }`, 1);
});

test("unmodeled relevant forwarding and exhausted source allowances remain incomplete", () => {
  check(`export circuit run(${parameters}): Bytes<32> { return persistentHash<Bytes<32>>(coin.nonce); }`, 0);
  withFiles({ "main.compact": header + `export circuit run(${parameters}): ShieldedSendResult { return ${send}; }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const observed = exportedShieldedDescriptors(program, 2);
    assert.equal(observed.complete, false); assert.deepEqual(observed.observations, []); assert.ok(observed.failures.length);
  });
  check(`export circuit run(${parameters}): [Uint<128>] { return map((ignored: Field): Uint<128> => coin.value, [0 as Field]); }`, 0, true);
  check(`witness unknown(): ShieldedCoinInfo; export circuit run(): Uint<128> { return disclose(unknown().value); }`, 0, true);
  check(`witness unknown(coin: QualifiedShieldedCoinInfo): Uint<128>; export circuit run(${parameters}): Uint<128> { return disclose(unknown(coin)); }`, 0, true);
});


test("CLI opt-in selection exposes the same informational source site", () => {
  const file = resolve("tests/corpus/synthetic-regressions/privacy16/shielded-result-return/positive.compact");
  const cli = spawnSync(process.execPath, ["dist/src/cli.js", "scan", file, "--detectors", rule.id, "--json", "--fail-on", "none"], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  const report = JSON.parse(cli.stdout);
  assert.equal(report.status, "complete"); assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].detectorId, rule.id);
});
