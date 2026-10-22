import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, scanFile } from "../src/index.js";
import { sourceObservations, cachedSourceObservations } from "../src/analysis/source-observations.js";
import { discardedShieldedSendResult as rule } from "../src/detectors/shielded-send-result.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const parameters = "coin: ShieldedCoinInfo, qualified: QualifiedShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey, ContractAddress>";
function checked(body: string, expected: string[], header = "import CompactStandardLibrary;"): void {
  withFiles({ "main.compact": header + "\nexport ledger count: Counter;\n" + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    const source = sourceObservations(program, 200000, "shielded-send-results");
    assert.equal(source.complete, true);
    assert.deepEqual(source.observations.filter(item => item.kind === rule.id).map(item => item.metadata.discardedBy), expected);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, expected.length);
    for (const item of report.findings) { assert.equal(item.severity, "info"); assert.equal(item.confidence, "high"); }
    const ordinary = sourceObservations(program);
    assert.deepEqual(cachedSourceObservations(program), ordinary);
    assert.deepEqual(cachedSourceObservations(program, "shielded-send-results"), source);
    assert.deepEqual(sourceObservations(program, source.work, "shielded-send-results"), source);
    const exhausted = sourceObservations(program, source.work - 1, "shielded-send-results");
    assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
    assert.equal(rule.defaultEnabled, true);
  });
}

test("canonical direct sends and unused immutable aliases report metadata discard", () => checked(`
export circuit entry(${parameters}): [] {
  sendImmediateShielded(disclose(coin), disclose(recipient), 1);
  const result = sendShielded(disclose(qualified), disclose(recipient), 1); const alias = result; const unused = disclose(alias);
  count.increment(1);
}`, ["expression-statement", "unused-alias-chain"]));

test("field selection, returned results, fan-out, and captures conservatively retain metadata", () => checked(`
export circuit entry(${parameters}): [] {
  const selected = sendImmediateShielded(disclose(coin), disclose(recipient), 1); const unusedField = selected.sent;
  const result = sendShielded(disclose(qualified), disclose(recipient), 1); const unused = result; const used = result; const field = used.change;
  const captured = sendImmediateShielded(disclose(coin), disclose(recipient), 1);
  const captures = map((ignored: Field): ShieldedCoinInfo => captured.sent, [0 as Field]);
  count.increment(1);
}
export circuit returned(${parameters}): ShieldedSendResult { return sendShielded(disclose(qualified), disclose(recipient), 1); }
`, []));

test("source rejection and skipped branches exclude sends; sequence prefixes remain outside scope", () => checked(`
export circuit entry(${parameters}): [] {
  false && (sendImmediateShielded(disclose(coin), disclose(recipient), 1), true);
  const consumed = (sendImmediateShielded(disclose(coin), disclose(recipient), 1), true);
  if (false) { sendShielded(disclose(qualified), disclose(recipient), 1); }
  assert(false,"reject"); sendImmediateShielded(disclose(coin), disclose(recipient), 1);
}`, []));

test("import aliases preserve canonical identities", () => checked(`
export circuit entry(${parameters}): [] { renamed(disclose(coin), disclose(recipient), 1); count.increment(1); }
`, ["expression-statement"], "import CompactStandardLibrary; import { sendImmediateShielded as renamed } from CompactStandardLibrary;"));

test("custom same-name helper is quiet", () => checked(`
circuit sendImmediateShielded(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey, ContractAddress>, value: Uint<128>): ShieldedCoinInfo { return coin; }
export circuit entry(${parameters}): [] { sendImmediateShielded(disclose(coin), disclose(recipient), 1); count.increment(1); }
`, [], "import { ShieldedCoinInfo, QualifiedShieldedCoinInfo, Either, ZswapCoinPublicKey, ContractAddress, Counter } from CompactStandardLibrary;"));

test("mint descriptors and exact nested producer returns are tracked; partial helper returns remain outside", () => checked(`
circuit produce(recipient: Either<ZswapCoinPublicKey, ContractAddress>): ShieldedCoinInfo {
  return mintShieldedToken(pad(32,"reward"), 1, pad(32,"nonce"), recipient);
}
circuit forward(recipient: Either<ZswapCoinPublicKey, ContractAddress>): ShieldedCoinInfo { return produce(recipient); }
circuit partial(${parameters}): ShieldedCoinInfo { return sendImmediateShielded(coin, recipient, 1).sent; }
export circuit entry(${parameters}): [] {
  disclose(mintShieldedToken(pad(32,"reward2"), 1, pad(32,"nonce2"), disclose(recipient)));
  const unused = forward(disclose(recipient)); const alias = unused;
  partial(disclose(coin), disclose(qualified), disclose(recipient));
  count.increment(1);
}
`, ["expression-statement", "unused-alias-chain"]));

test("returning the input coin does not retain a discarded send descriptor", () => checked(`
circuit deposit(coin: ShieldedCoinInfo, parent: ContractAddress): [] {
  sendImmediateShielded(disclose(coin), right<ZswapCoinPublicKey, ContractAddress>(disclose(parent)), 1);
}
export circuit entry(coin: ShieldedCoinInfo, parent: ContractAddress): ShieldedCoinInfo {
  deposit(coin, parent); count.increment(1); return coin;
}
`, ["expression-statement"]));

test("owned parent forwarding and mint descriptors agree across default and Counter selections", () => {
  for (const [name, line] of [["counter-parent-send-metadata", 8], ["counter-mint-metadata", 12]] as const) {
    for (const kind of ["positive", "corrected", "lookalike"]) {
      const file = resolve(`tests/corpus/known-bugs/${name}-${kind}.compact`);
      for (const experimentalCounterQueries of [false, true]) {
        for (const detectors of [undefined, [rule.id]]) {
          const report = scanFile(file, { experimentalCounterQueries, detectors });
          assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
          assert.deepEqual(report.findings.filter(item => item.detectorId === rule.id).map(item => item.location.line), kind === "positive" ? [line] : []);
        }
      }
    }
  }
});
