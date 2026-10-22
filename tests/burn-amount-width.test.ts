import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { burnAmountWidths, BURN_AMOUNT_WIDTH_RULE } from "../src/semantic/burn-amount-width.js";
import { shieldedBurnAmountWidth as rule } from "../src/detectors/burn-amount-width.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function check(amountType: string, recipient: string, expression = "amount", extra = "", send = "sendShielded", prefix = "", count?: number, coinType = "QualifiedShieldedCoinInfo"): void {
  const expected = count ?? (amountType === "Uint<64>" && recipient === "shieldedBurnAddress()" && expression !== "amount + 1" ? 1 : 0);
  const source = `pragma language_version >= 0.18; import CompactStandardLibrary; ${extra}
export circuit burn(coin: ${coinType}, amount: ${amountType}, recipient: Either<ZswapCoinPublicKey, ContractAddress>): ShieldedSendResult {
${prefix} return ${send}(disclose(coin), disclose(${recipient}), disclose(${expression})); }`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    const query = burnAmountWidths(program); assert.equal(query.complete, true); assert.equal(query.observations.length, expected);
    for (const mode of [undefined, "counter-predicates"] as const) {
      const scan = scanFile(file, { detectors: [BURN_AMOUNT_WIDTH_RULE], ...(mode ? { experimentalCounterQueries: true } : {}) });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.equal(scan.findings.length, expected);
      for (const finding of scan.findings) { assert.equal(finding.severity, "info"); assert.equal(finding.metadata.balanceAvailability, "not-proven"); }
    }
    assert.ok(scanFile(file).findings.every(item => item.detectorId !== BURN_AMOUNT_WIDTH_RULE));
    assert.equal(burnAmountWidths(program, 1).complete, false);
  });
}
test("canonical burn exposes only the exact exported narrow amount width", () => {
  check("Uint<64>", "shieldedBurnAddress()");
  check("Uint<128>", "shieldedBurnAddress()");
  check("Uint<64>", "recipient");
  check("Uint<64>", "shieldedBurnAddress()", "amount + 1");
});
test("transparent aliases and resolved pure helper returns preserve amount identity", () => {
  check("Uint<64>", "shieldedBurnAddress()", "copy", "", "sendShielded", "const copy = amount;");
  check("Uint<64>", "shieldedBurnAddress()", "forward(amount)", "pure circuit forward(value: Uint<64>): Uint<64> { return value; }");
});

test("canonical immediate send and burn recipient aliases retain resolved identities", () => {
  check("Uint<64>", "shieldedBurnAddress()", "amount", "", "sendImmediateShielded", "", 1, "ShieldedCoinInfo");
  check("Uint<64>", "destination", "amount", "", "sendShielded", "const destination = shieldedBurnAddress();", 1);
  check("Uint<64>", "Mock_shieldedBurnAddress()", "amount", "module Mock { export pure circuit shieldedBurnAddress(): Either<ZswapCoinPublicKey, ContractAddress> { return default<Either<ZswapCoinPublicKey, ContractAddress>>; } } import Mock prefix Mock_;", "sendShielded", "", 0);
});

test("source findings agree across instruction/reference and cached/uncached facts", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit burn(coin: QualifiedShieldedCoinInfo, amount: Uint<64>): ShieldedSendResult { return sendShielded(disclose(coin), disclose(shieldedBurnAddress()), disclose(amount)); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    let first: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cache, cache).analyze();
      const findings = rule.run(facts); assert.equal(findings.length, 1);
      if (first) assert.deepEqual(findings, first); else first = findings;
    }
  });
});
