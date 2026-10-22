import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, type AnalysisFacts } from "../src/index.js";
import { receivedCoinNotValidated as rule } from "../src/detectors/received-coin.js";
import { receivedCoinValidation } from "../src/dataflow/coin-validation.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
ledger color: Bytes<32>; ledger price: Uint<128>;
circuit check(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value >= price, "price"); }
circuit receipt(coin: ShieldedCoinInfo): [] { receiveShielded(disclose(coin)); }
`;
function fixture(source: string, expected: Record<string, string[]>, inspect?: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(Object.fromEntries(findings.map(item => [item.metadata.entry, item.metadata.missingConstraints])), expected);
      baseline ??= findings; assert.deepEqual(findings, baseline);
      inspect?.(facts);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(Object.fromEntries(result.findings.map(item => [item.metadata.entry, item.metadata.missingConstraints])), expected);
    }
  });
}

test("receipt policy uses exact operands, aliases and successful helper assertions", () => {
  fixture(`${header}
export circuit unchecked(coin: ShieldedCoinInfo): [] { receipt(coin); }
export circuit colorOnly(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); receipt(coin); }
export circuit amountOnly(coin: ShieldedCoinInfo): [] { assert(coin.value == price, "price"); receipt(coin); }
export circuit corrected(coin: ShieldedCoinInfo): [] { check(coin); receipt(coin); }
export circuit after(coin: ShieldedCoinInfo): [] { receipt(coin); check(coin); }
export circuit wrongCoin(coin: ShieldedCoinInfo, other: ShieldedCoinInfo): [] { check(other); receipt(coin); }
export circuit linked(coin: ShieldedCoinInfo, other: ShieldedCoinInfo): [] { assert(coin == other, "same"); check(other); receipt(coin); }
export circuit linkedFloor(coin: ShieldedCoinInfo, amount: Uint<128>): [] { assert(coin.value == amount, "amount"); assert(amount >= price, "price"); assert(coin.color == color, "color"); receipt(coin); }
`, { unchecked: ["color", "value"], colorOnly: ["value"], amountOnly: ["color"], wrongCoin: ["color", "value"] });
});

test("caller terms, ignored comparisons, self-written storage and tautologies are not payment policies", () => {
  fixture(`${header}
export circuit callerTerms(coin: ShieldedCoinInfo, expected: ShieldedCoinInfo): [] { assert(coin == expected, "same"); receipt(coin); }
export circuit ignored(coin: ShieldedCoinInfo): [] { coin.color == color; coin.value == price; receipt(coin); }
export circuit tautology(coin: ShieldedCoinInfo): [] { assert(coin.color == coin.color, "color"); assert(coin.value >= (0 as Uint<128>), "nonnegative"); receipt(coin); }
export circuit overwritten(coin: ShieldedCoinInfo): [] { color = disclose(coin.color); price = disclose(coin.value); check(coin); receipt(coin); }
export circuit upperOnly(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value <= price, "ceiling"); receipt(coin); }
export circuit positive(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value > (0 as Uint<128>), "positive"); receipt(coin); }
export circuit constants(coin: ShieldedCoinInfo): [] { assert(coin.color == default<Bytes<32>>, "color"); assert(coin.value == (10 as Uint<128>), "price"); receipt(coin); }
`, { callerTerms: ["color", "value"], ignored: ["color", "value"], tautology: ["color", "value"], overwritten: ["color", "value"], upperOnly: ["value"] });
});

test("branch alternatives preserve partial validation and exclude rejected receipts", () => {
  fixture(`${header}
export circuit partial(coin: ShieldedCoinInfo, flag: Boolean): [] { if (disclose(flag)) { check(coin); } receipt(coin); }
export circuit alternatives(coin: ShieldedCoinInfo, flag: Boolean): [] { if (disclose(flag)) { check(coin); } else { assert(coin.color == color, "color"); assert(!(coin.value < price), "price"); } receipt(coin); }
export circuit rejected(coin: ShieldedCoinInfo): [] { receipt(coin); assert(false, "disabled"); }
export circuit missingOtherBranch(coin: ShieldedCoinInfo, flag: Boolean): [] { if (disclose(flag)) { assert(coin.color == color, "color"); } else { assert(coin.value >= price, "price"); } receipt(coin); }
`, { partial: ["color", "value"], missingOtherBranch: ["color", "value"] });
});

test("different receipts at one helper retain separate invocation constraints", () => {
  fixture(`${header}
export circuit twice(first: ShieldedCoinInfo, second: ShieldedCoinInfo): [] { check(first); receipt(first); receipt(second); }
module Fake { export circuit receiveShielded(value: Field): Field { return value; } }
import Fake prefix F_;
export circuit lookalike(value: Field): Field { return F_receiveShielded(value); }
`, { twice: ["color", "value"] }, facts => {
    const findings = rule.run(facts);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].metadata.successfulReceives, 1);
  });
});

test("later constant equalities cannot make a zero lower bound meaningful", () => {
  fixture(`${header}
export circuit after(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value >= price, "price"); assert(price == (0 as Uint<128>), "zero"); receipt(coin); }
export circuit before(coin: ShieldedCoinInfo): [] { assert(price == (0 as Uint<128>), "zero"); assert(coin.color == color, "color"); assert(coin.value >= price, "price"); receipt(coin); }
export circuit alias(coin: ShieldedCoinInfo, expected: Uint<128>): [] { assert(coin.color == color, "color"); assert(coin.value >= expected, "price"); assert(expected == price, "term"); assert(price == (0 as Uint<128>), "zero"); receipt(coin); }
export circuit strict(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value > price, "price"); assert(price == (0 as Uint<128>), "zero"); receipt(coin); }
export circuit positive(coin: ShieldedCoinInfo): [] { assert(coin.color == color, "color"); assert(coin.value >= price, "price"); assert(price == (10 as Uint<128>), "ten"); receipt(coin); }
`, { after: ["value"], before: ["value"], alias: ["value"] });
});

test("receipt review is opt-in and missing evidence or exhausted budgets stay incomplete", () => {
  fixture(`${header} export circuit unchecked(coin: ShieldedCoinInfo): [] { receipt(coin); }`, { unchecked: ["color", "value"] }, facts => {
    const operation = facts.paths[0].operations!.find(item => item.name === "createZswapOutput")!;
    assert.equal(receivedCoinValidation(facts.paths[0], operation.args[0], 0).complete, false);
    const missing = new Dataflow(facts.program).analyze();
    assert.deepEqual(rule.run(missing), []);
    assert.ok(missing.diagnostics.some(item => item.code === "predicate-evidence-unavailable"));
    assert.equal(scanFile(facts.program.root, { detectors: [rule.id], maxSteps: 1 }).status, "incomplete");
    assert.equal(scanFile(facts.program.root).findings.some(item => item.detectorId === rule.id), false);
  });
});

test("received-coin manifest cases compile and detect the seeded real-corpus mutation", () => {
  const manifest = JSON.parse(readFileSync(resolve("tests/corpus/manifest.json"), "utf8"));
  for (const item of manifest.receivedCoin.cases) {
    const file = resolve("tests/corpus", item.file);
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.map(item => item.location.line), item.lines);
  }
});
