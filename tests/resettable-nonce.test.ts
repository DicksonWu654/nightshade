import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { resettableListNonce as rule } from "../src/detectors/resettable-nonce.js";
import { resettableNoncePairs } from "../src/dataflow/resettable-nonce.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
const prefix = `import CompactStandardLibrary;\nledger memos: List<Bytes<32>>;\n`;
function check(nonce: string, reset: string, expected: number) {
  const source = `${prefix}export circuit mint(): [] { mintShieldedToken(default<Bytes<32>>, 1, ${nonce}, right<ZswapCoinPublicKey, ContractAddress>(kernel.self())); memos.pushFront(default<Bytes<32>>); }\nexport circuit prune(): [] { ${reset} }`;
  checkSource(source, expected);
}
function checkSource(source: string, expected: number) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file); let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, false, false, true, false, false, true, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts); assert.deepEqual(facts.diagnostics, []); assert.equal(findings.length, expected);
      if (source.includes("ledger queues") && expected) assert.ok(findings.every(finding => finding.metadata.selectorRelation === "may-overlap"));
      baseline ??= findings; assert.deepEqual(findings, baseline);
      assert.equal(resettableNoncePairs(facts, program.entries, 0).complete, false);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics)); assert.equal(result.findings.length, expected);
    }
  });
}
test("whole List hash-derived coin nonce and exported reset", () => {
  check("persistentHash<Uint<64>>(memos.length() as Uint<64>)", "memos.resetToDefault();", 1);
  check("evolveNonce(memos.length() as Uint<64>, default<Bytes<32>>)", "memos.resetToDefault();", 1);
  check("default<Bytes<32>>", "memos.resetToDefault();", 0);
  check("persistentHash<Uint<64>>(memos.length() as Uint<64>)", "", 0);
  check("persistentHash<Uint<64>>(memos.length() as Uint<64>)", 'memos.resetToDefault(); assert(false, "disabled");', 0);
});

test("keyed Lists retain may-overlap evidence without wildcard equality", () => {
  const fixture = (read: string, reset: string) => `import CompactStandardLibrary;
ledger queues: Map<Uint<8>, List<Bytes<32>>>;
export circuit mint(key: Uint<8>): [] { assert(queues.member(disclose(key)), "present");
  mintShieldedToken(default<Bytes<32>>, 1, evolveNonce(queues.lookup(${read}).length() as Uint<64>, default<Bytes<32>>), right<ZswapCoinPublicKey, ContractAddress>(kernel.self())); }
export circuit prune(other: Uint<8>): [] { queues.insert(${reset}, default<List<Bytes<32>>>); }`;
  checkSource(fixture("disclose(key)", "disclose(other)"), 1);
  checkSource(fixture("1", "2"), 0);
});
test("owned compiler triplet", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/library-credit-nonce-reset-${variant}.compact`);
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, variant === "positive" ? 1 : 0);
    }
  }
});
test("missing evidence and Counter absence are explicit", () => {
  withFiles({ "main.compact": `${prefix}export circuit mint(): [] {
    mintShieldedToken(default<Bytes<32>>, 1, evolveNonce(memos.length() as Uint<64>, default<Bytes<32>>), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));
  } export circuit prune(): [] { memos.resetToDefault(); }` }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact"))).analyze();
    assert.equal(facts.diagnostics.length, 0);
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.code === "resettable-nonce-evidence-unavailable"));
  });
  withFiles({ "main.compact": "import CompactStandardLibrary; ledger count: Counter; export circuit step(flag: Boolean): [] { count.resetToDefault(); if (disclose(flag)) { count.increment(1); } }" }, directory => {
    const file = resolve(directory, "main.compact");
    const facts = new Dataflow(new Program(file)).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.deepEqual(facts.diagnostics, []);
    const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries: true, maxPaths: 1 });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 0);
  });
});
