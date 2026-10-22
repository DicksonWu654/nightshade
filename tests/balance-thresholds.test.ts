import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { balanceThresholds, BALANCE_THRESHOLD_RULE } from "../src/semantic/balance-thresholds.js";
import { exactBalanceThreshold as rule } from "../src/detectors/balance-thresholds.js";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
import { AnalysisError } from "../src/model.js";

const header = "import CompactStandardLibrary; export ledger saved: Uint<128>;";
function source(body: string, inspect: (program: Program, file: string) => void, imports = header): void {
  withFiles({ "main.compact": `${imports}\nexport circuit entry(color: Bytes<32>, amount: Uint<128>): [] { ${body} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    inspect(new Program(file), file);
  });
}
function expect(body: string, replacements: string[], imports?: string): void {
  source(body, (program, file) => {
    const query = balanceThresholds(program);
    assert.equal(query.complete, true);
    assert.deepEqual(query.observations.map(row => row.replacement), replacements);
    let first: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts);
      assert.deepEqual(findings.map(item => item.metadata.replacement), replacements);
      assert.ok(findings.every(item => item.severity === "info" && item.confidence === "high" && item.metadata.runtimeReachability === "not-proven"));
      if (first) assert.deepEqual(findings, first); else first = findings;
    }
    const baseline = scanFile(file), selected = scanFile(file, { detectors: [BALANCE_THRESHOLD_RULE] });
    assert.equal(baseline.status, "complete"); assert.equal(selected.status, "complete");
    assert.ok(baseline.findings.every(item => item.detectorId !== BALANCE_THRESHOLD_RULE));
    assert.equal(selected.findings.length, replacements.length);
  }, imports);
}

test("direct and reversed thresholds select the comparison helper with the same bound", () => {
  for (const [op, direct, reverse] of [["<", "Lt", "Gt"], ["<=", "Lte", "Gte"], [">", "Gt", "Lt"], [">=", "Gte", "Lte"]]) {
    expect(`assert(unshieldedBalance(disclose(color)) ${op} disclose(amount), "balance");`, [`unshieldedBalance${direct}`]);
    expect(`assert(disclose(amount) ${op} unshieldedBalance(disclose(color)), "balance");`, [`unshieldedBalance${reverse}`]);
  }
});

test("immutable alias chains, disclosure and identity casts retain the exact getter", () => {
  expect('const balance = unshieldedBalance(disclose(color)); const copy = disclose(balance); const copied = copy as Uint<128>; assert(copied >= disclose(amount), "balance");', ["unshieldedBalanceGte"]);
  expect('const balance = unshieldedBalance(disclose(color)); const unusedCopy = balance; assert(disclose(balance) >= disclose(amount), "balance");', ["unshieldedBalanceGte"]);
});

test("lambda-local aliases remain local while outer aliases are retained captures", () => {
  expect('const checked = map((item: Uint<128>): Uint<128> => { const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); return item; }, [amount]);', ["unshieldedBalanceGte"]);
  expect('const checked = map((item: Uint<128>): Uint<128> => { assert(unshieldedBalance(disclose(color)) >= disclose(amount), "balance"); return item; }, [amount]);', ["unshieldedBalanceGte"]);
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); const checked = map((item: Uint<128>): Uint<128> => { const copy = balance; return copy; }, [amount]);', []);
});

test("other uses retain deliberate snapshots, equality, transforms and repeated thresholds", () => {
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); saved = disclose(balance);', []);
  expect('assert(unshieldedBalance(disclose(color)) == disclose(amount), "exact balance");', []);
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "lower"); assert(balance <= disclose(amount), "upper");', []);
  expect('const balance = unshieldedBalance(disclose(color)) + 0; assert(balance >= disclose(amount), "balance");', []);
  expect('assert(unshieldedBalanceGte(disclose(color), disclose(amount)), "balance");', []);
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); const captured = map((item: Uint<128>): Uint<128> => balance, [amount]); saved = disclose(captured[0]);', []);
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); if (false) { saved = disclose(balance); }', []);
  expect('const balance = unshieldedBalance(disclose(color)); assert(balance >= disclose(amount), "balance"); saved = disclose(((): Uint<128> => balance)());', []);
  expect('const balance = unshieldedBalance(disclose(color)); const copy = balance; assert(balance >= disclose(amount), "balance"); saved = disclose(((): Uint<128> => copy)());', []);
});

test("a wider bound does not receive a same-bound helper recommendation", () => {
  withFiles({ "main.compact": `${header} export circuit entry(color: Bytes<32>, amount: Uint<129>): [] { assert(unshieldedBalance(disclose(color)) >= disclose(amount), "balance"); }`,
    "invalid-helper.compact": `${header} export circuit entry(color: Bytes<32>, amount: Uint<129>): [] { assert(unshieldedBalanceGte(disclose(color), disclose(amount)), "balance"); }` }, directory => {
    const file = resolve(directory, "main.compact"), invalid = resolve(directory, "invalid-helper.compact");
    if (process.env.COMPACTC_TEST) {
      assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
      assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, invalid).valid, false);
    }
    assert.equal(balanceThresholds(new Program(file)).complete, true);
    assert.deepEqual(balanceThresholds(new Program(file)).observations, []);
    assert.throws(() => new Program(invalid), error => error instanceof AnalysisError && error.diagnostic.code === "call-type-mismatch");
  });
});

test("canonical import aliases match and application namesakes remain quiet", () => {
  expect('assert(readBalance(disclose(color)) >= disclose(amount), "balance");', ["unshieldedBalanceGte"], 'import { unshieldedBalance as readBalance } from CompactStandardLibrary;');
  expect('assert(Mock_unshieldedBalance(disclose(color)) >= disclose(amount), "balance");', [], `import CompactStandardLibrary;
    module Mock { export circuit unshieldedBalance(color: Bytes<32>): Uint<128> { return 7; } }
    import Mock prefix Mock_;`);
});

test("source query budgets discard partial observations instead of certifying absence", () => {
  source('assert(unshieldedBalance(disclose(color)) >= disclose(amount), "balance");', program => {
    const complete = balanceThresholds(program); assert.equal(complete.observations.length, 1);
    for (const allowance of [0, 1, complete.work - 1]) {
      const exhausted = balanceThresholds(program, allowance);
      assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
    }
  });
});

test("source budget failure is rule scoped and does not degrade baseline completion", () => {
  source('assert(unshieldedBalance(disclose(color)) >= disclose(amount), "balance");' + '0;'.repeat(8000), (_program, file) => {
    const report = scanFile(file, { detectors: [BALANCE_THRESHOLD_RULE] });
    assert.equal(report.status, "incomplete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.some(item => item.code === "balance-threshold-observation-budget" && item.scope?.detectorId === BALANCE_THRESHOLD_RULE));
    assert.ok(report.coverage.rules?.every(row => row.status === "incomplete"));
  });
});

test("selecting a source-only rule retains baseline correlated admission", () => {
  const parameters = Array.from({ length: 10 }, (_, i) => `branch${i}: Boolean`).join(", ");
  const branches = Array.from({ length: 10 }, (_, i) => `if (disclose(branch${i})) { total = total + 1; }`).join(" ");
  withFiles({ "main.compact": `${header} export ledger total: Field; export circuit entry(${parameters}): [] { ${branches} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const baseline = scanFile(file), selected = scanFile(file, { detectors: [BALANCE_THRESHOLD_RULE] });
    assert.equal(baseline.coverage.baselineStatus, "complete", JSON.stringify(baseline.diagnostics));
    assert.equal(selected.coverage.baselineStatus, "complete", JSON.stringify(selected.diagnostics));
    assert.equal(selected.status, "complete");
    assert.deepEqual(selected.coverage.completedEntries, baseline.coverage.completedEntries);
    assert.deepEqual(selected.findings, []);
  });
});

test("owned real Counter triplet is compiler valid and follows the documented static contract", () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-balance-threshold-${kind}.compact`);
    assert.match(readFileSync(file, "utf8"), /round.increment\(1\)/);
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error);
    }
    const report = scanFile(file, { detectors: [BALANCE_THRESHOLD_RULE] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [20] : []);
  }
});
