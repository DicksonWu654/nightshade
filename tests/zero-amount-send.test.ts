import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile } from "../src/index.js";
import { zeroSendFindings } from "../src/detectors/zero-send.js";
import { ZERO_SEND_RULE, ZERO_SEND_TARGET } from "../src/semantic/zero-send-targets.js";
import { Dataflow } from "../src/dataflow/index.js";
import { Program } from "../src/semantic/index.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = `import CompactStandardLibrary;
export circuit probe(amount: Uint<128>, other: Uint<128>, flag: Boolean): [] {`;
const send = `sendUnshielded(default<Bytes<32>>, disclose(amount), right<ContractAddress, UserAddress>(default<UserAddress>));`;
function check(body: string, expected: number) {
  withFiles({ "main.compact": `${header}${body}}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(result.valid, true, result.error);
    }
    const scan = scanFile(file, { detectors: [ZERO_SEND_RULE] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.equal(scan.findings.length, expected);
    for (const item of scan.findings) {
      assert.equal(item.severity, "info"); assert.equal(item.metadata.pathFeasibility, "not-proven");
    }
  });
}

test("owned frozen-study seeds: caller amount, constant zero, positive guard and namesake", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-zero-unshielded-send-${variant}.compact`);
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(result.valid, true, result.error);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [ZERO_SEND_RULE], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(item => item.location.line), variant === "positive" ? [29, 33] : []);
    }
    assert.equal(scanFile(file).findings.some(item => item.detectorId === ZERO_SEND_RULE), false);
  }
});

test("actual immutable amount equality, exclusion and range guards suppress zero review", () => {
  for (const guard of ["amount > 0", "0 < amount", "amount >= 1", "amount != 0", "!(amount == 0)", "amount == 1"])
    check(`assert(${guard}, "positive"); ${send}`, 0);
  check(`const saved = amount; assert(saved > 0, "alias"); ${send}`, 0);
  check(`assert(amount == other, "same"); assert(other > 0, "positive"); ${send}`, 0);
  check(`${send} assert(amount > 0, "atomic completion");`, 0);
  check(`if (disclose(flag)) { assert(amount > 0, "positive"); ${send} }`, 0);
});

test("unrelated guards and separate histories cannot donate a positive lower bound", () => {
  check(`assert(other > 0, "unrelated"); ${send}`, 1);
  check(`if (disclose(flag)) { assert(amount > 0, "positive"); } ${send}`, 1);
  check(`assert(amount >= 0, "zero allowed"); ${send}`, 1);
});

test("missing observations and budgets yield rule-scoped incomplete evidence", () => {
  withFiles({ "main.compact": `${header}${send}}` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(zeroSendFindings(facts), []);
    assert.ok(facts.diagnostics.some(item => item.scope?.kind === "rule" && item.scope.detectorId === ZERO_SEND_RULE));
    const exact = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true,
      "all", false, false, false, true, false, false, false, false, false, true, new Set([ZERO_SEND_TARGET])).analyze();
    assert.equal(zeroSendFindings(exact).length, 1);
    assert.deepEqual(zeroSendFindings(exact, 0), []);
    assert.ok(exact.diagnostics.some(item => item.scope?.detectorId === ZERO_SEND_RULE));
    const scan = scanFile(program.root, { detectors: [ZERO_SEND_RULE], maxSteps: 1 });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.some(item => item.scope?.detectorId === ZERO_SEND_RULE));
  });
});

test("canonical import aliases and cached/reference histories preserve range evidence", () => {
  for (const guard of ["", 'assert(amount > 0, "positive");']) {
    const source = `${header}${guard}${send}}`.replace("import CompactStandardLibrary;", "import CompactStandardLibrary; import { sendUnshielded as forwardSend } from CompactStandardLibrary;").replace("sendUnshielded(default", "forwardSend(default");
    withFiles({ "main.compact": source }, directory => {
      const file = resolve(directory, "main.compact");
      if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
      const program = new Program(file);
      for (const [engine, cached] of [["instructions", true], ["instructions", false], ["expressions", false]] as const) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
          "all", false, false, false, true, false, false, false, false, false, true, new Set([ZERO_SEND_TARGET])).analyze();
        assert.deepEqual(facts.diagnostics, []);
        assert.equal(zeroSendFindings(facts).length, guard ? 0 : 1);
      }
    });
  }
});
