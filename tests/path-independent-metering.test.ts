import assert from "node:assert/strict";
import test from "node:test";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Program, scanFile } from "../src/index.js";
import { immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { withFiles } from "./helpers.js";

test("complementary-send budgets and results are independent of checkout path", context => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-path-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 250) long = join(long, "long-checkout-Ω-$-0123456789");
    mkdirSync(short); mkdirSync(long, { recursive: true });
    assert.ok(long.length >= 250);
    const results = ["positive", "corrected"].map(variant => {
      const scans = [short, long].map(directory => {
        const file = join(directory, `${variant}.compact`);
        copyFileSync(resolve("tests/fixtures/path-independent", `${variant}.compact`), file);
        const scan = scanFile(file, { detectors: ["zero-amount-complementary-send-review"] });
        assert.ok(scan.findings.every(finding => finding.location.file === file));
        const normalized = JSON.parse(JSON.stringify({
          status: scan.status, diagnostics: scan.diagnostics,
          findings: scan.findings.map(finding => [finding.detectorId, finding.location.line]),
          coverage: scan.coverage,
          values: scan.ruleObservationWork?.find(work => work.detectorId === "zero-amount-complementary-send-review")?.metrics.abstractValues,
        }, (_key, value) => typeof value === "string" ? value.split(directory).join("<checkout>") : value));
        context.diagnostic(`${variant}: directoryLength=${directory.length} ${JSON.stringify(normalized)}`);
        return normalized;
      });
      return { variant, scans };
    });
    for (const { variant, scans } of results) {
      assert.deepEqual(scans[1], scans[0], variant);
      assert.equal(scans[0].status, "complete", variant);
      assert.deepEqual(scans[0].diagnostics, [], variant);
      assert.deepEqual(scans[0].findings, variant === "positive" ? [["zero-amount-complementary-send-review", 35]] : []);
      assert.equal(typeof scans[0].values, "number");
    }
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test("metering retains compiler pathname distinctions and user operand data", () => {
  withFiles({
    "main.compact": 'import CompactStandardLibrary; import "Store" prefix A_; import "./Store" prefix B_; export circuit entry(): Field { return A_get() + B_get(); }',
    "Store.compact": 'module Store { export ledger value: Field; export circuit get(): Field { return value; } }',
  }, directory => {
    const program = new Program(join(directory, "main.compact"));
    const ledgers = program.activeSymbols().filter(symbol => symbol.kind === "ledger");
    assert.equal(ledgers.length, 2);
    assert.equal(program.files.size, 3, "physical parsing still shares bytes");
    for (const file of program.files.keys()) assert.match(program.meteringIdentity(file), /^@file\d+$/,
      "builtin sources must also be independent of the analyzer checkout");
    assert.equal(new Set(ledgers.map(symbol => program.meteringIdentity(symbol.id))).size, 2);
    for (const symbol of ledgers) {
      const identity = `${symbol.id}:snapshot`;
      let values = 0;
      const meter = Object.assign((_work: number, retained: number) => { values += retained; return true; },
        { identityText: program.meteringIdentity });
      const exact = immutableOperandKey({ identity, flows: [], ledger: new Set() }, 4096, undefined, meter);
      assert.equal(exact.key, `id:${identity}`, "actual equality keys stay distinct and unchanged");
      assert.ok(values > 0);
    }
    const source = join(directory, "Store.compact");
    const nested = JSON.stringify(JSON.stringify([source, 42]));
    assert.ok(!program.meteringIdentity(nested).includes(directory));
    const constant = "x".repeat(65537);
    assert.equal(immutableOperandKey({ constant, constantKind: "bytes", flows: [], ledger: new Set() }, 4096,
      undefined, Object.assign(() => true, { identityText: program.meteringIdentity })).complete, false,
      "the source-data size limit remains enforced");
  });
});
