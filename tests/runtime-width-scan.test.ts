import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { scanFile, scanFileIsolated } from "../src/index.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const id = "shielded-coin-runtime-width";
const body = `import CompactStandardLibrary;
export circuit wide(): [] {
  const coin = ShieldedCoinInfo { nonce: pad(32, "nonce"), color: pad(32, "color"),
    value: 18446744073709551616 as Uint<128> };
  createZswapOutput(coin, left<ZswapCoinPublicKey, ContractAddress>(default<ZswapCoinPublicKey>));
}
export circuit idle(): [] {}`;

test("opt-in reference width diagnosis survives the worker and leaves default findings unchanged", async context => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-runtime-width-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact"); writeFileSync(file, body);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const ordinary = scanFile(file), selected = scanFile(file, { detectors: [id] });
  assert.equal(ordinary.status, "complete", JSON.stringify(ordinary.diagnostics));
  assert.ok(ordinary.findings.every(item => item.detectorId !== id));
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  assert.equal(selected.findings.length, 1);
  assert.equal(selected.findings[0].severity, "low");
  assert.equal(selected.findings[0].confidence, "high");
  assert.deepEqual(selected.coverage.rules!.map(row => row.status), ["complete", "not-applicable"]);
  const worker = await scanFileIsolated(file, { detectors: [id] });
  assert.deepEqual(worker.findings, selected.findings);
  assert.deepEqual(worker.coverage, selected.coverage);
  const failed = scanFile(file, { detectors: [id], maxSteps: 1 });
  assert.equal(failed.coverage.baselineStatus, "incomplete");
  assert.ok(failed.diagnostics.some(issue => issue.code === "runtime-width-baseline-incomplete" && issue.scope?.detectorId === id));
  assert.deepEqual(failed.findings, []);
});

test("each relevant entry has an independent width observation obligation", () => {
  withFiles({ "main.compact": body + `
export circuit narrow(): [] {
  createZswapOutput(ShieldedCoinInfo { nonce: pad(32, "n"), color: pad(32, "c"),
    value: 1 }, left<ZswapCoinPublicKey, ContractAddress>(default<ZswapCoinPublicKey>));
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { detectors: [id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.diagnostics, []);
    assert.equal(report.findings.length, 1);
    assert.deepEqual(report.coverage.rules!.map(row => row.status), ["complete", "not-applicable", "complete"]);
  });
});

test("unsupported reference profiles invalidate only relevant width obligations", () => {
  withFiles({ "main.compact": body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_035_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_035_TEST, file, [], 30000, 2, "0.35.0");
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { compilerVersion: "0.35.0", detectors: [id] });
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.status, "incomplete");
    assert.deepEqual(report.findings, []);
    assert.deepEqual(report.coverage.rules!.map(row => row.status), ["incomplete", "not-applicable"]);
    assert.ok(report.diagnostics.every(issue => issue.code === "runtime-width-profile-unavailable" && issue.scope?.detectorId === id));
    assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
    const rendered = sarif(report) as { runs: { properties: { coverage: typeof report.coverage } }[] };
    assert.deepEqual(rendered.runs[0].properties.coverage, report.coverage);
  });
});
