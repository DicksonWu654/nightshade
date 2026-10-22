import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Ajv } from "ajv";
import AjvDraft04 from "ajv-draft-04";
import { scanFile, scanFileIsolated, detectors, mergeResults } from "../src/index.js";
import { sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const example = readFileSync("examples/zero-total-detector.cjs", "utf8");
const positive = 'export ledger total: Field; export circuit clear(): [] { total = 0 as Field; }';
const customId = "custom-zero-total-write";
const cli = resolve("dist/src/cli.js");
const moduleSource = (body: string, extra = "") => `module.exports = { apiVersion: 1, factsVersion: 1, id: 'custom-check', description: 'Owned API check', requires: [], run(context) { ${body} }, ${extra} };`;

test("compiler-valid custom detector positive/corrected/lookalike use the installed API shape", () => {
  for (const [source, count] of [[positive, 1], [positive.replace("total = 0", "total = 1"), 0], [positive.replaceAll("total", "subtotal"), 0]] as const) {
    withFiles({ "main.compact": source, "rule.cjs": example }, root => {
      const file = resolve(root, "main.compact"), detectorModules = [resolve(root, "rule.cjs")];
      if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
      const report = scanFile(file, { detectorModules, detectors: [customId] });
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.equal(report.findings.length, count);
      assert.deepEqual(report.coverage.detectors, [customId]);
      assert.equal(report.customDetectors?.[0].factsVersion, 1);
      const validate = new Ajv({ strict: false }).compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
      assert.equal(validate(report), true, JSON.stringify(validate.errors));
      const serialized = sarif(report) as { runs: { tool: { driver: { rules: { id: string }[] } } }[] };
      assert.ok(serialized.runs[0].tool.driver.rules.some(rule => rule.id === customId));
      if (process.env.SARIF_SCHEMA) {
        const validateSarif = new AjvDraft04.default({ strict: false, validateFormats: false }).compile(JSON.parse(readFileSync(process.env.SARIF_SCHEMA, "utf8")));
        assert.equal(validateSarif(serialized), true, JSON.stringify(validateSarif.errors));
      }
      assert.equal(detectors.some(rule => rule.id === customId), false);
      assert.equal(scanFile(file).customDetectors, undefined);
      assert.deepEqual(scanFile(file).findings, []);
    });
  }
});

test("explicit CLI modules retain filtering, baselines, inline reasons and directory merging", () => {
  withFiles({ "first.compact": positive, "second.compact": positive.replaceAll("clear", "reset"), "rule.cjs": example,
    "nightshade.json": JSON.stringify({ version: 1, detectors: [customId] }) }, root => {
    const args = [cli, root, "--json", "--detector-module", resolve(root, "rule.cjs")];
    const execute = (extra: string[] = []) => spawnSync(process.execPath, [...args, ...extra], { encoding: "utf8", timeout: 20000 });
    const observed = execute(); assert.equal(observed.status, 1, observed.stderr);
    const report = JSON.parse(observed.stdout);
    assert.equal(report.findings.length, 2); assert.equal(report.customDetectors.length, 1);
    assert.equal(execute(["--min-severity", "low"]).status, 0);
    assert.equal(execute(["--write-baseline", resolve(root, "baseline.json")]).status, 1);
    assert.equal(execute(["--baseline", resolve(root, "baseline.json")]).status, 0);
    const missing = spawnSync(process.execPath, [cli, root, "--json"], { encoding: "utf8", timeout: 20000 });
    assert.equal(missing.status, 2); assert.ok(JSON.parse(missing.stdout).diagnostics.some((item: { code: string }) => item.code === "invalid-config"));
    writeFileSync(resolve(root, "first.compact"), 'export ledger total: Field; export circuit clear(): [] {\n// nightshade-disable-next-line custom-zero-total-write -- Intentional total reset for maintenance\ntotal = 0 as Field; }');
    const inline = scanFile(resolve(root, "first.compact"), { detectorModules: [resolve(root, "rule.cjs")], detectors: [customId] });
    assert.equal(inline.status, "complete"); assert.match(inline.findings[0].suppression?.reason ?? "", /Intentional total reset/);
    const conflicting = structuredClone(inline); conflicting.customDetectors![0].description = "Different rule";
    assert.ok(mergeResults([inline, conflicting]).diagnostics.some(item => item.code === "custom-detector-conflict"));
  });
});

test("declared facts include caller predicates, call observations and effect histories", () => {
  const source = 'import CompactStandardLibrary; export ledger table: Map<Field,Field>; circuit store(value: Field): [] { table.insert(1 as Field,disclose(value)); } export circuit entry(flag: Boolean, value: Field): [] { assert(disclose(flag),"guard"); store(value); }';
  withFiles({ "main.compact": source, "check.cjs": moduleSource(`
    const assert = require('node:assert/strict'), facts = context.facts;
    assert.equal(context.factsVersion,1); assert.equal(facts.predicateScope,'all');
    assert.equal(facts.collectionEvidence,true); assert.equal(facts.merkleEvidence,true);
    assert.ok(Array.isArray(facts.initialization)); assert.ok(facts.callReaches.length > 0);
    assert.deepEqual(facts.completedEntries,facts.program.entries);
    assert.ok(facts.paths.some(path => path.predicates.length && path.writes.length && path.operations.some(op => op.kind === 'collection-write')));
    return [];`, "requires: ['predicates','calls','merkle','collections','initialization']") }, root => {
    const file = resolve(root, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const report = scanFile(file, { detectorModules: [resolve(root, "check.cjs")] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  });
});

test("module/version/requirements and malformed findings fail explicitly without poisoning default scans", () => {
  for (const plugin of [moduleSource("return [];", "apiVersion: 2"), moduleSource("return [];", "factsVersion: 2"), moduleSource("return [];", "requires: ['unknown']"),
    moduleSource("return [];", "id: 'impossible-assertion'"), moduleSource("throw new Error('owned failure');"), moduleSource("return Promise.resolve([]);"),
    moduleSource("return [{}];"), moduleSource("return [null];"), moduleSource("const value = {}; value.self = value; return [value];")]) {
    withFiles({ "main.compact": positive, "rule.cjs": plugin }, root => {
      const file = resolve(root, "main.compact");
      const report = scanFile(file, { detectorModules: [resolve(root, "rule.cjs")] });
      assert.equal(report.status, "incomplete"); assert.ok(report.diagnostics.some(item => ["detector-module-error", "custom-detector-error"].includes(item.code)));
      assert.equal(scanFile(file).status, "complete");
    });
  }
  withFiles({ "main.compact": positive, "rule.cjs": example }, root => {
    const file = resolve(root, "main.compact"), module = resolve(root, "rule.cjs");
    for (const paths of [["https://invalid.example/rule.cjs"], ["relative.cjs"], [module, module]]) assert.equal(scanFile(file, { detectorModules: paths }).status, "incomplete");
    const experimental = scanFile(file, { detectorModules: [module], experimentalCounterQueries: true });
    assert.ok(experimental.diagnostics.some(item => item.code === "custom-detector-mode"));
  });
});

test("isolated custom findings agree; source/path/output failures remain incomplete", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "nightshade-custom-"));
  try {
    const file = resolve(root, "main.compact"), module = resolve(root, "rule.cjs");
    writeFileSync(file, positive); writeFileSync(module, example);
    const options = { detectorModules: [module], detectors: [customId] };
    const isolated = await scanFileIsolated(file, options);
    assert.equal(isolated.status, "complete"); assert.deepEqual(isolated.findings, scanFile(file, options).findings);
    const exhausted = await scanFileIsolated(file, options, { maxOutputBytes: 1024 });
    assert.equal(exhausted.status, "incomplete"); assert.equal(exhausted.diagnostics[0].code, "worker-output-budget");
    writeFileSync(file, 'export ledger total: Field; export circuit clear(flag: Boolean): [] { if (disclose(flag)) { total = 0 as Field; } else { total = 1 as Field; } }');
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const budget = await scanFileIsolated(file, { ...options, maxPaths: 1 });
    assert.equal(budget.status, "incomplete"); assert.ok(budget.diagnostics.some(item => item.code === "analysis-budget"));
    writeFileSync(module, moduleSource("context.facts.diagnostics.length = 0; context.facts.completedEntries.push(...context.facts.program.entries); return [];"));
    const retained = await scanFileIsolated(file, { detectorModules: [module], maxPaths: 1 });
    assert.equal(retained.status, "incomplete"); assert.ok(retained.diagnostics.some(item => item.code === "analysis-budget"));
    assert.deepEqual(retained.coverage.completedEntries, []);
    writeFileSync(file, 'export circuit entry(): [] { unresolved(); }');
    assert.equal((await scanFileIsolated(file, options)).status, "incomplete");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("custom incompleteness and detached histories preserve other detector evidence", () => {
  withFiles({ "main.compact": positive, "rule.cjs": example,
    "first.cjs": moduleSource("for (const path of context.facts.paths) path.writes.length = 0; context.incomplete('Application pricing policy is not modeled'); return [];") }, root => {
    const result = scanFile(resolve(root, "main.compact"), { detectorModules: [resolve(root, "first.cjs"), resolve(root, "rule.cjs")] });
    assert.equal(result.status, "incomplete"); assert.ok(result.diagnostics.some(item => item.code === "custom-detector-incomplete"));
    assert.deepEqual(result.findings.map(finding => finding.detectorId), [customId]);
  });
});

test("rejected async output stays incomplete without crashing direct API consumers", () => {
  withFiles({ "main.compact": positive, "rule.cjs": moduleSource("return Promise.reject(new Error('Owned async failure'));") }, root => {
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import {scanFile} from ${JSON.stringify(new URL("../src/index.js", import.meta.url).href)};
      const result = scanFile(${JSON.stringify(resolve(root, "main.compact"))}, {detectorModules:[${JSON.stringify(resolve(root, "rule.cjs"))}]});
      await new Promise(resolve => setImmediate(resolve));
      console.log(JSON.stringify(result));`], { encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout); assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.some((item: { code: string }) => item.code === "custom-detector-error"));
  });
});

test("custom spans match UTF-8 offsets and normalized UTF-16 positions", () => {
  const source = '/* Ω🚀 */\r\nexport ledger total: Field;\u2028export circuit clear(): [] { total = 0 as Field; }';
  withFiles({ "main.compact": source, "rule.cjs": example }, root => {
    const file = resolve(root, "main.compact"), module = resolve(root, "rule.cjs");
    const good = scanFile(file, { detectorModules: [module] });
    assert.equal(good.status, "complete", JSON.stringify(good.diagnostics)); assert.equal(good.findings.length, 1);
    writeFileSync(module, example + '\nconst original = module.exports.run; module.exports.run = context => original(context).map(f => ({...f, location: {...f.location, line: 9999, endLine: 9999}}));');
    const bad = scanFile(file, { detectorModules: [module] });
    assert.equal(bad.status, "incomplete"); assert.ok(bad.diagnostics.some(item => item.code === "custom-detector-error"));
  });
});

test("[timing] a nonterminating trusted detector is stopped by the existing worker", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "nightshade-custom-timeout-"));
  try {
    const file = resolve(root, "main.compact"), module = resolve(root, "rule.cjs");
    writeFileSync(file, positive); writeFileSync(module, moduleSource("require('node:fs').writeFileSync(__dirname + '/started','yes'); while (true) {}"));
    const report = await scanFileIsolated(file, { detectorModules: [module] }, { timeoutMs: 2000 });
    assert.ok(existsSync(resolve(root, "started"))); assert.equal(report.status, "incomplete"); assert.equal(report.diagnostics[0].code, "worker-timeout");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("custom finding validation accepts the critical severity shared with built-in rules", () => {
  withFiles({ "main.compact": positive, "rule.cjs": example.replace('severity: "info"', 'severity: "critical"') }, root => {
    const report = scanFile(resolve(root, "main.compact"), { detectorModules: [resolve(root, "rule.cjs")], detectors: [customId] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].severity, "critical");
  });
});
