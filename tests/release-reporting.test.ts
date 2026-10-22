import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import { human, sarif } from "../src/reporting/index.js";
import { withFiles } from "./helpers.js";

test("human coverage is concise by default and retains incomplete rows", () => {
  const result = scanFile(resolve("examples/review/corrected.compact"));
  assert.equal(result.status, "complete");
  const concise = human(result), verbose = human(result, { verbose: true });
  assert.match(concise, /Rule coverage: \d+ selected rule\(s\); 0 with incomplete entries/);
  assert.doesNotMatch(concise, /Rule coverage [a-z-]+:/);
  assert.match(verbose, /Rule coverage [a-z-]+:/);
  assert.match(concise, /analysis complete\./);
  assert.doesNotMatch(concise.split("\n").at(-1)!, /[ \t]+$/);
  assert.ok(human({ ...result, compilerValidated: true }).endsWith(" Compiler validation passed."));
  assert.doesNotMatch(concise, /experimental subset|validity not established|validation not requested/);
  const row = result.coverage.rules![0];
  row.status = "incomplete"; result.status = "incomplete";
  const incomplete = human(result);
  assert.match(incomplete, /1 with incomplete entries/);
  assert.ok(incomplete.includes(`Rule coverage ${row.detectorId}:`));
  assert.match(incomplete, /analysis incomplete\./);
});


test("SARIF embeds per-rule help, descriptions, default levels and honest priority metadata", () => {
  const result = scanFile(resolve("examples/review/contract.compact"));
  const output = sarif(result) as { runs: { tool: { driver: { informationUri?: string; rules: { id: string; fullDescription: { text: string }; help: { text: string; markdown: string }; helpUri?: string; defaultConfiguration: { level: string }; properties: Record<string, unknown> }[] } } }[] };
  const driver = output.runs[0].tool.driver;
  assert.equal(driver.rules.length, 96);
  for (const rule of driver.rules) {
    assert.ok(rule.fullDescription.text.length > 20, rule.id);
    assert.ok(rule.help.markdown.includes("#"), rule.id);
    assert.equal(rule.help.text, rule.help.markdown);
    assert.ok(["note", "warning", "error"].includes(rule.defaultConfiguration.level));
    assert.ok(Number.isFinite(Number(rule.properties["security-severity"])));
    assert.equal(rule.properties.maturity, "experimental");
    const levels = rule.properties.severityLevels as string[];
    if (levels.length === 1) assert.equal(rule.properties["security-severity"],
      ({ info: "0.0", low: "3.0", medium: "5.0", high: "8.0", critical: "9.5" } as Record<string, string>)[levels[0]], rule.id);
  }
  const direct = driver.rules.find(rule => rule.id === "ledger-bound-preimage-publication")!;
  assert.equal(direct.defaultConfiguration.level, "warning");
  assert.equal(direct.properties["security-severity"], "5.0");
  assert.doesNotMatch(String(driver.informationUri ?? ""), /example|OWNER|TODO/);
});

test("shared authorization SARIF priority stays low while finding severities retain their grades", () => {
  withFiles({ "main.compact": `ledger value: Field; witness valid(): Boolean;
export circuit validate(next: Field): [] { assert(valid(), "check"); value = disclose(next); }
export circuit mint(next: Field): [] { assert(valid(), "check"); value = disclose(next); }` }, directory => {
    const report = scanFile(resolve(directory, "main.compact"), { detectors: ["spoofable-authorization"] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(finding => finding.severity).sort(), ["critical", "low"]);
    const output = sarif(report) as { runs: { tool: { driver: { rules: { id: string; defaultConfiguration: { level: string }; properties: Record<string, unknown> }[] } }; results: { level: string; properties: { severity: string } }[] }[] };
    const run = output.runs[0];
    const rule = run.tool.driver.rules.find(rule => rule.id === "spoofable-authorization")!;
    assert.equal(rule.properties["security-severity"], "3.0");
    assert.equal(rule.defaultConfiguration.level, "warning");
    assert.deepEqual(rule.properties.severityLevels, ["low", "high", "critical"]);
    assert.deepEqual(run.results.map(finding => [finding.properties.severity, finding.level]).sort(), [["critical", "error"], ["low", "warning"]]);
  });
});


test("finding text omits empty call paths while retaining known callers", () => {
  const report = scanFile(resolve("examples/review/contract.compact"));
  assert.equal(report.findings.length, 1);
  report.findings[0].callPath = [];
  assert.doesNotMatch(human(report), /Call path:/);
  report.findings[0].callPath = ["entry", "helper"];
  assert.match(human(report), /Call path: entry → helper/);
});
