import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { withFiles } from "./helpers.js";

const binary = resolve("dist/src/cli.js");

test("the installed CLI never executes a planted working-directory explorer", () => {
  withFiles({
    "scripts/explore.mjs": "import { writeFileSync } from 'node:fs'; writeFileSync('executed', 'yes'); console.log('PLANTED');",
    "main.compact": "export circuit entry(): [] {}",
  }, cwd => {
    for (const args of [["explore", "main.compact"], ["explore"], ["--help"]]) {
      const result = spawnSync(process.execPath, [binary, ...args], { cwd, encoding: "utf8", timeout: 15000 });
      assert.equal(result.error, undefined);
      assert.equal(result.status, args[0] === "--help" ? 0 : 2);
      assert.doesNotMatch(result.stdout + result.stderr, /PLANTED|MODULE_NOT_FOUND/);
      assert.equal(existsSync(resolve(cwd, "executed")), false);
      if (args[0] === "--help") assert.doesNotMatch(result.stdout, /nightshade explore|historical default|schema 1\.7\.0|for compatibility/);
    }
  });
});


test("usage aliases work and human argument errors use stderr without a scan envelope", () => {
  for (const arg of ["help", "-h", "--help"]) {
    const row = spawnSync(process.execPath, [binary, arg], { encoding: "utf8" });
    assert.equal(row.status, 0); assert.match(row.stdout, /nightshade \[scan\]/); assert.equal(row.stderr, "");
  }
  for (const arg of ["-V", "--version"]) {
    const row = spawnSync(process.execPath, [binary, arg], { encoding: "utf8" });
    assert.equal(row.status, 0); assert.equal(row.stdout.trim(), "Nightshade 0.1.0");
  }
  for (const arg of ["-v", "--bogus"]) {
    const row = spawnSync(process.execPath, [binary, arg], { encoding: "utf8" });
    assert.equal(row.status, 2); assert.equal(row.stdout, "");
    assert.equal(row.stderr.trim(), `nightshade: unknown option '${arg}' (see --help)`);
    const json = spawnSync(process.execPath, [binary, arg, "--json"], { encoding: "utf8" });
    assert.equal(json.status, 2); assert.equal(JSON.parse(json.stdout).status, "incomplete");
  }
});


test("detector JSON lists only implemented IDs with documented ratings and maturity", () => {
  const row = spawnSync(process.execPath, [binary, "detector", "list", "--json"], { encoding: "utf8" });
  assert.equal(row.status, 0, row.stderr);
  const rules = JSON.parse(row.stdout) as { id: string; severity: string; confidence: string; maturity: string; severityLevels: string[]; defaultEnabled: boolean; policyRequired: boolean }[];
  assert.equal(rules.length, 96);
  assert.equal(new Set(rules.map(r => r.id)).size, rules.length);
  for (const r of rules) {
    assert.ok(["info", "low", "medium", "high", "critical", "varies"].includes(r.severity), r.id);
    assert.ok(["low", "medium", "high", "varies"].includes(r.confidence), r.id);
    assert.equal(r.maturity, "experimental"); assert.ok(r.severityLevels.length);
    assert.equal(typeof r.defaultEnabled, "boolean", r.id);
    assert.equal(typeof r.policyRequired, "boolean", r.id);
    assert.ok(!["context-binding-review", "field-arithmetic-domain-review", "terminal-state-exclusivity-review"].includes(r.id));
  }
  for (const [id, enabled, required] of [["ledger-bound-preimage-publication", true, false], ["declared-secret-publication", true, true], ["unbounded-mint", false, false]] as const) {
    const rule = rules.find(rule => rule.id === id)!;
    assert.deepEqual([rule.defaultEnabled, rule.policyRequired], [enabled, required], id);
    const shown = JSON.parse(spawnSync(process.execPath, [binary, "detector", "show", id, "--json"], { encoding: "utf8" }).stdout)[0];
    assert.deepEqual([shown.defaultEnabled, shown.policyRequired], [enabled, required], id);
  }
});

test("missing paths have friendly CLI errors and retain incomplete JSON and SARIF results", () => {
  withFiles({}, root => {
    const path = resolve(root, "missing source.compact");
    for (const args of [[path], ["--config", path]]) {
      const human = spawnSync(process.execPath, [binary, ...args], { encoding: "utf8" });
      assert.equal(human.status, 2);
      assert.equal(human.stdout, "");
      assert.equal(human.stderr.trim(), `nightshade: path not found: ${path} (see --help)`);
      const json = spawnSync(process.execPath, [binary, ...args, "--json"], { encoding: "utf8" });
      assert.equal(json.status, 2);
      const report = JSON.parse(json.stdout);
      assert.equal(report.status, "incomplete");
      assert.equal(report.diagnostics[0].code, "input-error");
      assert.equal(report.diagnostics[0].message, `path not found: ${path}`);
      assert.equal(report.diagnostics[0].location.file, path);
      const sarif = spawnSync(process.execPath, [binary, ...args, "--sarif"], { encoding: "utf8" });
      assert.equal(sarif.status, 2);
      const invocation = JSON.parse(sarif.stdout).runs[0].invocations[0];
      assert.equal(invocation.executionSuccessful, false);
      assert.equal(invocation.toolExecutionNotifications[0].message.text, `input-error: path not found: ${path}`);
    }
  });
});
