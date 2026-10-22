import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { withFiles } from "./helpers.js";
import { emptyResult } from "../src/index.js";
import { configLocation, exitStatus, readConfiguration } from "../src/config.js";
import { human, sarif } from "../src/reporting/index.js";

test("only rule-scoped incompleteness may warn; baseline, worker and configuration failures remain fatal", () => {
  const report = emptyResult();
  report.status = "incomplete"; report.coverage.baselineStatus = "complete";
  const scope = { kind: "rule" as const, detectorId: "low-entropy-hash-disclosure", entry: "entry" };
  report.coverage.rules = [{ ...scope, root: "main.compact", evidence: "unavailable", status: "incomplete", diagnosticCodes: ["analysis-budget"] }];
  report.diagnostics = [{ code: "analysis-budget", message: "Review this entry manually", location: configLocation("main.compact"), scope }];
  const strict = readConfiguration(), warning = { ...strict, ruleIncomplete: "warn" as const };
  assert.equal(exitStatus(report, strict), 2); assert.equal(exitStatus(report, warning), 0);
  assert.equal(report.status, "incomplete");
  assert.match(human(report, { ruleIncomplete: "warn" }), /WARNING:.*analysis-budget/);
  assert.match(human(report, { ruleIncomplete: "warn" }), /analysis.*remain incomplete/);
  const formatted = sarif(report, { ruleIncomplete: "warn" }) as { runs: { invocations: { executionSuccessful: boolean; toolExecutionNotifications: { level: string }[] }[] }[] };
  assert.equal(formatted.runs[0].invocations[0].executionSuccessful, false);
  assert.equal(formatted.runs[0].invocations[0].toolExecutionNotifications[0].level, "warning");
  report.coverage.baselineStatus = "incomplete"; assert.equal(exitStatus(report, warning), 2);
  report.coverage.baselineStatus = "complete";
  report.diagnostics.push({ code: "unused-suppression", message: "Unused suppression", location: configLocation(".") });
  assert.equal(exitStatus(report, warning), 2);
  report.diagnostics.pop(); report.diagnostics[0].code = "worker-timeout";
  assert.equal(exitStatus(report, warning), 2);
});

test("CLI/config warning opt-in retains finding thresholds and baseline failures", () => {
  withFiles({ "nightshade.json": JSON.stringify({ version: 1, ruleIncomplete: "warn" }) }, cwd => {
    assert.equal(readConfiguration(resolve(cwd, "nightshade.json")).ruleIncomplete, "warn");
  });
  const cli = resolve("dist/src/cli.js"), file = resolve("examples/review/contract.compact");
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, file, "--json", "--rule-incomplete", "warn", ...args], { encoding: "utf8", timeout: 15000 });
  assert.equal(run().status, 1); assert.equal(run("--fail-on", "none").status, 0);
  const limited = run("--max-steps", "1", "--fail-on", "none");
  assert.equal(limited.status, 2); assert.equal(JSON.parse(limited.stdout).status, "incomplete");
  withFiles({ "bad.json": JSON.stringify({ version: 1, ruleIncomplete: true }) }, cwd => {
    assert.throws(() => readConfiguration(resolve(cwd, "bad.json")), /ruleIncomplete/);
  });
});
