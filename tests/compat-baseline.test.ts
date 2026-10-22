import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { withFiles } from "./helpers.js";

test("compatibility baseline and audit retain rejected roots and keep baseline budgets fail-closed", () => {
  const source = readFileSync("examples/review/contract.compact", "utf8");
  withFiles({ "references/source/root.compact": source, "references/source/rejected.compact": "invalid fixture\n" }, directory => {
    const donor = resolve(directory, "references/source");
    const git = (...args: string[]) => execFileSync("git", ["-C", donor, ...args], { encoding: "utf8" }).trim();
    git("init", "--quiet"); git("add", ".");
    git("-c", "user.name=Compatibility test", "-c", "user.email=compat@example.invalid", "commit", "--quiet", "-m", "fixture");
    const hash = (text: string) => createHash("sha256").update(text).digest("hex");
    const manifest = { population: { id: "mode-fixture", roots: 2 }, repositories: [{ name: "source", commit: git("rev-parse", "HEAD") }],
      apps: [{ repository: "source", file: "root.compact", sha256: hash(source), compilerVersion: "0.34.0", compilerExitCode: 0 },
        { repository: "source", file: "rejected.compact", sha256: hash("invalid fixture\n"), compilerVersion: "0.34.0", compilerExitCode: 1 }],
      compilerProfiles: { "0.34.0": { languageVersion: "0.26" } }, dependencyTrees: [], excludedLibraries: [] };
    const manifestPath = resolve(directory, "manifest.json"); writeFileSync(manifestPath, JSON.stringify(manifest));
    const run = (name: string, mode: string, ...flags: string[]) => {
      const output = resolve(directory, name);
      execFileSync(process.execPath, [resolve("scripts/bench-compat.mjs"), "--mode", mode, "--manifest", manifestPath,
        "--references", resolve(directory, "references"), "--output", output, "--workers", "1", ...flags], { encoding: "utf8", stdio: "pipe" });
      return { report: JSON.parse(readFileSync(resolve(output, "report.json"), "utf8")), raw: JSON.parse(readFileSync(resolve(output, "scans/001.json"), "utf8")) };
    };
    const baseline = run("baseline", "baseline"), audit = run("audit", "audit"), exhausted = run("exhausted", "baseline", "--max-steps", "1");
    for (const { report } of [baseline, audit, exhausted]) {
      assert.equal(report.population.roots, 2);
      assert.equal(report.rows.length, 1); assert.equal(report.compilerRejected.length, 1);
      assert.equal(report.realApplications.totalApps, 2);
      assert.equal(report.buildChangedDuringRun, false);
    }
    assert.equal(baseline.report.analysisMode, "baseline"); assert.equal(audit.report.analysisMode, "audit");
    assert.equal(baseline.report.analyzer.distSha256, audit.report.analyzer.distSha256);
    assert.match(baseline.report.analyzer.baselineAdapter.sha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(baseline.raw.coverage.detectors, []); assert.deepEqual(baseline.raw.coverage.rules, []);
    assert.equal(baseline.raw.status, "complete"); assert.deepEqual(baseline.raw.findings, []);
    assert.equal(audit.raw.status, "complete"); assert.ok(audit.raw.findings.some((finding: { detectorId: string }) => finding.detectorId === "ledger-bound-preimage-publication"));
    assert.equal(exhausted.raw.status, "incomplete"); assert.equal(exhausted.report.summary.complete, 0);
    assert.ok(exhausted.raw.diagnostics.some((issue: { code: string }) => issue.code.endsWith("-budget")));
    assert.throws(() => run("invalid", "baseline", "--detectors", "impossible-assertion"), /Baseline mode cannot select detectors/);
    assert.throws(() => run("invalid-mode", "quiet"), /mode must be audit or baseline/);
  });
});
