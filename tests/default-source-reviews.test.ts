import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, scanFileIsolated, detectors, type Finding } from "../src/index.js";

const families = [
  { rule: "zero-amount-unshielded-send", fixture: "counter-zero-unshielded-send", lines: [29, 33], defaultEnabled: false },
  { rule: "merkle-insert-without-dedupe", fixture: "counter-merkle-insert-dedupe", lines: [31], defaultEnabled: false },
  { rule: "field-recomposition-range-review", fixture: "counter-field-recomposition", lines: [32], defaultEnabled: true },
  { rule: "merkle-leaf-binding-review", fixture: "counter-merkle-leaf-commitment", lines: [35], defaultEnabled: true },
  { rule: "merkle-leaf-binding-review", fixture: "single", directory: "drafts/merkle-byte-binding", lines: [10], defaultEnabled: true },
] as const;

for (const family of families) test(`actionability-gated informational review preserves selected source evidence: ${family.rule}, ${family.fixture}`, async () => {
  const directory = "directory" in family ? family.directory : "known-bugs";
  const informationalReview = (finding: Finding) => finding.severity === "info" &&
    (family.rule === "merkle-leaf-binding-review"
      ? finding.metadata.doesNotProve === "security-flaw-or-exploitability"
      : finding.metadata.pathFeasibility === "not-proven");
  for (const experimentalCounterQueries of [false, true]) {
    const options = { experimentalCounterQueries };
    const file = resolve(`tests/corpus/${directory}/${family.fixture}-positive.compact`);
    const selected = scanFile(file, { ...options, detectors: [family.rule] });
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.deepEqual(selected.findings.map(finding => finding.location.line), family.lines);
    const direct = scanFile(file, options);
    const isolated = await scanFileIsolated(file, options);
    const expected = family.defaultEnabled ? selected.findings : [];
    assert.deepEqual(direct.findings.filter(finding => finding.detectorId === family.rule), expected);
    // The supervised worker uses JSON transport, which omits undefined fields.
    assert.deepEqual(isolated.findings.filter(finding => finding.detectorId === family.rule), JSON.parse(JSON.stringify(expected)));
    const selectedIsolated = await scanFileIsolated(file, { ...options, detectors: [family.rule] });
    assert.equal(selectedIsolated.status, "complete", JSON.stringify(selectedIsolated.diagnostics));
    assert.deepEqual(selectedIsolated.findings, JSON.parse(JSON.stringify(selected.findings)));
    assert.ok(selected.findings.every(informationalReview));
    for (const report of [direct, isolated]) {
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.equal(report.coverage.detectors.includes(family.rule), family.defaultEnabled);
      const findings = report.findings.filter(finding => finding.detectorId === family.rule);
      assert.ok(findings.every(informationalReview));
    }
    for (const variant of ["corrected", "lookalike"]) {
      const controlFile = resolve(`tests/corpus/${directory}/${family.fixture}-${variant}.compact`);
      const control = scanFile(controlFile, options);
      if ("directory" in family && variant === "corrected" && !experimentalCounterQueries) {
        // This new byte fixture already exposes a low-entropy compression gap.
        // Adding leaf binding must preserve that explicit independent limitation.
        const previous = scanFile(controlFile, { ...options,
          detectors: detectors.filter(rule => rule.defaultEnabled !== false && rule.id !== family.rule).map(rule => rule.id) });
        assert.equal(control.status, "incomplete");
        assert.equal(previous.status, "incomplete");
        assert.equal(control.coverage.baselineStatus, "complete");
        assert.deepEqual(control.diagnostics, previous.diagnostics);
        assert.deepEqual(control.diagnostics.map(issue => [issue.code, issue.scope?.detectorId]),
          [["observation-compression-dependency", "low-entropy-hash-disclosure"]]);
        assert.ok(control.coverage.rules!.filter(row => row.detectorId === family.rule).every(row => row.status === "complete"));
      } else assert.equal(control.status, "complete", JSON.stringify(control.diagnostics));
      assert.equal(control.coverage.detectors.includes(family.rule), family.defaultEnabled);
      assert.deepEqual(control.findings.filter(finding => finding.detectorId === family.rule), []);
    }
  }
});
