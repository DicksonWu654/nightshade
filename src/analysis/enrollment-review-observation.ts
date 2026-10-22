import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { enrollmentReviewScope, STORED_ENROLLMENT_RULE } from "../semantic/enrollment-review.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Compilation-unit conjunction: all dependent entries share one unchanged
 * step/path/value allowance. Partial writers cannot yield a Cell result. */
export function observeEnrollmentReview(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [];
  let coverage: RuleCoverage[] | undefined;
  let coverageAdmitted = false;
  // Failure output has a separate fixed bound: fifteen details, one summary,
  // and at most one representative coverage row if full admission was denied.
  const detailLimit = 15;
  const retainIssue = (issue: Diagnostic, entry?: string) => {
    if (diagnostics.length >= detailLimit) return;
    diagnostics.push(entry ? { ...issue, scope: { kind: "rule", detectorId: rule.id, entry } } : issue);
  };
  const started = performance.now();
  const charge = (amount = 1, values = 0) => {
    metrics.steps += amount; metrics.abstractValues += values;
    if (metrics.steps > limits.maxSteps || metrics.abstractValues > limits.maxValues) throw new Error("Enrollment preparation exhausted its shared allowance");
    return true;
  };
  const failed = (message: string, code = "enrollment-review-preparation-unavailable") => {
    if (!coverageAdmitted) {
      code = "enrollment-review-coverage-unavailable";
      const entry = program.entries[0];
      const omitted = entry ? "Only the first entry is represented in failure coverage; remaining entries are unobserved." : "No entry coverage was admitted.";
      message = `Enrollment review coverage for ${program.entries.length} entries is unavailable: ${message}. ${omitted}`;
      coverage = entry ? [{ root: program.root, detectorId: rule.id, entry,
        status: "incomplete", evidence: "unavailable", diagnosticCodes: [code] }] : [];
    } else for (const row of coverage!) {
      // The admission reserves one failure-code slot and a reporting visit per
      // row. Failure does not construct a second inventory or per-row messages.
      row.status = "incomplete"; row.evidence = "unavailable"; row.diagnosticCodes.push(code);
    }
    const entry = program.entries[0];
    diagnostics.push({ code, message, location: program.rootSource.ast.span,
      ...(entry ? { scope: { kind: "rule" as const, detectorId: STORED_ENROLLMENT_RULE, entry } } : {}) });
  };
  try {
    // Reserve rows, arrays, retained slots and potential failure reporting
    // before constructing any of the selected entry inventory.
    charge(program.entries.length * 2, program.entries.length * 8 + 3);
    coverage = [];
    coverageAdmitted = true;
    for (const entry of program.entries) coverage.push({ root: program.root, detectorId: rule.id, entry,
      status: "incomplete", evidence: "unavailable", diagnosticCodes: [] });
    for (const entry of program.entries) { charge(); if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Enrollment review requires completed baseline semantics before scope absence"); }
    const scope = enrollmentReviewScope(program, charge);
    if (!scope.cells.length || !scope.uses.length) {
      for (const row of coverage) { charge(); row.status = "not-applicable"; row.evidence = "structural-absence"; }
      return { findings, diagnostics, coverage, work };
    }
    charge(0, 10);
    const outcomes: { entry: string; histories: number }[] = [];
    const merged: AnalysisFacts = { program, paths: [], completedEntries: [], diagnostics: [], failedAssertions: [], assertionReaches: [],
      pathSemantics: "equivalent-states", predicateScope: "all", signatureEvidence: true, metrics,
      enrollmentReviewEvidence: { ...scope, ...limits, outcomes } };
    for (const entry of scope.entries) {
      charge();
      const available = { steps: limits.maxSteps - metrics.steps, values: limits.maxValues - metrics.abstractValues, paths: limits.maxPaths - metrics.paths };
      if (available.steps <= 0 || available.values <= 0 || available.paths <= 0) throw new Error("Enrollment exact histories exhausted their shared allowance");
      const facts = new Dataflow(program, available.steps, available.paths, available.values, execution.engine ?? "instructions",
        execution.cached ?? true, execution.cached ?? true).analyzeEnrollmentReviewEntry(entry);
      for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
      if (facts.diagnostics.length || !facts.completedEntries.includes(entry)) {
        for (const issue of facts.diagnostics) { if (diagnostics.length >= detailLimit) break; retainIssue(issue, entry); }
        throw new Error("A dependent enrollment writer/use history did not complete");
      }
      charge(facts.paths.length, facts.paths.length + 4);
      outcomes.push({ entry, histories: facts.paths.length });
      merged.paths.push(...facts.paths); merged.completedEntries.push(entry);
    }
    const detectorStarted = performance.now();
    try { findings.push(...rule.run(merged)); }
    finally { work.detectorMs += performance.now() - detectorStarted; }
    if (merged.diagnostics.length) {
      for (const issue of merged.diagnostics) { if (diagnostics.length >= detailLimit) break; retainIssue(issue); }
      findings.length = 0;
      failed("The complete enrollment conjunction is unavailable", "enrollment-review-incomplete");
    } else {
      for (const row of coverage) {
        row.status = scope.entries.includes(row.entry) ? "complete" : "not-applicable";
        row.evidence = scope.entries.includes(row.entry) ? "exact-observation" : "structural-absence";
      }
    }
  } catch (error) { findings.length = 0; failed(error instanceof Error ? error.message : String(error)); }
  finally { work.analysisMs += performance.now() - started - work.detectorMs; }
  return { findings, diagnostics, coverage: coverage!, work };
}
