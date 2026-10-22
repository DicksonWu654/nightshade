import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { domainReviewScope } from "../semantic/domain-review.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Independent exact entries share preparation and cumulative retained values.
 * Per-entry preparation/interpretation/proof uses the original step limit. */
export function observeDomainReview(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  for (const entry of program.entries) {
    const started = performance.now();
    const scope = { kind: "rule" as const, detectorId: rule.id, entry };
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let preparation = 0;
    const charge = (work: number, values: number) => {
      preparation += work; metrics.steps += work; metrics.abstractValues += values;
      if (preparation >= limits.maxSteps || metrics.abstractValues >= limits.maxValues) throw new Error("Domain review source preparation exhausted its shared allowance");
      return true;
    };
    try {
      charge(1, 0);
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Domain review requires completed baseline semantics for this entry");
      if (!domainReviewScope(program, entry, charge)) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      charge(1, 2);
      const facts = new Dataflow(program, limits.maxSteps - preparation, limits.maxPaths, limits.maxValues - metrics.abstractValues).analyzeDomainReviewEntry(entry);
      const detectorStarted = performance.now();
      try {
        if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) findings.push(...rule.run(facts));
      } finally {
        measured.detectorMs += performance.now() - detectorStarted;
        for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
      }
      diagnostics.push(...facts.diagnostics.map(issue => ({ ...issue, scope })));
      row.diagnosticCodes.push(...facts.diagnostics.map(issue => issue.code));
      if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) { row.status = "complete"; row.evidence = "exact-observation"; }
      else if (!facts.diagnostics.length) throw new Error("Exact domain review histories did not complete");
    } catch (error) {
      const code = "domain-review-preparation-unavailable";
      diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
        location: program.functions.get(entry)!.declaration.span, scope });
      row.diagnosticCodes.push(code);
    } finally { measured.analysisMs += performance.now() - started; }
  }
  measured.analysisMs -= measured.detectorMs;
  return { findings, diagnostics, coverage, work: measured };
}
