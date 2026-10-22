import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { PUBLIC_SCALAR_TARGETS, PUBLIC_SCALAR_PROFILE_MESSAGE, publicScalarProfile, publicScalarScope } from "../semantic/public-scalar-targets.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import { AnalysisError, type Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Preparation, ordinary source observation and matching share entry work and
 * cumulative rule values. Failed matching is included in returned metrics. */
export function observePublicScalar(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  // A labelled no-entrypoint scan has no selected entry observation to prepare.
  if (!program.entries.length) return { findings: [] as Finding[], diagnostics: [] as Diagnostic[], coverage: [] as RuleCoverage[], work };
  // Reserve output containers, entry rows and bounded failure envelopes.
  metrics.abstractValues += 24 + program.entries.length * 20;
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  if (metrics.abstractValues > limits.maxValues) {
    const code = "public-scalar-budget";
    // The precharged failure slots retain a row for every unavailable entry;
    // refusing the inventory cannot turn omitted rows into apparent absence.
    for (const entry of program.entries) {
      diagnostics.push({ code, message: "Scalar coverage inventory exhausted the cumulative value allowance", location: program.functions.get(entry)!.declaration.span,
        scope: { kind: "rule", detectorId: rule.id, entry } });
      coverage.push({ root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [code] });
    }
    return { findings, diagnostics, coverage, work };
  }
  for (const entry of program.entries) {
    const started = performance.now(), scope = { kind: "rule" as const, detectorId: rule.id, entry }, location = program.functions.get(entry)!.declaration.span;
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let entryWork = 0, budgetCode = "public-scalar-budget";
    const charge = (steps = 1, values = 0) => {
      entryWork += steps; metrics.steps += steps; metrics.abstractValues += values;
      if (entryWork > limits.maxSteps || metrics.abstractValues > limits.maxValues)
        throw new AnalysisError({ code: budgetCode, message: "Scalar preparation exhausted the shared work/value allowance", location });
      return true;
    };
    try {
      charge(2);
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new AnalysisError({ code: "public-scalar-evidence", message: "Scalar observation requires completed baseline semantics", location });
      budgetCode = "public-scalar-target-budget";
      const target = publicScalarScope(program, entry, Math.min(20000, limits.maxSteps - entryWork), charge);
      if (!target.complete) throw new AnalysisError({ code: target.unavailable === "budget" ? "public-scalar-target-budget" : "public-scalar-target-unavailable", message: "Canonical scalar applicability is incomplete", location });
      budgetCode = "public-scalar-budget";
      if (!target.applicable) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      charge(4, 6);
      if (!publicScalarProfile(program)) throw new AnalysisError({ code: "public-scalar-profile", message: PUBLIC_SCALAR_PROFILE_MESSAGE, location });
      const flow = new Dataflow(program, limits.maxSteps - entryWork, limits.maxPaths, limits.maxValues - metrics.abstractValues,
        execution.engine ?? "instructions", execution.cached ?? true, execution.cached ?? true, "equivalent-states", false, true,
        "witness", false, false, false, true, false, false, true, false, false, false, PUBLIC_SCALAR_TARGETS);
      const facts = flow.analyzeSubset([entry]);
      const detectorStarted = performance.now();
      let result: Finding[] = [];
      try { if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) result = rule.run(facts); }
      finally {
        work.detectorMs += performance.now() - detectorStarted;
        for (const key in metrics) metrics[key as keyof typeof metrics] += facts.metrics[key as keyof typeof metrics];
      }
      for (const issue of facts.diagnostics) {
        diagnostics.push({ ...issue, scope }); row.diagnosticCodes.push(issue.code);
      }
      if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) {
        if (!row.diagnosticCodes.length) throw new AnalysisError({ code: "public-scalar-evidence", message: "Scalar source observation did not complete", location });
        continue;
      }
      findings.push(...result); row.status = "complete"; row.evidence = "exact-observation";
    } catch (error) {
      const issue = error instanceof AnalysisError ? error.diagnostic : { code: "public-scalar-observation-unavailable", message: error instanceof Error ? error.message : String(error), location };
      diagnostics.push({ ...issue, scope }); row.diagnosticCodes.push(issue.code);
    } finally { work.analysisMs += performance.now() - started; }
  }
  work.analysisMs -= work.detectorMs;
  return { findings, diagnostics, coverage, work };
}
