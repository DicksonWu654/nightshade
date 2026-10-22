import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { CLOSED_CAPACITY_RULE, closedCapacityScope, type ClosedCapacityScope } from "../semantic/closed-capacity.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Closure is discovered once and retained under the rule's cumulative values.
 * Its failure is propagated linearly; no entry retries an exhausted traversal. */
export function observeClosedCapacity(program: Program, rule: Detector, options: { maxSteps?: number; maxPaths?: number; maxValues?: number }) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0, statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: CLOSED_CAPACITY_RULE, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const coverage: RuleCoverage[] = [], diagnostics: Diagnostic[] = [], findings: Finding[] = [];
  let closure: ClosedCapacityScope | undefined, failure: string | undefined;
  const started = performance.now();
  try {
    closure = closedCapacityScope(program, (steps = 1, values = 0) => {
      if (metrics.steps + steps > limits.maxSteps || metrics.abstractValues + values > limits.maxValues) throw new Error("Closed capacity source closure exhausted its shared allowance");
      metrics.steps += steps; metrics.abstractValues += values;
    });
  } catch (error) { failure = error instanceof Error ? error.message : "Closed source closure is unavailable"; }
  const discoverySteps = metrics.steps;
  work.analysisMs += performance.now() - started;
  for (const entry of program.entries) {
    const scope = { kind: "rule" as const, detectorId: rule.id, entry }, location = program.functions.get(entry)!.declaration.span;
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "exact-observation", diagnosticCodes: [] }; coverage.push(row);
    const issue = (code: string, message: string) => { diagnostics.push({ code, message, location, scope }); row.diagnosticCodes.push(code); };
    if (program.symbols.get(entry)?.kind === "constructor" || closure && !closure.entries.has(entry)) {
      row.status = "not-applicable"; row.evidence = "structural-absence"; continue;
    }
    if (failure) { issue("closed-capacity-closure-unavailable", failure); continue; }
    const remainingSteps = limits.maxSteps - discoverySteps, remainingValues = limits.maxValues - metrics.abstractValues;
    if (remainingSteps <= 0 || remainingValues <= 0) { issue("closed-capacity-observation-budget", "Closed capacity observation exhausted its shared allowance"); continue; }
    const analyzed = performance.now();
    const facts = new Dataflow(program, remainingSteps, limits.maxPaths, remainingValues, "instructions", true, true, "equivalent-states", false, false, "all", false, true, false, false).analyzeConfiguredCapacityEntry(entry);
    facts.closedCapacity = { writers: closure!.writers };
    work.analysisMs += performance.now() - analyzed;
    const detected = performance.now(); findings.push(...rule.run(facts)); work.detectorMs += performance.now() - detected;
    for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
    for (const diagnostic of facts.diagnostics) { diagnostics.push({ ...diagnostic, scope }); row.diagnosticCodes.push(diagnostic.code); }
    if (!row.diagnosticCodes.length && facts.completedEntries.includes(entry)) row.status = "complete";
    else if (!row.diagnosticCodes.length) issue("closed-capacity-observation-incomplete", "Constructor-to-entry observation did not complete");
  }
  return { findings, diagnostics, coverage, work };
}
