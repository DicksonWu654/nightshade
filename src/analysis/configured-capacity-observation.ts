import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { CONFIGURED_CAPACITY_RULE } from "../dataflow/configured-capacity.js";
import { configuredCapacityTargets } from "../semantic/configured-capacity-targets.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

export function observeConfiguredCapacity(program: Program, rule: Detector, options: { maxSteps?: number; maxPaths?: number; maxValues?: number }) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0, statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: CONFIGURED_CAPACITY_RULE, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const coverage: RuleCoverage[] = [], diagnostics: Diagnostic[] = [], findings: Finding[] = [];
  for (const entry of program.entries) {
    const scope = { kind: "rule" as const, detectorId: rule.id, entry }, location = program.functions.get(entry)!.declaration.span;
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "exact-observation", diagnosticCodes: [] }; coverage.push(row);
    const started = performance.now();
    const target = configuredCapacityTargets(program, entry, Math.min(20000, limits.maxSteps));
    metrics.steps += target.work; metrics.abstractValues += target.work;
    if (target.complete && !target.applicable) { row.status = "not-applicable"; row.evidence = "structural-absence"; work.analysisMs += performance.now() - started; continue; }
    const issue = (code: string, message: string) => { diagnostics.push({ code, message, location, scope }); row.diagnosticCodes.push(code); };
    const remaining = limits.maxValues - metrics.abstractValues;
    if (!target.complete || remaining <= 0 || target.work >= limits.maxSteps) { issue("capacity-applicability-budget", "Resolved configured-capacity applicability exhausted its allowance"); work.analysisMs += performance.now() - started; continue; }
    const facts = new Dataflow(program, limits.maxSteps - target.work, limits.maxPaths, remaining, "instructions", true, true, "equivalent-states", false, false, "all", false, true, false, false).analyzeConfiguredCapacityEntry(entry);
    work.analysisMs += performance.now() - started;
    const detected = performance.now(); findings.push(...rule.run(facts)); work.detectorMs += performance.now() - detected;
    for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
    for (const diagnostic of facts.diagnostics) { diagnostics.push({ ...diagnostic, scope }); row.diagnosticCodes.push(diagnostic.code); }
    if (!row.diagnosticCodes.length && facts.completedEntries.includes(entry)) row.status = "complete";
    else if (!row.diagnosticCodes.length) issue("capacity-observation-incomplete", "Constructor-to-entry observation did not complete");
  }
  return { findings, diagnostics, coverage, work };
}
