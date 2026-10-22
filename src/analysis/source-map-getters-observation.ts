import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { prepareSourceMapGetters, mapGetterClosure } from "../semantic/source-map-getters.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import { AnalysisError, type Diagnostic } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

export function observeSourceMapGetters(program: Program, rule: Detector, policies: ResolvedPolicies,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0, statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  if (!policies.sourceMapGetters?.length) {
    for (const entry of program.entries) coverage.push({ root: program.root, detectorId: rule.id, entry, status: "not-applicable", evidence: "structural-absence", diagnosticCodes: [] });
    return { findings, diagnostics, coverage, work };
  }
  const started = performance.now(); let preparation = 0;
  const prepareCharge = (steps = 1, values = 0) => {
    if (preparation + steps > limits.maxSteps || metrics.abstractValues + values > limits.maxValues) throw new Error("Source Map getter preparation exhausted its shared allowance");
    preparation += steps; metrics.steps += steps; metrics.abstractValues += values; return true;
  };
  const issue = (entry: string, error: unknown) => {
    const code = error instanceof AnalysisError ? error.diagnostic.code : "source-map-getter-evidence-unavailable";
    diagnostics.push({ code, message: error instanceof Error ? error.message : String(error), location: program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId: rule.id, entry } }); return code;
  };
  let claims: ReturnType<typeof prepareSourceMapGetters> = [], failure: unknown;
  try { claims = prepareSourceMapGetters(program, policies.sourceMapGetters ?? [], prepareCharge); }
  catch (error) { failure = error; }
  if (failure && !program.entries.length) {
    const code = failure instanceof AnalysisError ? failure.diagnostic.code : "source-map-getter-evidence-unavailable";
    diagnostics.push({ code, message: failure instanceof Error ? failure.message : String(failure), location: program.rootSource.ast.span,
      scope: { kind: "rule", detectorId: rule.id, entry: "" } });
  }
  for (const entry of program.entries) {
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "not-applicable", evidence: "structural-absence", diagnosticCodes: [] }; coverage.push(row);
    if (failure) { row.status = "incomplete"; row.evidence = "unavailable"; row.diagnosticCodes.push(issue(entry, failure)); continue; }
    const selected = claims.filter(claim => claim.getter === entry); if (!selected.length) continue;
    let entryWork = preparation; const local: Finding[] = [];
    const charge = (steps = 1, values = 0) => {
      if (entryWork + steps > limits.maxSteps || metrics.abstractValues + values > limits.maxValues) throw new Error("Source Map getter entry preparation exhausted its shared allowance");
      entryWork += steps; metrics.steps += steps; metrics.abstractValues += values; return true;
    };
    const retainMetrics = (facts: AnalysisFacts) => {
      entryWork += facts.metrics.steps;
      for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
    };
    const analyze = (target: string) => {
      if (limits.maxSteps - entryWork <= 0 || limits.maxValues - metrics.abstractValues <= 0) throw new Error("Source Map getter execution allowance exhausted");
      return new Dataflow(program, limits.maxSteps - entryWork, limits.maxPaths, limits.maxValues - metrics.abstractValues,
        execution.engine ?? "instructions", execution.cached ?? true, execution.cached ?? true).analyzeMapGetterEntry(target);
    };
    try {
      row.status = "incomplete"; row.evidence = "unavailable";
      for (const claim of selected) {
        charge(); if (baselineCompleted && (!baselineCompleted.has(entry) || !baselineCompleted.has(claim.setter))) throw new Error("Source Map getter requires completed setter/getter baseline semantics");
        // Both source closures must be complete, even if the getter reads the Map.
        const reads = mapGetterClosure(program, entry, claim.map, charge);
        mapGetterClosure(program, claim.setter, claim.map, charge);
        if (reads) continue;
        const setter = analyze(claim.setter); retainMetrics(setter);
        if (!setter.completedEntries.includes(claim.setter) || setter.diagnostics.length) {
          for (const diagnostic of setter.diagnostics) { diagnostics.push({ ...diagnostic, scope: { kind: "rule", detectorId: rule.id, entry } }); row.diagnosticCodes.push(diagnostic.code); }
          throw new Error("Original successful setter histories are incomplete");
        }
        const facts = analyze(entry);
        // Matching sees both captures' spent work; the getter's original budget
        // remains the matching allowance, without resetting an observer budget.
        const maxSteps = limits.maxSteps - entryWork, maxValues = limits.maxValues - metrics.abstractValues;
        facts.sourceMapGetterEvidence = { claim, setterPaths: setter.paths, setterHistories: setter.sourceClaimEvidence?.histories ?? -1, getterClosure: "complete-without-selected-root-read", maxSteps, maxValues };
        const detected = performance.now(); const found = rule.run(facts, policies); work.detectorMs += performance.now() - detected;
        retainMetrics(facts);
        if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) {
          for (const diagnostic of facts.diagnostics) { diagnostics.push({ ...diagnostic, scope: { kind: "rule", detectorId: rule.id, entry } }); row.diagnosticCodes.push(diagnostic.code); }
          throw new Error("Original successful getter histories or selected contract evidence are incomplete");
        }
        local.push(...found);
      }
      findings.push(...local); row.status = "complete"; row.evidence = "exact-observation";
    } catch (error) { row.diagnosticCodes.push(issue(entry, error)); }
  }
  work.analysisMs = performance.now() - started - work.detectorMs;
  return { findings, diagnostics, coverage, work };
}
