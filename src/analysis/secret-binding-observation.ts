import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { SECRET_BINDING_RULE, secretBindingScope } from "../semantic/secret-binding.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Entry-local execution meters and cumulative values survive preparation,
 * capture and the subsequent cross-entry comparison. No retry is available. */
export function observeSecretBindings(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  if (!program.entries.length) return { findings, diagnostics, coverage, work };
  metrics.abstractValues += 32 + program.entries.length * 20;
  const combined: AnalysisFacts = { program, paths: [], completedEntries: [], diagnostics: [], failedAssertions: [], assertionReaches: [],
    predicateScope: "all", pathSemantics: "equivalent-states", digestEvidence: true, metrics,
    secretBindingEvidence: { ...limits, entrySteps: new Map() } };
  for (const entry of program.entries) {
    const started = performance.now(), scope = { kind: "rule" as const, detectorId: SECRET_BINDING_RULE, entry };
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let preparation = 0;
    const charge = (steps: number, values: number) => {
      preparation += steps; metrics.steps += steps; metrics.abstractValues += values;
      if (preparation > limits.maxSteps || metrics.abstractValues > limits.maxValues) throw new Error("Secret binding preparation exhausted its shared allowance");
      return true;
    };
    try {
      charge(1, 0);
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Secret binding requires completed baseline semantics");
      if (!secretBindingScope(program, entry, charge)) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      charge(2, 4);
      const flow = new Dataflow(program, limits.maxSteps - preparation, limits.maxPaths, limits.maxValues - metrics.abstractValues,
        execution.engine ?? "instructions", execution.cached ?? true, execution.cached ?? true,
        "equivalent-states", false, false, "all", false, true, false, false, false, false, true);
      const facts = flow.analyzeSecretBindingEntry(entry);
      for (const key in metrics) metrics[key as keyof typeof metrics] += facts.metrics[key as keyof typeof metrics];
      const spent = facts.secretBindingEvidence?.entrySteps.get(entry);
      if (spent === undefined) throw new Error("Selected secret binding entry meter is unavailable");
      combined.secretBindingEvidence!.entrySteps.set(entry, preparation + spent);
      for (const issue of facts.diagnostics) { diagnostics.push({ ...issue, scope }); row.diagnosticCodes.push(issue.code); }
      if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) {
        if (!facts.diagnostics.length) throw new Error("Secret binding histories did not complete");
        continue;
      }
      charge(0, facts.paths.length + 1);
      combined.paths.push(...facts.paths); combined.completedEntries.push(entry);
      row.status = "complete"; row.evidence = "exact-observation";
    } catch (error) {
      const code = /allowance/.test(String(error)) ? "secret-binding-preparation-budget" : "secret-binding-evidence";
      diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
        location: program.functions.get(entry)!.declaration.span, scope }); row.diagnosticCodes.push(code);
    } finally { work.analysisMs += performance.now() - started; }
  }
  const matching = performance.now();
  if (!diagnostics.length && combined.completedEntries.length) findings.push(...rule.run(combined));
  work.detectorMs = performance.now() - matching;
  diagnostics.push(...combined.diagnostics);
  // Incomplete sibling evidence can affect every compared writer, so the pass
  // never turns a partial source inventory into completed quiet coverage.
  if (diagnostics.length) for (const row of coverage) if (row.status !== "not-applicable") {
    row.status = "incomplete"; row.evidence = "unavailable";
    row.diagnosticCodes = [...new Set([...row.diagnosticCodes, ...diagnostics.map(issue => issue.code)])];
  }
  return { findings, diagnostics, coverage, work };
}
