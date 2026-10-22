import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { signatureIdentityScope } from "../semantic/signature-targets.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Preparation, exact observation and proof share the unchanged entry-local
 * steps/paths and rule-wide cumulative value allowance. There is no retry. */
export function observeSignatureIdentity(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  // Reserve reporting containers and all row/failure slots before inventory.
  metrics.abstractValues += 3 + program.entries.length * 8;
  if (metrics.abstractValues > limits.maxValues) {
    const code = "signature-identity-coverage-budget", entry = program.entries[0];
    diagnostics.push({ code, message: "Signature review coverage inventory exhausted the cumulative allowance; all entries remain unobserved",
      location: program.rootSource.ast.span, ...(entry ? { scope: { kind: "rule" as const, detectorId: rule.id, entry } } : {}) });
    if (entry) coverage.push({ root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [code] });
    return { findings, diagnostics, coverage, work };
  }
  for (const entry of program.entries) {
    const started = performance.now(), scope = { kind: "rule" as const, detectorId: rule.id, entry };
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let entryWork = 0;
    const charge = (amount = 1, values = 0) => {
      entryWork += amount; metrics.steps += amount; metrics.abstractValues += values;
      if (entryWork >= limits.maxSteps || metrics.abstractValues >= limits.maxValues)
        throw new Error("Signature review preparation exhausted the shared allowance");
      return true;
    };
    try {
      charge(2);
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Signature review requires completed baseline semantics");
      if (!signatureIdentityScope(program, entry, charge)) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      if (!(program.compilerVersion === "0.34.0" || program.zkirVersion === 2 && ["0.35.0", "0.35.0-rc.1"].includes(program.compilerVersion)))
        throw new Error("Signature review requires exact supported 0.34.0/ZKIR2 or ZKIR3, or 0.35.0/RC1 ZKIR2 profiles");
      const facts = new Dataflow(program, limits.maxSteps - entryWork, limits.maxPaths, limits.maxValues - metrics.abstractValues,
        execution.engine ?? "instructions", execution.cached ?? true, execution.cached ?? true).analyzeSignatureIdentityEntry(entry);
      const detectorStarted = performance.now();
      let result: Finding[] = [];
      try { if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) result = rule.run(facts); }
      finally {
        work.detectorMs += performance.now() - detectorStarted;
        for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
      }
      for (const issue of facts.diagnostics) {
        if (diagnostics.length < 15) diagnostics.push({ ...issue, scope });
        if (!row.diagnosticCodes.includes(issue.code)) row.diagnosticCodes.push(issue.code);
      }
      if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) throw new Error("Required original signature histories or exact key proof are incomplete");
      findings.push(...result); row.status = "complete"; row.evidence = "exact-observation";
    } catch (error) {
      const code = "signature-identity-preparation-unavailable";
      if (diagnostics.length < 16) diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
        location: program.functions.get(entry)!.declaration.span, scope });
      row.diagnosticCodes.push(code);
    } finally { work.analysisMs += performance.now() - started; }
  }
  work.analysisMs -= work.detectorMs;
  return { findings, diagnostics, coverage, work };
}
