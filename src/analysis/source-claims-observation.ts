import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { prepareSourceClaims, sourceClaimScope } from "../semantic/source-claims.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import { AnalysisError, type Diagnostic } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Quote preparation, closure admission, capture and matching share the original
 * rule allowance. No fallback or independent proof budget is available. */
export function observeSourceClaims(program: Program, rule: Detector, policies: ResolvedPolicies,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>,
  execution: { engine?: "instructions" | "expressions"; cached?: boolean } = {}) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  const started = performance.now();
  let preparation = 0;
  const prepareCharge = (amount = 1, values = 0) => {
    preparation += amount; metrics.steps += amount; metrics.abstractValues += values;
    if (preparation > limits.maxSteps || metrics.abstractValues > limits.maxValues) throw new Error("Source claim preparation exhausted its shared allowance");
    return true;
  };
  const unavailable = (entry: string | undefined, error: unknown) => {
    const code = error instanceof AnalysisError ? error.diagnostic.code : "source-claim-evidence-unavailable";
    const scope = entry ? { kind: "rule" as const, detectorId: rule.id, entry } : undefined;
    if (diagnostics.length < 16) diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
      location: entry ? program.functions.get(entry)!.declaration.span : program.rootSource.ast.span, ...(scope ? { scope } : {}) });
    return code;
  };
  try {
    prepareCharge(0, 3 + program.entries.length * 8);
    const claims = prepareSourceClaims(program, policies.sourceClaims ?? [], prepareCharge);
    for (const entry of program.entries) {
      const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "not-applicable", evidence: "structural-absence", diagnosticCodes: [] };
      coverage.push(row);
      const selected = claims.get(entry); if (!selected) continue;
      row.status = "incomplete"; row.evidence = "unavailable";
      let entryWork = preparation;
      const charge = (amount = 1, values = 0) => {
        entryWork += amount; metrics.steps += amount; metrics.abstractValues += values;
        if (entryWork > limits.maxSteps || metrics.abstractValues > limits.maxValues) throw new Error("Source claim entry preparation exhausted its shared allowance");
        return true;
      };
      try {
        charge();
        if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Source claim observation requires completed baseline semantics");
        if (program.compilerVersion !== "0.34.0" || ![2, 3].includes(program.zkirVersion)) throw new Error("Source claim review requires Compact 0.34.0/ZKIR2 or ZKIR3");
        if (!sourceClaimScope(program, entry, charge)) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
        const facts = new Dataflow(program, limits.maxSteps - entryWork, limits.maxPaths, limits.maxValues - metrics.abstractValues,
          execution.engine ?? "instructions", execution.cached ?? true, execution.cached ?? true).analyzeSourceClaimEntry(entry);
        if (facts.sourceClaimEvidence) facts.sourceClaimEvidence.claims = selected;
        const detectorStarted = performance.now(); let result: Finding[] = [];
        try { if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) result = rule.run(facts, policies); }
        finally {
          work.detectorMs += performance.now() - detectorStarted;
          for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
        }
        for (const issue of facts.diagnostics) {
          if (diagnostics.length < 15) diagnostics.push({ ...issue, scope: { kind: "rule", detectorId: rule.id, entry } });
          if (!row.diagnosticCodes.includes(issue.code)) row.diagnosticCodes.push(issue.code);
        }
        if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) throw new Error("Required source claim history or tag evidence is incomplete");
        findings.push(...result); row.status = "complete"; row.evidence = "exact-observation";
      } catch (error) { row.diagnosticCodes.push(unavailable(entry, error)); }
    }
  } catch (error) {
    const entry = program.entries[0], code = unavailable(entry, error);
    if (entry) coverage.push({ root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [code] });
  }
  work.analysisMs = performance.now() - started - work.detectorMs;
  return { findings, diagnostics, coverage, work };
}
