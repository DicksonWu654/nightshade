import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { operationIntentClosure, type ResolvedOperationIntentPolicy } from "../semantic/operation-intent.js";
import type { Program } from "../semantic/index.js";
import type { ResolvedPolicies } from "../policies.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** Complete selected entries and all potential state writers share the original pass value allowance. */
export function observeOperationIntent(program: Program, rule: Detector, policies: ResolvedPolicies,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  const selected = policies.operationIntent ?? [];
  for (const entry of program.entries) {
    const started = performance.now(), scope = { kind: "rule" as const, detectorId: rule.id, entry };
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let preparation = 0;
    let retainedFacts: AnalysisFacts | undefined;
    const charge = (work: number, values: number) => {
      preparation += work; metrics.steps += work; metrics.abstractValues += values;
      if (preparation >= limits.maxSteps || metrics.abstractValues >= limits.maxValues)
        throw new Error("Operation-intent source preparation exhausted its shared allowance");
    };
    const protectedRoot = (root: string, debit = charge): boolean => {
      for (const candidate of selected) {
        debit(1, 0);
        if (candidate.nonce === root || candidate.controllerCommitment === root) return true;
        for (const ledger of candidate.ledgers) { debit(1, 0); if (ledger === root) return true; }
      }
      return false;
    };
    try {
      charge(1, 0);
      if (!selected.length) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      operationIntentClosure(program, entry, charge);
      let policy: ResolvedOperationIntentPolicy | undefined;
      for (const candidate of selected) { charge(1, 0); if (candidate.circuit === entry) { policy = candidate; break; } }
      const fn = program.functions.get(entry)!;
      // Function write sets include transitive callees; constructors are the explicit initialization boundary.
      let bypass = false;
      if (!policy && fn.symbol.kind !== "constructor") for (const root of fn.writesState) {
        charge(1, 0); if (protectedRoot(root)) { bypass = true; break; }
      }
      if (!policy && !bypass) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Operation-intent requires completed baseline semantics");
      charge(1, 2);
      const facts = retainedFacts = new Dataflow(program, limits.maxSteps - preparation, limits.maxPaths, limits.maxValues - metrics.abstractValues)
        .analyzeOperationIntentEntry(entry);
      if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) {
        const detectorStarted = performance.now();
        try {
          if (policy) findings.push(...rule.run(facts, policies));
          else {
            const proofCharge = (work: number, values: number) => {
              facts.metrics.steps += work; facts.metrics.abstractValues += values;
              if (facts.metrics.steps > limits.maxSteps - preparation || facts.metrics.abstractValues > limits.maxValues - metrics.abstractValues)
                throw new Error("Operation-intent bypass proof allowance exhausted");
            };
            for (const path of facts.paths) for (const write of path.writes) {
              proofCharge(1, 0);
              if (!protectedRoot(write.ledger, proofCharge)) continue;
              proofCharge(0, 1);
              facts.diagnostics.push({ code: "operation-intent-undeclared-writer",
                message: "Successful protected state, controller or nonce writer is outside the declared operation-intent entries; policy results are incomplete",
                location: write.location });
            }
          }
        } finally { measured.detectorMs += performance.now() - detectorStarted; }
      }
      diagnostics.push(...facts.diagnostics.map(issue => ({ ...issue, scope })));
      row.diagnosticCodes.push(...facts.diagnostics.map(issue => issue.code));
      if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) { row.status = "complete"; row.evidence = "exact-observation"; }
      else if (!facts.diagnostics.length) throw new Error("Operation-intent exact histories did not complete");
    } catch (error) {
      const code = "operation-intent-preparation-unavailable";
      diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
        location: program.functions.get(entry)!.declaration.span, scope });
      row.diagnosticCodes.push(code);
    } finally {
      if (retainedFacts) for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += retainedFacts.metrics[key];
      measured.analysisMs += performance.now() - started;
    }
  }
  measured.analysisMs -= measured.detectorMs;
  return { findings, diagnostics, coverage, work: measured };
}
