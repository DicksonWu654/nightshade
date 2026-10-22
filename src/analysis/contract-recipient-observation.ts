import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { contractRecipientScope, contractRecipientType } from "../semantic/contract-recipient.js";
import { contractRecipientReviewPass } from "../detectors/contract-recipient.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** An ordinary pass plus each top-level native tag specialization share the
 * original entry-local work/path and pass-wide retained-value allowances. */
export function observeContractRecipient(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  for (const entry of program.entries) {
    const started = performance.now(), scope = { kind: "rule" as const, detectorId: rule.id, entry };
    const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    let entryWork = 0, entryPaths = 0;
    const charge = (work = 1, values = 0) => {
      entryWork += work; metrics.steps += work; metrics.abstractValues += values;
      if (entryWork >= limits.maxSteps || metrics.abstractValues >= limits.maxValues) throw new Error("Recipient preparation exhausted its shared allowance");
      return true;
    };
    try {
      charge();
      if (baselineCompleted && !baselineCompleted.has(entry)) throw new Error("Recipient review requires completed baseline semantics");
      if (!contractRecipientScope(program, entry, charge)) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      if (program.compilerVersion !== "0.34.0" || program.zkirVersion !== 2)
        throw new Error("Recipient auto-receive review requires Compact 0.34.0/ZKIR2");
      charge(0, 2); const pending: (string | undefined)[] = [undefined];
      for (const parameter of program.functions.get(entry)!.declaration.parameters) {
        charge(); if (contractRecipientType(program, parameter.type)) { charge(0, 1); pending.push(parameter.symbol); }
      }
      charge(0, 3); const admitted = new Map<string, Finding>(), deferred = new Set<string>(), completed = new Set<string>();
      for (const parameter of pending) {
        charge(1, 1);
        if (entryPaths >= limits.maxPaths) throw new Error("Recipient passes exhausted their shared entry path allowance");
        const facts = new Dataflow(program, limits.maxSteps - entryWork, limits.maxPaths - entryPaths, limits.maxValues - metrics.abstractValues)
          .analyzeContractRecipientEntry(entry, parameter);
        const detectorStarted = performance.now();
        let result: ReturnType<typeof contractRecipientReviewPass> | undefined;
        try {
          if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) result = contractRecipientReviewPass(facts, true);
        } finally {
          measured.detectorMs += performance.now() - detectorStarted;
          entryWork += facts.metrics.steps;
          entryPaths += facts.paths.length;
          for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
        }
        diagnostics.push(...facts.diagnostics.map(issue => ({ ...issue, scope })));
        row.diagnosticCodes.push(...facts.diagnostics.map(issue => issue.code));
        if (!facts.completedEntries.includes(entry) || facts.diagnostics.length) throw new Error("A required exact recipient pass is incomplete");
        if (entryWork > limits.maxSteps || metrics.abstractValues > limits.maxValues || entryPaths > limits.maxPaths)
          throw new Error("Recipient passes exhausted their original shared allowance");
        for (const item of result!.pendingParameters) {
          charge(pending.length);
          if (!pending.includes(item)) throw new Error("A deferred native tag has no admitted specialization");
          if (!deferred.has(item)) { charge(0, 1); deferred.add(item); }
        }
        for (const finding of result!.findings) {
          if (!admitted.has(finding.fingerprint)) charge(0, 1);
          admitted.set(finding.fingerprint, finding);
        }
        if (parameter) { charge(0, 1); completed.add(parameter); }
      }
      for (const parameter of deferred) { charge(); if (!completed.has(parameter)) throw new Error("Deferred recipient tag coverage remains incomplete"); }
      findings.push(...admitted.values());
      row.status = "complete"; row.evidence = "exact-observation";
    } catch (error) {
      const code = "contract-recipient-preparation-unavailable";
      diagnostics.push({ code, message: error instanceof Error ? error.message : String(error), location: program.functions.get(entry)!.declaration.span, scope });
      row.diagnosticCodes.push(code);
    } finally { measured.analysisMs += performance.now() - started; }
  }
  measured.analysisMs -= measured.detectorMs;
  return { findings, diagnostics, coverage, work: measured };
}
