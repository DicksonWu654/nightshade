import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import { mapDebitAmountCandidates } from "../dataflow/map-debit.js";
import { zeroDefaultGetterCertificate, type ZeroDefaultGetter } from "../dataflow/zero-default.js";
import { ZERO_DEFAULT_RULE, zeroDefaultScope } from "../semantic/zero-default-targets.js";
import type { Program } from "../semantic/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** One bounded cross-entry certificate. Any unavailable relevant entry withholds
 * the whole relation; unrelated entries keep their independent absence rows. */
export function observeZeroDefault(program: Program, rule: Detector,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const started = performance.now();
  const plan = zeroDefaultScope(program, Math.min(20000, limits.maxSteps), limits.maxValues);
  metrics.steps = plan.work;
  metrics.abstractValues = plan.values;
  // Rule reporting rows/diagnostics are bounded by the entry cap and remain
  // available on exhaustion. Admission/proof structures use this shared meter.
  const charge = (units = 1, retained = 0) => {
    metrics.steps += units; metrics.abstractValues += retained;
    if (metrics.steps > limits.maxSteps || metrics.abstractValues > limits.maxValues)
      throw new Error("Cross-entry getter/membership observations exhausted the shared work/value allowance");
  };
  let prepared = plan.complete;
  metrics.abstractValues++;
  if (metrics.abstractValues > limits.maxValues) prepared = false;
  const entries = new Set<string>();
  if (prepared && plan.getters.length && plan.spenders.length) {
    metrics.abstractValues += 3;
    if (metrics.abstractValues > limits.maxValues) prepared = false;
    const groups = prepared ? [plan.getters, plan.spenders] : [];
    for (const group of groups) {
      if (!prepared) break;
      for (const entry of group) {
        metrics.steps++;
        if (!entries.has(entry)) {
          metrics.abstractValues++;
          if (metrics.steps > limits.maxSteps || metrics.abstractValues > limits.maxValues) { prepared = false; break; }
          entries.add(entry);
        }
      }
    }
  }
  const coverage: RuleCoverage[] = program.entries.map(entry => ({ root: program.root, detectorId: ZERO_DEFAULT_RULE, entry,
    status: prepared && !entries.has(entry) ? "not-applicable" : "incomplete",
    evidence: prepared && !entries.has(entry) ? "structural-absence" : "exact-observation", diagnosticCodes: [] }));
  const diagnostics: Diagnostic[] = [], findings: Finding[] = [];
  const issue = (code: string, message: string, entry: string) => diagnostics.push({ code, message,
    location: program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: rule.id, entry } });
  const merge = (facts: AnalysisFacts, entry: string) => {
    for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
    diagnostics.push(...facts.diagnostics.map(diagnostic => ({ ...diagnostic, scope: { kind: "rule" as const, detectorId: rule.id, entry } })));
    if (!facts.completedEntries.includes(entry) && !facts.diagnostics.length) issue("zero-default-entry-incomplete", "Exact entry observation did not complete", entry);
    if (metrics.steps > limits.maxSteps || metrics.abstractValues > limits.maxValues)
      issue("zero-default-evidence-unavailable", "Cross-entry orchestration and observed facts exhausted the shared work/value allowance", entry);
  };
  const observer = () => {
    if (metrics.steps >= limits.maxSteps || metrics.abstractValues >= limits.maxValues) throw new Error("Cross-entry getter/membership observations exhausted the shared work/value allowance");
    return new Dataflow(program, limits.maxSteps - metrics.steps, limits.maxPaths, limits.maxValues - metrics.abstractValues);
  };
  let baselineReady = true;
  if (prepared && baselineCompleted) for (const entry of entries) {
    try { charge(); } catch { prepared = false; break; }
    if (!baselineCompleted.has(entry)) baselineReady = false;
  }
  if (!prepared) {
    const values = metrics.abstractValues > limits.maxValues || "reason" in plan && plan.reason === "values";
    const unresolved = "reason" in plan && plan.reason === "unresolved";
    for (const row of coverage) {
      row.status = "incomplete";
      issue(unresolved ? "zero-default-target-unavailable" : values ? "zero-default-preparation-values" : "zero-default-target-budget",
        unresolved ? "Resolved callable/source closure is unavailable; no admission absence certificate is available"
          : values ? "Cross-entry source preparation exhausted the shared value allowance"
            : "Cross-entry source admission exceeds its 64-entry or bounded source-work allowance", row.entry);
    }
  } else if (!baselineReady) {
    for (const entry of entries) issue("zero-default-baseline-incomplete", "All relevant getter/spender entries need completed baseline semantics before this cross-entry review", entry);
  } else if (entries.size) {
    let current = entries.values().next().value!;
    try {
      charge(0, 1);
      const getters: ZeroDefaultGetter[] = [];
      for (const entry of plan.getters) {
        charge();
        current = entry;
        const facts = observer().analyzeMapDebitCandidates(entry);
        let certificate: ZeroDefaultGetter | undefined;
        try { if (!facts.diagnostics.length && facts.completedEntries.includes(entry)) certificate = zeroDefaultGetterCertificate(facts, entry); }
        finally { merge(facts, entry); }
        if (certificate) { charge(0, 1); getters.push(certificate); }
        if (diagnostics.length) break;
      }
      if (!diagnostics.length && getters.length) for (const entry of plan.spenders) {
        charge();
        current = entry;
        const ordinary = observer().analyzeMapDebitCandidates(entry);
        let amounts: string[] = [];
        try { if (!ordinary.diagnostics.length && ordinary.completedEntries.includes(entry))
          amounts = mapDebitAmountCandidates(ordinary, entry, Math.max(0, ordinary.mapDebitEvidence!.maxSteps - ordinary.metrics.steps)); }
        finally { merge(ordinary, entry); }
        if (diagnostics.length) break;
        for (const amount of amounts) {
          charge();
          const facts = observer().analyzeZeroMapDebitEntry(entry, amount);
          facts.metrics.abstractValues += 2;
          if (facts.metrics.abstractValues > facts.zeroEntry!.maxValues) {
            merge(facts, entry); throw new Error("Cross-entry getter evidence carrier exhausted the shared value allowance");
          }
          facts.zeroDefaultEvidence = { getters };
          const detectorStarted = performance.now();
          try { if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) findings.push(...rule.run(facts)); }
          finally { measured.detectorMs += performance.now() - detectorStarted; merge(facts, entry); }
          if (diagnostics.length) break;
        }
        if (diagnostics.length) break;
      }
    } catch (error) {
      issue("zero-default-evidence-unavailable", error instanceof Error ? error.message : String(error), current);
    }
  }
  // Every relation depends on the entire relevant set. No partial certificate
  // becomes a clean result when another entry exhausts or loses evidence.
  if (diagnostics.length) {
    findings.length = 0;
    const codes = [...new Set(diagnostics.map(diagnostic => diagnostic.code))];
    for (const row of coverage) if (row.status !== "not-applicable") { row.diagnosticCodes = codes; row.evidence = "unavailable"; }
  } else for (const row of coverage) if (row.status !== "not-applicable") row.status = "complete";
  measured.analysisMs = performance.now() - started - measured.detectorMs;
  return { findings, diagnostics, coverage, work: measured };
}
