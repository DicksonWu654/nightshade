import { performance } from "node:perf_hooks";
import { Dataflow } from "../dataflow/index.js";
import { KEYED_STATE_INVARIANT } from "../dataflow/keyed-state-invariant.js";
import { keyedStateComponents } from "../semantic/keyed-state-components.js";
import type { Program } from "../semantic/index.js";
import type { Detector } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";

/** One shared exact pass, with complete may-dependency components reviewed
 * independently. Baseline diagnostics stay independent of this observation. */
export function observeKeyedState(program: Program, rule: Detector, options: { maxSteps?: number; maxPaths?: number; maxValues?: number }) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const coverage: RuleCoverage[] = [], diagnostics: Diagnostic[] = [];
  const entries: string[] = [];
  const started = performance.now();
  const plan = keyedStateComponents(program, Math.max(0, Math.min(20000, limits.maxSteps)));
  const preparation = plan.work;
  const applicable = new Set(plan.components.filter(component => component.applicable).flatMap(component => component.entries));
  for (const entry of program.entries) {
    const row: RuleCoverage = { root: program.root, detectorId: KEYED_STATE_INVARIANT, entry,
      status: plan.complete && !applicable.has(entry) ? "not-applicable" : "incomplete",
      evidence: plan.complete && !applicable.has(entry) ? "structural-absence" : "exact-observation", diagnosticCodes: [] };
    coverage.push(row);
    if (applicable.has(entry)) entries.push(entry);
  }
  const flow = new Dataflow(program, Math.max(1, limits.maxSteps - preparation), limits.maxPaths, Math.max(1, limits.maxValues - preparation),
    "instructions", true, true, "equivalent-states", false, false, "all", false, true, false, false);
  const facts = flow.analyzeSubset(!plan.complete || preparation >= limits.maxSteps || preparation >= limits.maxValues ? [] : entries);
  facts.metrics.steps += preparation; facts.metrics.abstractValues += preparation;
  facts.keyedStateEvidence = { entries, maxSteps: limits.maxSteps, maxValues: limits.maxValues };
  const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics: facts.metrics, analysisMs: performance.now() - started, detectorMs: 0 };
  if (!plan.complete || preparation >= limits.maxSteps || preparation >= limits.maxValues) {
    const code = !plan.complete && !/work allowance/.test(plan.reason ?? "") ? "keyed-state-component-unavailable" : "keyed-state-applicability-budget";
    for (const row of coverage.filter(row => row.status !== "not-applicable")) diagnostics.push({ code,
      message: plan.reason ?? "Resolved keyed-state component dependencies are incomplete; no exact relation result is available",
      location: program.functions.get(row.entry)!.declaration.span, scope: { kind: "rule", detectorId: rule.id, entry: row.entry } });
  }
  const detectorStarted = performance.now();
  const findings = diagnostics.length || !entries.length ? [] : rule.run(facts);
  measured.detectorMs = performance.now() - detectorStarted;
  for (const issue of facts.diagnostics) {
    if (issue.scope) diagnostics.push(issue);
    else for (const component of plan.components.filter(component => component.applicable && component.entries.some(entry => !facts.completedEntries.includes(entry))))
      for (const entry of component.entries) diagnostics.push({ ...issue, scope: { kind: "rule", detectorId: rule.id, entry } });
  }
  for (const row of coverage) {
    if (row.status === "not-applicable") continue;
    row.diagnosticCodes = diagnostics.filter(issue => issue.scope?.entry === row.entry).map(issue => issue.code);
    const component = plan.components.find(component => component.entries.includes(row.entry));
    if (!row.diagnosticCodes.length && component?.entries.every(entry => facts.completedEntries.includes(entry))) row.status = "complete";
  }
  return { findings, diagnostics, coverage, work: measured };
}
