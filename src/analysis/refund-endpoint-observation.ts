import { reserveRefundEndpointFinding } from "../detectors/refund-endpoint.js";
import { performance } from "node:perf_hooks";
import type { Program } from "../semantic/index.js";
import { discoverRefundEndpoints, REFUND_ENDPOINT_RULE } from "../semantic/refund-endpoint.js";
import { certifyRefundEndpoint, type RefundEndpointCertificate } from "../dataflow/refund-endpoint.js";
import type { AnalysisFacts } from "../dataflow/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { RuleCoverage, RuleObservationWork } from "./rule-observations.js";
export function observeRefundEndpoints(program: Program, rule: Detector, options: { maxSteps?: number; maxPaths?: number; maxValues?: number }) {
  const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
  const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
    statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
  const work: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 };
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [];
  metrics.abstractValues += 3 + program.entries.length * 8;
  for (const entry of program.entries) {
    const started = performance.now(); let steps = 0;
    const row: RuleCoverage = { root: program.root, entry, detectorId: REFUND_ENDPOINT_RULE, status: "incomplete", evidence: "unavailable", diagnosticCodes: [] };
    coverage.push(row);
    const charge = (amount = 1, values = 0) => {
      steps += amount; metrics.steps += amount; metrics.abstractValues += values;
      if (steps > limits.maxSteps || metrics.abstractValues > limits.maxValues) throw new Error("Refund local certificate shared allowance exhausted");
    };
    try {
      charge(); const candidates = discoverRefundEndpoints(program, entry, charge);
      if (!candidates.length) { row.status = "not-applicable"; row.evidence = "structural-absence"; continue; }
      if (program.compilerVersion !== "0.34.0" || ![2, 3].includes(program.zkirVersion)) throw new Error("Refund source certificate requires compiler 0.34.0/ZKIR2 or ZKIR3");
      if (candidates.length > limits.maxPaths) throw new Error("Refund local candidate allowance exhausted");
      const certificates: RefundEndpointCertificate[] = [], seen = new Set<number>();
      for (const candidate of candidates) {
        charge(1, 2); const certificate = certifyRefundEndpoint(program, candidate, charge);
        if (certificate && !seen.has(candidate.send.start)) {
          reserveRefundEndpointFinding(program, certificate, charge);
          certificates.push(certificate); seen.add(candidate.send.start);
        }
      }
      charge(1, 20); const facts: AnalysisFacts = { program, refundEndpointEvidence: { version: 1, program, compilerVersion: program.compilerVersion, zkirVersion: program.zkirVersion, certificates }, pathSemantics: "equivalent-states", paths: [],
        diagnostics: [], failedAssertions: [], assertionReaches: [], metrics, completedEntries: [] };
      const detectorStarted = performance.now(); findings.push(...rule.run(facts)); work.detectorMs += performance.now() - detectorStarted;
      row.status = "complete"; row.evidence = "source-local-formula";
    } catch (error) {
      const code = "refund-endpoint-source-unavailable"; row.diagnosticCodes.push(code);
      if (diagnostics.length < 16) diagnostics.push({ code, message: error instanceof Error ? error.message : String(error),
        location: program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: rule.id, entry } });
    } finally { work.analysisMs += performance.now() - started; }
  }
  work.analysisMs -= work.detectorMs; return { findings, diagnostics, coverage, work };
}
