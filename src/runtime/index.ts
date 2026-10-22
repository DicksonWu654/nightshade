import { isNoEntrypointsNotice } from "../model.js";
import { performance } from "node:perf_hooks";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ScanOptions, ScanResult, emptyResult } from "../index.js";
import { semanticProfile, validCompilerVersion, validSemanticProfile } from "../semantic/profile.js";
import { ExecutionLimits, WorkerFailure, runNodeModule } from "./process.js";

export type { ExecutionLimits } from "./process.js";

function validRuleCoverage(result: ScanResult): boolean {
  if (!result || typeof result !== "object") return false;
  const emptyRoots = result.coverage?.noEntrypointRoots;
  if (!Array.isArray(emptyRoots) || emptyRoots.some(root => typeof root !== "string") || new Set(emptyRoots).size !== emptyRoots.length) return false;
  const notices = (result.diagnostics ?? []).filter(issue => isNoEntrypointsNotice(issue, emptyRoots));
  const errors = (result.diagnostics ?? []).filter(issue => !isNoEntrypointsNotice(issue, emptyRoots));
  if (result.status === "complete" && errors.length) return false;
  if (emptyRoots.some(root => notices.filter(issue => issue.location.file === root).length !== 1)) return false;
  if (emptyRoots.length && (result.status !== "complete" || errors.length || result.entrypoints?.length
    || emptyRoots.length !== 1 || result.coverage.resolved?.length !== 1 || emptyRoots[0] !== result.coverage.resolved[0])) return false;
  if (result.status === "complete" && !result.entrypoints?.length && result.coverage?.resolved?.length && !emptyRoots.length) return false;
  const modern = result.coverage?.rules !== undefined || result.coverage?.baselineStatus !== undefined || result.ruleObservationWork !== undefined;
  if (!modern) {
    const scoped = (result.diagnostics ?? []).filter(issue => issue.scope);
    if (!scoped.length) return true;
    // Counter mode uses its existing analysis.coverage rows rather than the
    // default report's coverage.rules. Do not accept scoped legacy reports or
    // certify a Counter obligation covered after its source observation failed.
    if (result.schemaVersion !== "1.7.0" || !("analysis" in result) || result.status !== "incomplete"
      || !Array.isArray(result.analysis?.coverage) || !Array.isArray(result.entrypoints)
      || !Array.isArray(result.coverage?.detectors) || result.coverage.resolved?.length !== 1
      || new Set(result.entrypoints).size !== result.entrypoints.length
      || new Set(result.coverage.detectors).size !== result.coverage.detectors.length) return false;
    const rows = result.analysis.coverage, keys = new Set<string>();
    for (const row of rows) {
      if (row.root !== result.coverage.resolved[0] || !result.entrypoints.includes(row.entry)
        || !result.coverage.detectors.includes(row.detector) || !["covered", "incomplete"].includes(row.status)) return false;
      const key = JSON.stringify([row.entry, row.detector]);
      if (keys.has(key)) return false;
      keys.add(key);
    }
    for (const entry of result.entrypoints) for (const detector of result.coverage.detectors)
      if (!keys.has(JSON.stringify([entry, detector]))) return false;
    return scoped.every(issue => issue.scope!.kind === "rule"
      && rows.some(row => row.entry === issue.scope!.entry && row.detector === issue.scope!.detectorId && row.status === "incomplete"));
  }
  if (!Array.isArray(result.entrypoints) || !Array.isArray(result.coverage?.detectors) || !Array.isArray(result.coverage?.completedEntries)
    || !Array.isArray(result.coverage?.resolved) || !Array.isArray(result.diagnostics)
    || !["complete", "incomplete"].includes(result.coverage.baselineStatus!)) return false;
  const rows = result.coverage.rules;
  if (!Array.isArray(rows)) return false;
  const keys = new Set<string>();
  for (const row of rows) {
    if (!row || typeof row.root !== "string" || !result.coverage.resolved.includes(row.root) || typeof row.entry !== "string" || typeof row.detectorId !== "string"
      || !result.entrypoints.includes(row.entry) || !result.coverage.detectors.includes(row.detectorId)
      || !["complete", "incomplete", "not-applicable"].includes(row.status) || !["source-local-formula", "baseline", "exact-observation", "structural-absence", "conservative-absence", "unavailable"].includes(row.evidence)
      || !Array.isArray(row.diagnosticCodes) || row.diagnosticCodes.some(code => typeof code !== "string")
      || (row.status === "not-applicable") !== (row.evidence === "structural-absence")
      || row.evidence === "unavailable" && row.status !== "incomplete" || row.evidence === "conservative-absence" && (result.schemaVersion !== "1.6.0" || row.status !== "complete" || row.diagnosticCodes.length > 0)
      || row.evidence === "source-local-formula" && (result.schemaVersion !== "1.6.0" || row.detectorId !== "unshielded-refund-endpoint-review" || row.status !== "complete" || row.diagnosticCodes.length > 0)) return false;
    const key = JSON.stringify([row.root, row.entry, row.detectorId]);
    if (keys.has(key)) return false;
    keys.add(key);
  }
  // The worker analyzes one compilation unit. New metadata must enumerate
  // every selected detector/entry obligation exactly once, including absences.
  if (result.entrypoints.length) {
    if (result.coverage.resolved.length !== 1 || new Set(result.entrypoints).size !== result.entrypoints.length || new Set(result.coverage.detectors).size !== result.coverage.detectors.length) return false;
    for (const entry of result.entrypoints) for (const detector of result.coverage.detectors)
      if (!keys.has(JSON.stringify([result.coverage.resolved[0], entry, detector]))) return false;
  }
  if (result.status === "complete" && (result.coverage.baselineStatus === "incomplete" || rows.some(row => row.status === "incomplete") || errors.length)) return false;
  if (result.coverage.baselineStatus === "complete" && (errors.some(issue => !issue.scope) || result.entrypoints.some(entry => !result.coverage.completedEntries.includes(entry)))) return false;
  return !result.diagnostics.some(issue => issue.scope && (issue.scope.kind !== "rule"
    || !(issue.scope.entry === ""
      ? result.entrypoints.length === 0 && result.coverage.resolved.includes(issue.location.file)
        && result.coverage.detectors.includes(issue.scope.detectorId)
      : rows.some(row => row.detectorId === issue.scope!.detectorId && row.entry === issue.scope!.entry && row.status === "incomplete"))));
}

function expectedMode(result: ScanResult, experimental: boolean): boolean {
  if (!experimental) return result?.schemaVersion === "1.6.0" && result.scope === "experimental-subset" && !("analysis" in result);
  if (result?.schemaVersion !== "1.7.0" || result.scope !== "selected-detector-predicates") return false;
  const analysis = result.analysis;
  return analysis?.mode === "experimental-counter-queries" && analysis.scope === "selected-detector-predicates" && analysis.contract === "experimental-counter-scan-1"
    && Array.isArray(analysis.coverage) && analysis.coverage.every(row => row && typeof row.root === "string" && typeof row.entry === "string" && typeof row.detector === "string"
      && ["covered", "incomplete"].includes(row.status) && ["exact", "counter-query", "structural-absence", "source-work", "unavailable"].includes(row.method)
      && (row.contract === undefined || typeof row.contract === "string"))
    && Array.isArray(analysis.workPolicies) && analysis.workPolicies.every(row => row && typeof row.root === "string" && typeof row.circuit === "string" && ["covered", "incomplete"].includes(row.status))
    && typeof analysis.queryWork?.expenditureKnown === "boolean"
    && ["preparation", "query", "witnesses", "transferSteps", "transferValues", "findingChecks"].every(key => {
      const value = analysis.queryWork[key as Exclude<keyof typeof analysis.queryWork, "expenditureKnown">];
      return Number.isSafeInteger(value) && value >= 0;
    });
}

export async function scanFileIsolated(path: string, options: ScanOptions = {}, limits: ExecutionLimits = {}): Promise<ScanResult> {
  const started = performance.now();
  let result: ScanResult;
  try {
    const output = await runNodeModule(fileURLToPath(new URL("./worker.js", import.meta.url)), { path: resolve(path), options }, limits);
    result = JSON.parse(output.stdout) as ScanResult;
    const profileMatches = validSemanticProfile(result.semanticProfile) && (!validCompilerVersion(options.compilerVersion) || result.semanticProfile === semanticProfile(options.zkirVersion, options.compilerVersion))
      && ((options.zkirVersion === 3) === (result.semanticProfile === semanticProfile(3)));
    if (!validRuleCoverage(result) || !expectedMode(result, options.experimentalCounterQueries === true) || !profileMatches || !["complete", "incomplete"].includes(result.status) || !Array.isArray(result.findings) || !Array.isArray(result.diagnostics) || !result.coverage || !result.metrics) throw new WorkerFailure("worker-protocol", "Analysis worker did not return a supported report in the requested mode");
  } catch (error) {
    result = emptyResult(options.experimentalCounterQueries === true, options.zkirVersion, options.compilerVersion);
    if (result.schemaVersion === "1.7.0") result.analysis.queryWork.expenditureKnown = false;
    result.status = "incomplete";
    result.coverage.attempted = [resolve(path)];
    result.diagnostics.push({ code: error instanceof WorkerFailure ? error.code : "worker-error", message: error instanceof Error ? error.message : String(error), location: { file: resolve(path), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } });
  }
  result.metrics.workerMs = performance.now() - started;
  return result;
}
