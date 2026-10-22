import { informationUri, sarifRule } from "./rule-documentation.js";
import { pathToFileURL } from "node:url";
import { ruleIncompletenessOnly } from "../config.js";
import { ScanResult } from "../index.js";
import { Span, isNoEntrypointsNotice } from "../model.js";
import { detectors } from "../detectors/index.js";
import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { normalizeLineEndings } from "../source-text.js";
import { withFindingContract } from "../detectors/types.js";

export { PRINTER_SCHEMA_VERSION, printProgram, printProgramDocument } from "./printers.js";
export type { Printer, PrinterDocument } from "./printers.js";

export function human(result: ScanResult, options: { verbose?: boolean; ruleIncomplete?: "error" | "warn" } = {}): string {
  const output: string[] = [];
  for (const finding of result.findings) {
    output.push(`${finding.severity.toUpperCase()} — ${finding.title} [${finding.detectorId}]${finding.suppression ? " [suppressed]" : finding.baselineState === "unchanged" ? " [baseline]" : ""}`,
      `${finding.location.file}:${finding.location.line}:${finding.location.column}`,
      ...codeFrame(finding.location),
      finding.message,
      ...(finding.source ? [`Source: ${finding.source.file}:${finding.source.line}:${finding.source.column}`] : []),
      ...(finding.constraint ? [`Constraint: ${finding.constraint.file}:${finding.constraint.line}:${finding.constraint.column}`] : []),
      ...(finding.callPath.length ? [`Call path: ${finding.callPath.join(" → ")}`] : []),
      `Remediation: ${finding.remediation}`,
      ...(finding.suppression ? [`Suppression: ${finding.suppression.reason}`] : []), "");
  }
  const ruleWarning = options.ruleIncomplete === "warn" && ruleIncompletenessOnly(result);
  for (const diagnostic of result.diagnostics) output.push(`${ruleWarning && diagnostic.scope ? "WARNING: " : ""}${diagnostic.location.file}:${diagnostic.location.line}:${diagnostic.location.column}: ${diagnostic.code}${diagnostic.scope ? ` [rule ${diagnostic.scope.detectorId}; entry ${diagnostic.scope.entry}]` : ""}: ${diagnostic.message}`);
  if (ruleWarning) output.push("Rule incompleteness is a CI warning; the analysis and affected rules remain incomplete.");
  output.push(`Semantic profile: ${result.semanticProfile}.`);
  if (result.selection) output.push(`Output selection: ${result.selection.minimumSeverity ? `minimum severity ${result.selection.minimumSeverity}; ` : ""}${result.selection.findingsBeforeFilter} findings before filtering; ${result.selection.excludedRoots?.length ?? 0} roots excluded (imports retained).`);
  if (result.selection?.discovery) output.push(`Project discovery: ${result.selection.discovery.omittedLibraries.length} module-only libraries omitted as standalone roots; imported libraries remain analyzed. JSON/SARIF records the paths and inferred import directories.`);
  for (const root of result.coverage.noEntrypointRoots) output.push(`no entrypoints analyzed: ${root}; declaration checks completed.`);
  if (result.coverage.baselineStatus) output.push(`Baseline analysis: ${result.coverage.baselineStatus}; selected rules: ${result.status}.`);
  const ruleIds = [...new Set(result.coverage.rules?.map(row => row.detectorId) ?? [])];
  const incompleteRules = ruleIds.filter(id => result.coverage.rules!.some(row => row.detectorId === id && row.status === "incomplete"));
  output.push(`Rule coverage: ${ruleIds.length} selected rule(s); ${incompleteRules.length} with incomplete entries.`);
  for (const id of options.verbose ? ruleIds : incompleteRules) {
    const rows = result.coverage.rules!.filter(row => row.detectorId === id);
    output.push(`Rule coverage ${id}: ${rows.filter(row => row.status === "complete").length} complete, ${rows.filter(row => row.status === "not-applicable").length} structurally absent, ${rows.filter(row => row.status === "incomplete").length} unavailable/incomplete of ${rows.length} entrypoint(s).`);
  }
  const completion = result.schemaVersion === "1.7.0"
    ? `${result.analysis.coverage.filter(row => row.status === "covered").length}/${result.analysis.coverage.length} selected detector predicate(s) covered; ${result.coverage.completedEntries.length}/${result.entrypoints.length} entrypoint(s) completed by exact fallback; analysis ${result.status} for selected detector predicates (experimental Counter queries).`
    : `${result.coverage.completedEntries.length}/${result.entrypoints.length} entrypoint(s) completed; analysis ${result.status}.`;
  output.push(`${result.findings.length} finding(s), ${result.findings.filter(finding => finding.suppression).length} suppressed, ${result.findings.filter(finding => finding.baselineState === "unchanged").length} baseline; ${completion}${result.compilerValidated ? " Compiler validation passed." : ""}`);
  return output.join("\n").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
}

function codeFrame(span: Span): string[] {
  try {
    const text = normalizeLineEndings(readFileSync(span.file, "utf8")).split("\n")[span.line - 1];
    if (text === undefined) return [];
    const start = Math.max(0, span.column - 81);
    const snippet = text.slice(start, start + 240).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
    return [`  ${span.line} | ${start ? "…" : ""}${snippet}`, `  ${" ".repeat(String(span.line).length)} | ${" ".repeat(Math.max(0, span.column - 1 - start))}^`];
  } catch { return []; }
}

function location(span: Span) {
  const path = relative(process.cwd(), span.file);
  return { physicalLocation: {
    artifactLocation: path.startsWith("..") ? { uri: pathToFileURL(span.file).href } : { uri: path.split(/[\\/]/).map(encodeURIComponent).join("/"), uriBaseId: "%SRCROOT%" },
    region: { startLine: span.line, startColumn: span.column, endLine: span.endLine, endColumn: span.endColumn, byteOffset: span.start, byteLength: span.end - span.start },
  } };
}

export function sarif(result: ScanResult, options: { ruleIncomplete?: "error" | "warn" } = {}): object {
  const ruleWarning = options.ruleIncomplete === "warn" && ruleIncompletenessOnly(result);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Nightshade", version: result.toolVersion, ...(informationUri ? { informationUri } : {}), rules: [...detectors, ...(result.customDetectors ?? [])].map(sarifRule) } },
      columnKind: "utf16CodeUnits",
      originalUriBaseIds: { "%SRCROOT%": { uri: pathToFileURL(process.cwd() + "/").href } },
      invocations: [{ executionSuccessful: result.status === "complete", toolExecutionNotifications: result.diagnostics.map(diagnostic => ({ level: isNoEntrypointsNotice(diagnostic, result.coverage.noEntrypointRoots) ? "note" : ruleWarning && diagnostic.scope ? "warning" : "error", message: { text: `${diagnostic.code}: ${diagnostic.message}` }, locations: [location(diagnostic.location)], ...(diagnostic.scope ? { properties: { scope: diagnostic.scope } } : {}) })) }],
      properties: { scope: result.scope, ruleIncomplete: options.ruleIncomplete ?? "error", coverage: result.coverage, ...(result.ruleObservationWork ? { ruleObservationWork: result.ruleObservationWork } : {}), semanticProfile: result.semanticProfile, compilerValidated: result.compilerValidated, grammarRevision: result.grammarRevision, grammarBuild: result.grammarBuild, entrypoints: result.entrypoints,
        ...(result.selection ? { selection: result.selection } : {}),
        ...(result.customDetectors ? { customDetectors: result.customDetectors } : {}),
        ...(result.schemaVersion === "1.7.0" ? { analysis: result.analysis, exactCompletedEntries: result.coverage.completedEntries } : {}) },
      results: result.findings.map(finding => {
        const normalized = withFindingContract(finding);
        return {
        ruleId: normalized.detectorId, level: ["high", "critical"].includes(normalized.severity) ? "error" : normalized.severity === "info" ? "note" : "warning", message: { text: normalized.message },
        locations: [location(finding.location)],
        relatedLocations: [...(finding.source ? [{ id: 1, ...location(finding.source), message: { text: "Source" } }] : []), ...(finding.constraint ? [{ id: 2, ...location(finding.constraint), message: { text: "Relevant constraint or guard" } }] : [])],
        ...(finding.trace.length ? { codeFlows: [{ threadFlows: [{ locations: finding.trace.map(step => ({ location: { ...location(step.location), message: { text: `${step.kind}: ${step.label}` } } })) }] }] } : {}),
        partialFingerprints: { "nightshade/v1": normalized.fingerprint },
        ...(finding.suppression ? { suppressions: [{ kind: finding.suppression.kind ?? "external", status: "accepted", justification: finding.suppression.reason }] } : {}),
        ...(finding.baselineState ? { baselineState: finding.baselineState } : {}),
        properties: { ...finding.metadata, findingId: normalized.fingerprint, confidence: normalized.confidence, severity: normalized.severity, remediation: normalized.remediation, evidenceChain: normalized.evidenceChain, whyItMatters: normalized.whyItMatters },
      };
      }),
    }],
  };
}
