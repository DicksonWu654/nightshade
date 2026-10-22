import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { ScanOptions, ScanResult } from "./index.js";
import { Confidence, Severity, detectors } from "./detectors/index.js";
import { Span, fail, isNoEntrypointsNotice } from "./model.js";
import { validatePolicies } from "./policies.js";
import { ExecutionLimits, executionLimits } from "./runtime/process.js";
import { validCompilerVersion, validZkirVersion, type ZkirVersion } from "./semantic/profile.js";
import { validateExclusions } from "./reporting/selection.js";
import { customDetectorId } from "./runtime/detector-modules.js";

export const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const confidenceRank: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

export interface Configuration {
  roots?: string[];
  exclude?: string[];
  minSeverity?: Severity;
  options: ScanOptions;
  execution?: ExecutionLimits;
  failOn: Severity | "none";
  ruleIncomplete?: "error" | "warn";
  minConfidence: Confidence;
  suppressions: { fingerprint: string; reason: string }[];
}

export function configLocation(path: string): Span {
  return { file: resolve(path), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
}

function jsonFile(path: string): unknown {
  const location = configLocation(path);
  if (statSync(path).size > 1024 * 1024) fail("config-budget", "Configuration exceeds 1 MiB", location);
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch { return fail("invalid-config", "Cannot parse configuration JSON", location); }
}

function record(value: unknown, allowed: string[], location: Span): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) fail("invalid-config", `Expected an object with only: ${allowed.join(", ")}`, location);
  return value as Record<string, unknown>;
}

function strings(value: unknown, location: Span): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string" || !item.length)) fail("invalid-config", "Expected an array of non-empty strings", location);
  return value as string[];
}

export function readConfiguration(path?: string, observeExperimentalMode?: (enabled: boolean) => void, observeZkirVersion?: (version: ZkirVersion) => void): Configuration {
  const result: Configuration = { options: {}, failOn: "info", minConfidence: "low", suppressions: [] };
  if (!path) return result;
  const location = configLocation(path);
  const raw = jsonFile(path);
  // Preserve an explicit mode request in CLI error reports even if another field is invalid.
  if (raw && typeof raw === "object" && !Array.isArray(raw) && "experimentalCounterQueries" in raw && typeof raw.experimentalCounterQueries === "boolean") observeExperimentalMode?.(raw.experimentalCounterQueries);
  if (raw && typeof raw === "object" && "zkirVersion" in raw && validZkirVersion(raw.zkirVersion)) observeZkirVersion?.(raw.zkirVersion);
  const config = record(raw, ["version", "roots", "searchPaths", "detectors", "policies", "budgets", "execution", "failOn", "minConfidence", "minSeverity", "exclude", "suppressions", "experimentalCounterQueries", "zkirVersion", "compilerVersion", "profile", "ruleIncomplete"], location);
  if (config.version !== 1) fail("invalid-config", "Configuration version must be 1", location);
  if (config.compilerVersion !== undefined) {
    if (!validCompilerVersion(config.compilerVersion)) fail("unsupported-compiler-version", "Supported compilerVersion values: 0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0, 0.35.0-rc.1, 0.35.0", location);
    result.options.compilerVersion = config.compilerVersion;
  }
  if (config.zkirVersion !== undefined) {
    if (!validZkirVersion(config.zkirVersion)) fail("invalid-config", "zkirVersion must be 2 or 3", location);
    result.options.zkirVersion = config.zkirVersion;
  }
  if (config.experimentalCounterQueries !== undefined) {
    if (typeof config.experimentalCounterQueries !== "boolean") fail("invalid-config", "experimentalCounterQueries must be a boolean", location);
    result.options.experimentalCounterQueries = config.experimentalCounterQueries;
  }
  if (config.ruleIncomplete !== undefined) {
    if (config.ruleIncomplete !== "error" && config.ruleIncomplete !== "warn") fail("invalid-config", "ruleIncomplete must be error or warn", location);
    result.ruleIncomplete = config.ruleIncomplete;
  }
  if (config.profile !== undefined) {
    if (config.profile !== "audit" && config.profile !== "hygiene") fail("invalid-config", "profile must be audit or hygiene", location);
    result.options.profile = config.profile;
  }
  if (config.roots !== undefined) result.roots = strings(config.roots, location).map(pathname => resolve(dirname(path), pathname));
  if (config.exclude !== undefined) result.exclude = validateExclusions(config.exclude, location);
  if (config.minSeverity !== undefined) {
    if (typeof config.minSeverity !== "string" || !Object.hasOwn(severityRank, config.minSeverity)) fail("invalid-config", "Unknown minimum severity", location);
    result.minSeverity = config.minSeverity as Severity;
  }
  if (result.roots?.length === 0) fail("invalid-config", "roots cannot be empty", location);
  if (config.searchPaths !== undefined) result.options.searchPaths = strings(config.searchPaths, location).map(pathname => resolve(dirname(path), pathname));
  if (config.detectors !== undefined) {
    result.options.detectors = strings(config.detectors, location);
    if (result.options.detectors.length === 0 || result.options.detectors.some(id => !customDetectorId(id) && !detectors.some(detector => detector.id === id))) fail("invalid-config", "Detector selection must contain known detector IDs or explicitly loaded custom- IDs", location);
  }
  if (config.policies !== undefined) result.options.policies = validatePolicies(config.policies, location);
  if (config.execution !== undefined) {
    const execution = record(config.execution, ["timeoutMs", "heapMiB", "maxOutputBytes"], location);
    try { result.execution = executionLimits(execution); }
    catch (error) { fail("invalid-config", error instanceof Error ? error.message : String(error), location); }
  }
  if (config.budgets !== undefined) {
    const budgets = record(config.budgets, ["maxSteps", "maxPaths", "maxValues"], location);
    for (const [key, value] of Object.entries(budgets)) {
      if (!Number.isSafeInteger(value) || Number(value) < 1) fail("invalid-config", `Invalid budget ${key}`, location);
      result.options[key as "maxSteps" | "maxPaths" | "maxValues"] = Number(value);
    }
  }
  if (config.failOn !== undefined) {
    if (typeof config.failOn !== "string" || ![...Object.keys(severityRank), "none"].includes(config.failOn)) fail("invalid-config", "Unknown failOn severity", location);
    result.failOn = config.failOn as Severity | "none";
  }
  if (config.minConfidence !== undefined) {
    if (typeof config.minConfidence !== "string" || !Object.keys(confidenceRank).includes(config.minConfidence)) fail("invalid-config", "Unknown confidence threshold", location);
    result.minConfidence = config.minConfidence as Confidence;
  }
  if (config.suppressions !== undefined) {
    if (!Array.isArray(config.suppressions)) fail("invalid-config", "suppressions must be an array", location);
    result.suppressions = config.suppressions.map(entry => {
      const suppression = record(entry, ["fingerprint", "reason"], location);
      if (typeof suppression.fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(suppression.fingerprint) || typeof suppression.reason !== "string" || suppression.reason.trim().length < 8) fail("invalid-config", "Suppression requires an exact fingerprint and a meaningful reason (at least 8 characters)", location);
      return { fingerprint: suppression.fingerprint, reason: suppression.reason };
    });
  }
  return result;
}

export function defaultConfigurationPath(path: string): string | undefined {
  const directory = existsSync(path) && statSync(path).isDirectory() ? resolve(path) : dirname(resolve(path));
  const candidate = resolve(directory, "nightshade.json");
  return existsSync(candidate) ? candidate : undefined;
}

export function readBaseline(path: string): Set<string> {
  const location = configLocation(path);
  const baseline = record(jsonFile(path), ["version", "fingerprints"], location);
  if (baseline.version !== 1) fail("invalid-config", "Baseline version must be 1", location);
  const fingerprints = strings(baseline.fingerprints, location);
  if (fingerprints.some(value => !/^[a-f0-9]{64}$/.test(value))) fail("invalid-config", "Invalid baseline fingerprint", location);
  return new Set(fingerprints);
}

export function applyWorkflow(result: ScanResult, config: Configuration, baseline?: Set<string>): void {
  const suppressions = new Map(config.suppressions.map(item => [item.fingerprint, item.reason]));
  for (const finding of result.findings) {
    const reason = suppressions.get(finding.fingerprint);
    if (reason) finding.suppression = { reason };
    if (baseline) finding.baselineState = baseline.has(finding.fingerprint) ? "unchanged" : "new";
  }
  for (const fingerprint of suppressions.keys()) if (!result.findings.some(finding => finding.fingerprint === fingerprint)) {
    result.diagnostics.push({ code: "unused-suppression", message: `Suppression ${fingerprint} matches no finding in this scan`, location: configLocation(result.coverage.attempted[0] ?? ".") });
    result.status = "incomplete";
  }
  if (config.minSeverity !== undefined) {
    result.selection = { ...result.selection, minimumSeverity: config.minSeverity, findingsBeforeFilter: result.findings.length };
    result.findings = result.findings.filter(finding => severityRank[finding.severity] >= severityRank[config.minSeverity!]);
  }
}

/** Only entry-scoped rule gaps may affect CI policy; baseline/setup failures never do. */
export function ruleIncompletenessOnly(result: ScanResult): boolean {
  return result.status === "incomplete" && result.coverage.baselineStatus === "complete"
    && !!result.coverage.rules?.some(row => row.status === "incomplete")
    && result.diagnostics.some(d => d.scope?.kind === "rule")
    && result.diagnostics.every(d => isNoEntrypointsNotice(d, result.coverage.noEntrypointRoots)
      || d.scope?.kind === "rule" && !d.code.startsWith("worker-"));
}

export function exitStatus(result: ScanResult, config: Configuration): number {
  if (result.status === "incomplete" && !(config.ruleIncomplete === "warn" && ruleIncompletenessOnly(result))) return 2;
  if (config.failOn === "none") return 0;
  const threshold = severityRank[config.failOn];
  return result.findings.some(finding => !finding.suppression && finding.baselineState !== "unchanged" && severityRank[finding.severity] >= threshold && confidenceRank[finding.confidence] >= confidenceRank[config.minConfidence]) ? 1 : 0;
}
