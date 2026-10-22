import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { ScanResult } from "../src/index.js";
import type { CompilerVersion, ZkirVersion } from "../src/semantic/profile.js";
import type { Policies } from "../src/policies.js";

export const reproductionKinds = ["positive", "corrected", "lookalike"] as const;
export type ReproductionKind = typeof reproductionKinds[number];
export interface ReproductionTarget {
  detector: string;
  positiveLines: number[];
  correctedLines?: number[];
  lookalikeLines?: number[];
  /** An imported source site must be explicit; otherwise use the checked root. */
  files?: Partial<Record<ReproductionKind, string>>;
}
export interface ReproductionCase {
  id: string;
  compilerVersion: CompilerVersion;
  zkirVersion: ZkirVersion;
  requiresOZ: boolean;
  checks: Record<ReproductionKind, { file: string; sha256: string }>;
  targets: ReproductionTarget[];
  policies?: Policies;
  groundTruthStatus: string;
  scope: string;
}
export interface ReproductionRegistry {
  version: string;
  cases: ReproductionCase[];
}
export const sha256 = (bytes: string | Buffer): string => createHash("sha256").update(bytes).digest("hex");

export function corpusFile(file: string, corpusRoot = resolve("tests/corpus")): string {
  const full = resolve(corpusRoot, file), within = relative(corpusRoot, full);
  if (isAbsolute(file) || within === ".." || within.startsWith(".." + sep) || isAbsolute(within)) throw new Error(`Source outside owned corpus: ${file}`);
  return full;
}

export function loadReproductionRegistry(file = "tests/corpus/synthetic-regressions.json", corpusRoot = resolve("tests/corpus")): ReproductionRegistry {
  const registry = JSON.parse(readFileSync(file, "utf8")) as ReproductionRegistry;
  if (registry.version !== "synthetic-regressions-1") throw new Error("Unsupported regression registry");
  const ids = new Set(registry.cases.map(item => item.id));
  if (ids.size !== registry.cases.length) throw new Error("Duplicate case identity");
  for (const item of registry.cases) {
    for (const kind of reproductionKinds) {
      const source = item.checks[kind];
      if (sha256(readFileSync(corpusFile(source.file, corpusRoot))) !== source.sha256) throw new Error(`Changed ${item.id} ${kind}`);
    }
    for (const target of item.targets) {
      if (!target.detector || !target.positiveLines.length || [...target.positiveLines, ...target.correctedLines ?? [], ...target.lookalikeLines ?? []].some(line => !Number.isSafeInteger(line) || line < 1)) throw new Error(`Invalid mapped sites: ${item.id}`);
      for (const file of Object.values(target.files ?? {})) corpusFile(file, corpusRoot);
    }
  }
  return registry;
}

export interface ReproductionCheck {
  kind: ReproductionKind;
  compilerValid: boolean;
  report: Pick<ScanResult, "status" | "entrypoints" | "findings" | "coverage" | "diagnostics">;
}

export function assessReproductionCase(item: ReproductionCase, checks: ReproductionCheck[], corpusRoot = resolve("tests/corpus")) {
  const compilerAccepted = reproductionKinds.every(kind => checks.some(check => check.kind === kind && check.compilerValid));
  const mapped = item.targets.length > 0 && item.groundTruthStatus !== "pending-mapped-sites";
  const targets = item.targets.map(target => {
    const observations = reproductionKinds.map(kind => {
      const check = checks.find(check => check.kind === kind), report = check?.report;
      const selected = report?.coverage.detectors.includes(target.detector) === true;
      const rows = report?.coverage.rules?.filter(row => row.detectorId === target.detector) ?? [];
      // Incomplete unrelated rules are retained in the report but cannot erase
      // complete mapped evidence. Missing mapped entries never imply success.
      const complete = selected && !!report?.entrypoints.length && report.entrypoints.every(entry => rows.some(row => row.entry === entry && row.status !== "incomplete"));
      const source = corpusFile(target.files?.[kind] ?? item.checks[kind].file, corpusRoot);
      const findings = report?.findings.filter(finding => finding.detectorId === target.detector) ?? [];
      const actual = [...new Set(findings.filter(finding => resolve(finding.location.file) === source).map(finding => finding.location.line))].sort((a, b) => a - b);
      const expected = [...new Set(target[`${kind}Lines`] ?? [])].sort((a, b) => a - b);
      const exactSites = findings.every(finding => resolve(finding.location.file) === source) && JSON.stringify(actual) === JSON.stringify(expected);
      return { kind, selected, complete, expected, actual, totalMatches: findings.length, exactSites, quiet: findings.length === 0 };
    });
    return { detector: target.detector, observations,
      positiveDetected: observations[0].complete && observations[0].exactSites && observations[0].actual.length > 0,
      controlsVerifiedQuiet: observations.slice(1).every(row => row.complete && row.quiet && row.expected.length === 0) };
  });
  const positiveDetected = mapped && compilerAccepted && targets.every(target => target.positiveDetected);
  const quietControls = mapped && compilerAccepted && targets.every(target => target.controlsVerifiedQuiet);
  return { caseId: item.id, mapped, compilerAccepted, positiveDetected, quietControls, qualifiedSourceClass: positiveDetected && quietControls, targets,
    rootStatuses: checks.map(check => ({ kind: check.kind, status: check.report.status, baselineStatus: check.report.coverage.baselineStatus, diagnosticCodes: check.report.diagnostics.map(issue => issue.code) })) };
}
