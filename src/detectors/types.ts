import { createHash } from "node:crypto";
import { relative } from "node:path";
import { AnalysisFacts, TraceStep } from "../dataflow/index.js";
import { Span } from "../model.js";
import { ResolvedPolicies } from "../policies.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface Finding {
  detectorId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  message: string;
  location: Span;
  source?: Span;
  constraint?: Span;
  trace: TraceStep[];
  callPath: string[];
  remediation: string;
  fingerprint: string;
  /** One-line, source-verifiable provenance for report consumers. */
  evidenceChain?: string;
  /** One-line impact explanation for reviewers. */
  whyItMatters?: string;
  metadata: Record<string, unknown>;
  suppression?: { reason: string; kind?: "inSource" | "external" };
  baselineState?: "new" | "unchanged";
}

function oneLine(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
}

function evidencePosition(span: Span): string {
  return `${span.file}:${span.line}:${span.column}`;
}

/**
 * Add stable evidence fields to findings produced by older detector
 * implementations. Source and constraint locations, trace labels and the
 * final finding location are retained so a consumer can verify the chain
 * without depending on engine-specific internal trace representatives.
 */
export function withFindingContract(value: Finding): Finding {
  const hops = [
    value.source ? `source ${evidencePosition(value.source)}` : undefined,
    value.constraint ? `constraint ${evidencePosition(value.constraint)}` : undefined,
    // Keep both the semantic label and its source position. A trace can point
    // into a resolved dependency, so consumers must retain the referenced
    // source file when checking the chain.
    ...value.trace.map(step => `${step.kind} ${oneLine(step.label)} ${evidencePosition(step.location)}`),
    value.callPath.length ? `call ${value.callPath.map(oneLine).join(" -> ")}` : undefined,
    `finding ${evidencePosition(value.location)}`,
  ].filter((item): item is string => !!item);
  const evidenceChain = oneLine(value.evidenceChain ?? hops.join(" -> "));
  const whyItMatters = oneLine(value.whyItMatters ?? (typeof value.metadata.whyItMatters === "string" ? value.metadata.whyItMatters : value.message));
  return { ...value, evidenceChain, whyItMatters };
}

export interface Detector {
  id: string;
  description: string;
  requires: string[];
  policyRequired?: boolean;
  /** Heuristics demoted by the precision contract require explicit selection. */
  defaultEnabled?: boolean;
  run(facts: AnalysisFacts, policies?: ResolvedPolicies): Finding[];
}

export function finding(facts: Pick<AnalysisFacts, "program">, value: Omit<Finding, "fingerprint">, discriminator = ""): Finding {
  const root = facts.program.sourceRoot;
  for (const file of [...facts.program.files.keys()].sort((left, right) => right.length - left.length))
    discriminator = discriminator.replaceAll(file, () => relative(root, file));
  const key = [value.detectorId, relative(root, facts.program.root), relative(root, value.location.file), value.location.start, discriminator].join(":");
  return withFindingContract({ ...value, fingerprint: createHash("sha256").update(key).digest("hex") });
}

export function unique(findings: Finding[]): Finding[] {
  return [...new Map(findings.map(item => [item.fingerprint, item])).values()];
}
