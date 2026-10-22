import { extractTerminalCounterRegion, type CounterRegionLimits } from "../analysis/counter-regions.js";
import { queryCounterRegion, type CounterQueryLimits, type CounterQueryWork, type CounterQueryWitness } from "../dataflow/counter-queries.js";
import type { Dataflow } from "../dataflow/index.js";
import type { Diagnostic, Span } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import { secretPublicationOnPath, unguardedWriteOnPath } from "./path-observations.js";
import { unique, type Finding } from "./types.js";

export type CounterPolicyDetector = "declared-secret-publication" | "unguarded-sensitive-state-write";
export interface CounterConsumerLimits {
  query?: CounterQueryLimits;
  maxPolicies?: number;
  maxFindingWork?: number;
  maxFindings?: number;
}
export type CounterConsumerResult =
  | { status: "ineligible"; reason: string; location: Span }
  | { status: "incomplete"; diagnostics: Diagnostic[] }
  | { status: "complete"; findings: Finding[]; witnesses: CounterQueryWitness[];
      coverage: { contract: "terminal-counter-policy-consumers-1"; scope: "selected-policy-predicates";
        entry: string; detectors: CounterPolicyDetector[]; representedAssignments: bigint };
      work: { query: CounterQueryWork; findingChecks: number } };

const positive = (value: number | undefined, fallback: number): number => {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > 1000000) throw new Error("Invalid Counter consumer budget");
  return actual;
};

/**
 * Internal consumer for two existing predicates over a qualified region. The
 * first control parameter reaches every optional increment sink, so its public
 * flow query supplies all mutation sites, with all their ordinary-transfer flows.
 * This suffices for these two predicates only: neither inspects before/after
 * constants, bindings, rejection, or arbitrary Boolean combinations. No partial
 * witness collection is promoted to AnalysisFacts or whole-history coverage.
 */
export function counterPolicyFindings(flow: Dataflow, entry: string, policies: ResolvedPolicies,
  selected: readonly CounterPolicyDetector[], limits: CounterConsumerLimits = {}): CounterConsumerResult {
  if (!Array.isArray(selected) || !selected.length || selected.some(id => !["declared-secret-publication", "unguarded-sensitive-state-write"].includes(id))) throw new Error("Unsupported Counter policy detector selection");
  if (!limits || typeof limits !== "object" || Array.isArray(limits) || Object.keys(limits).some(key => !["query", "maxPolicies", "maxFindingWork", "maxFindings"].includes(key))) throw new Error("Invalid Counter consumer limits");
  const maxPolicies = positive(limits.maxPolicies, 256);
  const maxFindingWork = positive(limits.maxFindingWork, 20000);
  const maxFindings = positive(limits.maxFindings, 4096);
  const location = flow.program.functions.get(entry)?.declaration.span ?? flow.program.rootSource.ast.span;
  const incomplete = (code: string, message: string): CounterConsumerResult => ({ status: "incomplete", diagnostics: [{ code, message, location: { ...location } }] });
  if (policies.secrets.length + policies.authorization.length > maxPolicies) return incomplete("counter-consumer-policy-budget", "Counter consumer policy budget exhausted; results are incomplete");
  const extracted = extractTerminalCounterRegion(flow.program, entry, limits.query?.region as CounterRegionLimits | undefined);
  if (extracted.status !== "eligible") return extracted.status === "incomplete" ? { status: "incomplete", diagnostics: extracted.diagnostics }
    : { status: "ineligible", reason: extracted.reason, location: extracted.location };
  const preparation = extracted.work.syntaxNodes + extracted.work.cfgNodes + extracted.work.branches;
  const remainingQueryWork = positive(limits.query?.maxQueryWork, 20000) - preparation;
  if (remainingQueryWork < 1) return incomplete("counter-query-budget", "Counter consumer preparation exhausted query work; results are incomplete");
  const result = queryCounterRegion(flow, entry, { kind: "public-flow", source: extracted.region.diamonds[0].parameter }, { ...limits.query, maxQueryWork: remainingQueryWork });
  if (result.status !== "complete") return result;
  if (result.coverage.contract !== "terminal-counter-query-1" || result.coverage.scope !== "requested-existential-observations"
    || result.evidence.length !== extracted.region.diamonds.length || result.witnesses.length !== extracted.region.diamonds.length) return incomplete("counter-consumer-contract", "Counter query cannot establish complete mutation-site coverage for these predicates");
  const findings: Finding[] = [];
  let findingChecks = 0;
  for (const witness of result.witnesses) {
    const path = witness.path;
    const count = (selected.includes("declared-secret-publication") ? path.sinks.reduce((sum, sink) => sum + sink.value.flows.length * Math.max(1, policies.secrets.length), 0) : 0)
      + (selected.includes("unguarded-sensitive-state-write") ? path.writes.length * Math.max(1, policies.authorization.length) : 0);
    if (count > maxFindingWork - findingChecks) return incomplete("counter-consumer-work-budget", "Counter policy matching work budget exhausted; results are incomplete");
    findingChecks += count;
    const observed = [
      ...(selected.includes("declared-secret-publication") ? secretPublicationOnPath(flow.program, path, policies) : []),
      ...(selected.includes("unguarded-sensitive-state-write") ? unguardedWriteOnPath(flow.program, path, policies) : []),
    ];
    if (observed.length > maxFindings - findings.length) return incomplete("counter-consumer-finding-budget", "Counter finding budget exhausted; results are incomplete");
    findings.push(...observed);
  }
  return { status: "complete", findings: unique(findings), witnesses: result.witnesses,
    coverage: { contract: "terminal-counter-policy-consumers-1", scope: "selected-policy-predicates", entry,
      detectors: [...new Set(selected)], representedAssignments: result.coverage.assignments }, work: { query: { ...result.work, query: result.work.query + preparation }, findingChecks } };
}
