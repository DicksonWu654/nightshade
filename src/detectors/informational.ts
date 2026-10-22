import type { AnalysisFacts } from "../dataflow/index.js";
import { cachedSourceObservations, type SourceObservationKind } from "../analysis/source-observations.js";
import { cachedLedgerUsage } from "../analysis/ledger-usage.js";
import { uncoveredDeclarations } from "../analysis/assertions.js";
import { estimateWork } from "../analysis/work.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { spanId, type Span } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

const information = (facts: AnalysisFacts, id: string, location: Span, message: string, metadata: Record<string, unknown>, remediation: string): Finding => finding(facts, {
  detectorId: id, severity: "info", confidence: "high", title: id.split("-").join(" "), message, location,
  trace: [], callPath: [], remediation, metadata: { informational: true, reviewRequired: true, ...metadata },
});
const sourceRule = (id: SourceObservationKind, description: string, remediation: string): Detector => ({
  id, description, defaultEnabled: true, requires: ["resolved-model", "typed-source-constants"],
  run(facts) {
    const observations = cachedSourceObservations(facts.program);
    if (!observations.complete) {
      ruleObservationIssue(facts, id, "source-observation-budget", "Source-observation work/depth allowance exhausted; this rule has no complete source result");
      return [];
    }
    return observations.observations.filter(item => item.kind === id).map(item => information(facts, id, item.location, item.message,
      { ...item.metadata, scope: id === "duplicated-branch-tail" ? "resolved-compilation-unit-source-observations" : "root-compilation-unit-source-observations" }, remediation));
  },
});

export const unusedDeclaration = sourceRule("unused-declaration", "Ledger, witness or private circuit has no reference in the compilation unit",
  "Remove stale declarations or restore the intended reference. External consumers of exported ledger data and library APIs require separate review.");
export const deadCode = sourceRule("dead-code", "Statement, branch or loop is excluded by source control flow",
  "Review the constant condition, empty range or preceding termination; remove dead code or restore its intended execution.");
export const shadowing = sourceRule("shadowing", "Parameter or local binding hides an outer declaration",
  "Use distinct names, especially for locals that hide ledger fields or helper circuits.");
export const unnecessaryDisclose = sourceRule("unnecessary-disclose", "Disclosure operand is already public in the source context",
  "Remove redundant disclosure only after confirming the compiler accepts the intended privacy boundary; this is a readability observation, not a secret leak.");
export const constantCondition = sourceRule("constant-condition", "Branch condition reduces to a typed scalar source constant",
  "Review configuration and comparison operands; simplify an intentional constant branch or correct an unintended condition.");
export const duplicatedBranchTail = sourceRule("duplicated-branch-tail", "Terminating branch repeats its immediate following expression and return tail",
  "Consider sharing the repeated tail after preserving branch-specific work and return behavior. Review proof constraints, privacy and transaction ordering before refactoring; duplicate source does not establish duplicate execution or measured cost.");

export const redundantBooleanBranch = sourceRule("redundant-boolean-branch", "Both branch arms only return opposite Boolean literals",
  "Consider returning the condition or its negation directly. Retain intentional explanatory branches and the condition's effects, constraints and disclosure boundary. This source simplification does not establish compiler cost or a security defect.");

export const writeOnlyLedger: Detector = {
  id: "write-only-ledger", description: "Ordinary ledger Cell is explicitly written but has no Compact source read in the compilation unit", defaultEnabled: false,
  requires: ["resolved-model", "ledger-read-write-usage", "bounded-source-absence"],
  run(facts) {
    const usage = cachedLedgerUsage(facts.program);
    for (const issue of usage.issues) ruleObservationIssue(facts, writeOnlyLedger.id, issue.code, issue.message);
    return usage.observations.map(item => information(facts, writeOnlyLedger.id, item.location,
      `Ledger field ${item.name} is written but never read by Compact code in this compilation unit. A stored configuration value may not affect circuit behavior; external readers can intentionally consume it.`,
      { evidence: "resolved-ledger-writes-no-source-reads", scope: "compilation-unit-source-usage", ledger: item.name,
        instances: item.instances, writers: item.writers, offchainReads: "not-analyzed", uselessStorage: "not-claimed" },
      "Review whether circuit logic should read this stored value. Retain intentional off-chain metadata and document its consumers; this finding does not establish that writes can safely be removed."));
  },
};

export const alwaysTrueAssertion: Detector = {
  id: "always-true-assertion", description: "Assertion is already true on every analyzed reach before enforcing it", defaultEnabled: true,
  requires: ["assertion-reaches", "completed-entries"],
  run(facts) {
    const uncovered = uncoveredDeclarations(facts), completed = new Set([...facts.completedEntries, ...facts.sourceQueries?.map(query => query.entry) ?? []]), groups = new Map<string, typeof facts.assertionReaches>();
    for (const reach of [...facts.assertionReaches, ...facts.sourceQueries?.flatMap(query => query.assertionReaches) ?? []]) {
      if (reach.location.file !== facts.program.rootSource.path) continue;
      const key = spanId(reach.location), group = groups.get(key) ?? []; group.push(reach); groups.set(key, group);
    }
    const results: Finding[] = [];
    for (const reaches of groups.values()) {
      if (reaches.some(reach => reach.mayFail !== false || !reach.maySucceed || !completed.has(reach.entry)
        || uncovered.has(spanId(facts.program.functions.get(reach.owner)!.declaration.span)))) continue;
      results.push(information(facts, alwaysTrueAssertion.id, reaches[0].location,
        "Assertion is already true on every modeled reach, before this assertion adds a constraint. A prior guard or fixed input may make it redundant.",
        { evidence: "pre-assertion-constant-truth", entries: [...new Set(reaches.map(reach => facts.program.symbols.get(reach.entry)!.name))] },
        "Check for a tautological comparison or a missing operand. Retain intentional defensive checks when they document a helper's contract."));
    }
    return results;
  },
};

export const timeDependence: Detector = {
  id: "time-dependence", description: "A successful circuit uses a protocol block-time comparison", defaultEnabled: true,
  requires: ["runtime-operations", "completed-entries"],
  run(facts) {
    const findings: Finding[] = [], completed = new Set([...facts.completedEntries, ...facts.sourceQueries?.map(query => query.entry) ?? []]);
    let work = 0;
    for (const path of [...facts.paths, ...facts.sourceQueries?.flatMap(query => query.paths) ?? []]) for (const operation of path.operations ?? []) {
      if (++work > 1000000) { facts.diagnostics.push({ code: "time-observation-budget", message: "Block-time observation allowance exhausted; time-dependence review is incomplete", location: facts.program.rootSource.ast.span }); return []; }
      if (!completed.has(path.entry) || operation.kind !== "kernel-read" || !["blockTimeLessThan", "blockTimeGreaterThan"].includes(operation.name)) continue;
      const location = operation.callSites?.slice().reverse().find(site => site.file === facts.program.rootSource.path) ?? operation.location;
      findings.push(information(facts, timeDependence.id, location,
        "A modeled successful history uses protocol block time. Time bounds can affect liveness and acceptance near a boundary; they are not a randomness source.",
        { evidence: "canonical-kernel-time-read", operation: operation.name, entry: facts.program.symbols.get(path.entry)!.name },
        "Review boundary inclusivity, permitted clock variation and expiry behavior. Intentional deadlines and timelocks are normal uses."));
    }
    return unique(findings);
  },
};

export const circuitCost: Detector = {
  id: "circuit-cost", description: "Circuit exceeds 10000 expanded source-operation units (not proof rows)", defaultEnabled: true,
  requires: ["cfg", "resolved-calls", "static-loop-bounds"],
  run(facts) {
    const results: Finding[] = [];
    const allowance = Math.max(1, Math.floor(200000 / Math.max(1, facts.program.entries.length)));
    for (const entry of facts.program.entries) {
      const estimate = estimateWork(facts.program, entry, allowance), symbol = facts.program.symbols.get(entry)!;
      if (!estimate) { facts.diagnostics.push({ code: "work-estimate-unavailable", message: `Finite work estimate unavailable or ${allowance}-visit allowance exhausted for ${symbol.name}; circuit-cost review is incomplete`, location: symbol.span }); continue; }
      if (estimate.units <= 10000) continue;
      results.push(information(facts, circuitCost.id, symbol.span,
        `${symbol.name} has an expanded source-operation upper bound of ${estimate.units} units, above the informational threshold of 10000. This is not measured proof rows, prover time or optimized compiler cost.`,
        { ...estimate, threshold: 10000, estimateOnly: true }, "Review repeated source work and measure actual compiler/prover cost before optimizing. Use a circuit-work-budget policy for project-specific limits."));
    }
    return results;
  },
};

export const informationalDetectors = [unusedDeclaration, deadCode, shadowing, unnecessaryDisclose, constantCondition, duplicatedBranchTail, redundantBooleanBranch, writeOnlyLedger, alwaysTrueAssertion, timeDependence, circuitCost];
