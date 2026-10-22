import { privatePredicateCover } from "../dataflow/predicate-cover.js";
import type { RuntimeOperation, SuccessfulPath } from "../dataflow/index.js";
import { VALUE_TRANSFER_CIRCUITS, mayTransferValue } from "../semantic/value-transfers.js";
import { spanId, type Span } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

interface TransferGroup {
  paths: SuccessfulPath[];
  operations: RuntimeOperation[];
  locations: Span[];
  invocations: Map<string, Span[]>;
}

export const unprotectedValueTransfer: Detector = {
  id: "unprotected-value-transfer",
  defaultEnabled: false,
  description: "Successful token operations have no required application predicate constraining private caller inputs",
  requires: ["successful-predicates", "all-predicates", "runtime-operations", "completed-entries"],
  run(facts) {
    const scope = mayTransferValue(facts.program);
    const issue = (code: string, message: string, location: Span = facts.program.rootSource.ast.span) => facts.diagnostics.push({ code, message: `${message}; value-transfer review is incomplete`, location });
    if (!scope.complete) { issue("predicate-analysis-budget", "Token-operation applicability exceeded its allowance"); return []; }
    if (!scope.applicable) return [];
    if (facts.predicateScope !== "all") { issue("predicate-evidence-unavailable", "Token-operation review requires complete private and public predicates"); return []; }
    const findings: Finding[] = [];
    let work = scope.work;
    for (const entry of facts.completedEntries) {
      if (facts.program.symbols.get(entry)!.kind === "constructor") continue;
      const groups = new Map<string, TransferGroup>();
      for (const path of facts.paths) {
        if (path.entry !== entry) continue;
        const seen = new Set<string>();
        for (const operation of path.operations ?? []) {
          if (++work > 1000000) { issue("predicate-analysis-budget", "Token-operation grouping exceeded its allowance"); return []; }
          if (operation.kind !== "kernel-write" && operation.kind !== "native-witness") continue;
          const index = operation.callPath.findIndex(callee => VALUE_TRANSFER_CIRCUITS.has(callee));
          if (index < 0) continue;
          if (!operation.callSites?.[index]) { issue("predicate-evidence-unavailable", "Token-operation invocation evidence is missing", operation.location); return []; }
          const callee = operation.callPath[index];
          const group: TransferGroup = groups.get(callee) ?? { paths: [], operations: [], locations: [], invocations: new Map() };
          if (!seen.has(callee)) { group.paths.push(path); seen.add(callee); }
          const location = operation.callSites[index];
          const chain = operation.callSites.slice(0, index + 1), invocation = JSON.stringify(chain.map(spanId));
          if (!group.invocations.has(invocation)) { group.invocations.set(invocation, chain); group.locations.push(location); group.operations.push(operation); }
          groups.set(callee, group);
        }
      }
      for (const [callee, group] of groups) {
        const cover = privatePredicateCover(group.paths, Math.min(100000, 1000000 - work));
        work += cover.work;
        if (cover.status === "incomplete") { issue("predicate-analysis-budget", "Application predicate coverage exceeded its allowance or evidence is missing", group.locations[0]); return []; }
        if (cover.status !== "unconstrained") continue;
        const name = facts.program.symbols.get(entry)!.name, operationName = facts.program.symbols.get(callee)!.name;
        findings.push(finding(facts, {
          detectorId: unprotectedValueTransfer.id, severity: "low", confidence: "low", title: "Token operation has no required caller-input constraint",
          message: `${name} reaches ${operationName} on modeled successful histories with the same recorded public conditions that collectively impose no required private-input predicate. This is limited to recorded predicates; implicit arithmetic and transaction checks still apply. Public minting, payment and faucet behavior may be intentional. Standard-library recipient and change branches are excluded. Review the application policy.`,
          location: group.locations[0], trace: group.locations.map(location => ({ kind: "effect", label: operationName, location })),
          callPath: group.operations[0].callPath.map(id => facts.program.symbols.get(id)!.name),
          remediation: "Confirm whether this operation is intentionally public. If access should be restricted, enforce the intended caller or protocol check. A private-dependent condition alone is not proof of authentication.",
          metadata: { reviewRequired: true, authenticationIntent: "unknown", pathFeasibility: "not-proven", entry: name, operation: operationName,
            evidence: "application-private-predicate-cover", successfulHistories: group.paths.length, invocationSites: group.locations, invocationChains: [...group.invocations.values()],
            mechanism: "bounded-query-over-recorded-histories", doesNotProve: "authorization-or-exploitability" },
        }, `${entry}:${callee}`));
      }
    }
    return findings;
  },
};
