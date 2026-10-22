import type { AnalysisFacts } from "../dataflow/index.js";
import { mintQuantityEvidence } from "../dataflow/mint-quantities.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { ZERO_SEND_RULE, ZERO_SEND_TARGET, zeroSendScope } from "../semantic/zero-send-targets.js";
import { numericBound } from "../semantic/types.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

/** A zero-inclusive envelope is a review observation, never a feasibility proof. */
export function zeroSendFindings(facts: AnalysisFacts, allowance = 200000, entries: readonly string[] = facts.program.entries): Finding[] {
  const scope = zeroSendScope(facts.program, entries);
  const incomplete = (reason: string): Finding[] => {
    ruleObservationIssue(facts, ZERO_SEND_RULE, "zero-send-evidence-incomplete", `${reason}; zero-amount unshielded send review is incomplete`);
    return [];
  };
  if (!scope.complete) return incomplete("Canonical send applicability exceeded its allowance");
  if (!scope.applicable) return [];
  if (!facts.invocationEvidence?.includes(ZERO_SEND_TARGET) || !facts.mintQuantityEvidence
    || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
    return incomplete("Exact canonical invocation snapshots, numeric constraints and original successful histories are required");
  for (const entry of entries) {
    if (facts.completedEntries.includes(entry)) continue;
    const entryScope = zeroSendScope(facts.program, [entry]);
    if (!entryScope.complete || entryScope.applicable) return incomplete("Applicable entry lacks complete successful-history coverage");
  }
  let work = 0;
  const charge = (amount = 1) => {
    work += amount;
    if (!Number.isSafeInteger(allowance) || work > allowance) throw new Error("Numeric review allowance exhausted");
  };
  const results: Finding[] = [];
  try {
    for (const path of facts.paths) {
      charge();
      if (!facts.completedEntries.includes(path.entry)) return incomplete("Entry lacks complete successful-history coverage");
      const operations = (path.operations ?? []).filter(op => {
        charge();
        return op.kind === "circuit-invocation" && op.name === ZERO_SEND_TARGET;
      });
      if (!operations.length) continue;
      // Existing reusable projection reconstructs equality, exclusion and range
      // constraints independently for each original history, including aliases.
      const evidence = mintQuantityEvidence(path, charge);
      for (const operation of operations) {
        charge();
        const amount = operation.args[1];
        const type = amount?.type && facts.program.representationOf(amount.type);
        const bound = type && numericBound(type);
        if (!amount || !type || !bound || bound > 1n << 128n) return incomplete("Send amount lacks an exact unsigned scalar snapshot");
        const { range } = evidence.bounds(amount, type);
        if (range.minimum !== 0n) continue;
        results.push(finding(facts, {
          detectorId: ZERO_SEND_RULE, severity: "info", confidence: "medium",
          title: "Unshielded send amount retains zero in its modeled range",
          message: "A canonical sendUnshielded call has no modeled positive lower bound on its amount on this successful history. Review whether zero should be rejected. This static range observation does not establish a feasible zero transaction, proof success, node rejection or deployed impact.",
          location: operation.location, trace: [{ kind: "call", label: "Canonical unshielded send", location: operation.location }],
          callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "If zero sends are invalid for the application, enforce amount > 0 on the actual sent value before successful completion.",
          metadata: { reviewRequired: true, evidence: "zero-inclusive-unshielded-send-amount-range",
            scope: "static-unshielded-send-amount-review", entry: facts.program.symbols.get(path.entry)?.name,
            minimum: String(range.minimum), maximum: String(range.maximum), constant: amount.constant,
            pathFeasibility: "not-proven", proofSuccess: "not-proven", nodeRejection: "not-proven", deployedImpact: "not-proven" },
        }, path.entry));
      }
    }
  } catch (error) { return incomplete(error instanceof Error ? error.message : String(error)); }
  return unique(results);
}

export const zeroAmountUnshieldedSend: Detector = {
  id: ZERO_SEND_RULE, defaultEnabled: false,
  description: "Review canonical unshielded send amounts with a zero-inclusive successful-history range",
  requires: ["canonical-invocation-snapshots", "all-predicates", "exact-numeric-operands", "completed-entries"],
  run: facts => zeroSendFindings(facts),
};
