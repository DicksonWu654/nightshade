import type { AnalysisFacts } from "../dataflow/index.js";
import { requiredAbsenceBeforeSurvivingInsertion } from "../dataflow/collection-consumption.js";
import { mintQuantityEvidence } from "../dataflow/mint-quantities.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { ZERO_CONSUMPTION_RULE, zeroConsumptionScope } from "../semantic/zero-consumption-targets.js";
import { ZERO_SEND_TARGET } from "../semantic/zero-send-targets.js";
import { numericBound, parseType } from "../semantic/types.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

/** One ordinary atomic history joins exact persistent consumption with a
 * zero-inclusive payout observation. It proves neither zero feasibility nor
 * that an application must prohibit zero compensation for a useful action. */
export function zeroConsumptionFindings(facts: AnalysisFacts, allowance = 200000,
  entries: readonly string[] = facts.program.entries): Finding[] {
  const scope = zeroConsumptionScope(facts.program, entries);
  const incomplete = (reason: string): Finding[] => {
    ruleObservationIssue(facts, ZERO_CONSUMPTION_RULE, "zero-consumption-evidence-incomplete",
      `${reason}; zero-amount Set consumption review is incomplete`);
    return [];
  };
  if (!scope.complete) return incomplete("Resolved send/Set applicability exceeded its allowance");
  if (!scope.applicable) return [];
  if (!facts.invocationEvidence?.includes(ZERO_SEND_TARGET) || !facts.collectionEvidence || !facts.mintQuantityEvidence
    || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
    return incomplete("Exact invocation, collection, numeric operands and ordinary all-predicate histories are required");
  for (const entry of entries) if (!facts.completedEntries.includes(entry)) {
    const entryScope = zeroConsumptionScope(facts.program, [entry]);
    if (!entryScope.complete || entryScope.applicable) return incomplete("Applicable entry lacks complete successful-history coverage");
  }
  let work = 0;
  const charge = (units = 1) => {
    work += units;
    if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance)
      throw new Error("Consumption matching allowance exhausted");
  };
  const findings: Finding[] = [];
  try {
    for (const path of facts.paths) {
      charge();
      if (!entries.includes(path.entry)) continue;
      if (!path.operations || !path.predicates) return incomplete("Original operation/predicate history is unavailable");
      const evidence = mintQuantityEvidence(path, charge);
      for (let sendIndex = 0; sendIndex < path.operations.length; sendIndex++) {
        const send = path.operations[sendIndex];
        charge();
        if (send.kind !== "circuit-invocation" || send.name !== ZERO_SEND_TARGET) continue;
        const boundary = send.operationsBefore;
        if (boundary === undefined || !Number.isSafeInteger(boundary) || boundary < 0 || boundary > sendIndex)
          return incomplete("Canonical send lacks its original pre-body operation boundary");
        const amount = send.args[1], type = amount?.type && facts.program.representationOf(amount.type);
        const bound = type && numericBound(type);
        if (!amount || !type || !bound || bound > 1n << 128n)
          return incomplete("Canonical send amount lacks an exact unsigned scalar snapshot");
        const { range } = evidence.bounds(amount, type);
        if (range.minimum !== 0n) continue;
        for (let index = 0; index < boundary; index++) {
          charge();
          const insertion = path.operations[index];
          if (insertion.kind !== "collection-write" || insertion.name !== "insert") continue;
          const receiver = insertion.args[0]?.region;
          if (!receiver) return incomplete("Collection insertion lacks a resolved receiver");
          if (parseType(facts.program.representationOf(receiver.type)).name !== "Set") continue;
          const consumed = requiredAbsenceBeforeSurvivingInsertion(path, index, allowance - work, facts.program.meteringIdentity);
          charge(consumed.work);
          if (!consumed.complete) return incomplete("Consumption lacks exact operands/order or exhausted its allowance");
          for (const query of consumed.queries) {
            charge();
            const entry = facts.program.symbols.get(path.entry)!.name;
            const collection = facts.program.symbols.get(receiver.root)!.name;
            findings.push(finding(facts, {
              detectorId: ZERO_CONSUMPTION_RULE, severity: "info", confidence: "medium",
              title: "Required-absence Set key is consumed before a zero-inclusive payout",
              message: `${entry} enforces absence of an exact key in ${collection}, inserts that key before a canonical sendUnshielded whose modeled amount retains zero, and preserves that insertion through this successful history. Review whether consuming this record for zero compensation is intended. This does not prove zero transaction feasibility, a failed payout, one-use policy or deployed impact.`,
              location: send.location, constraint: query.location,
              trace: [{ kind: "constraint", label: "required absence of the exact Set key", location: query.location },
                { kind: "state-write", label: "same-key insertion survives completion", location: insertion.location },
                { kind: "call", label: "zero-inclusive canonical unshielded send", location: send.location }],
              callPath: send.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
              remediation: "If this application requires positive compensation before consuming this record, enforce positivity on the actual sent amount; otherwise document the intended zero-compensation transition.",
              metadata: { reviewRequired: true, entry, collection, evidence: "exact-pre-send-surviving-set-consumption",
                minimum: String(range.minimum), maximum: String(range.maximum), query: query.location, insertion: insertion.location,
                oneUseIntent: "unknown", pathFeasibility: "not-proven", deployedImpact: "not-proven" },
            }, `${path.entry}:${query.location.start}:${insertion.location.start}`));
          }
        }
      }
    }
  } catch (error) { return incomplete(error instanceof Error ? error.message : String(error)); }
  return unique(findings);
}

export const zeroAmountSetConsumptionReview: Detector = {
  id: ZERO_CONSUMPTION_RULE, defaultEnabled: true,
  description: "Review exact surviving Set absence consumption before a zero-inclusive canonical unshielded payout",
  requires: ["canonical-invocation-snapshots", "collection-observations", "all-predicates", "exact-numeric-operands", "completed-entries"],
  run: facts => zeroConsumptionFindings(facts),
};
