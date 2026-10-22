import { currentRootObservations } from "../analysis/current-root.js";
import { CURRENT_ROOT_RULE } from "../dataflow/merkle-freshness.js";
import { spanId } from "../model.js";
import { finding, type Detector } from "./types.js";

export const currentRootPolicyMismatch: Detector = {
  id: CURRENT_ROOT_RULE,
  description: "An explicitly selected membership guard lacks current-root evidence at enforcement time",
  policyRequired: true, defaultEnabled: false,
  requires: ["declared-current-root-policy", "all-successful-predicates", "native-merkle-queries", "ordered-writes"],
  run(facts, policies) {
    const result = currentRootObservations(facts, policies);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(observation => {
      const { policy, queries, guard, reason, overlappingWrites } = observation;
      const entry = facts.program.symbols.get(policy.circuit)!, ledger = facts.program.symbols.get(policy.ledger)!;
      return finding(facts, {
        detectorId: CURRENT_ROOT_RULE, severity: "medium", confidence: "high",
        title: "Declared current-root membership lacks guard-time evidence",
        message: `The currentRootMembership policy for ${entry.name}/${ledger.name} requires current-root checks when enforced. ${reason === "query-not-current-only"
          ? "This required native HistoricMerkleTree check accepts historical roots without a recognized current-only invariant."
          : "This required saved check is enforced after a write that may overlap its tree; its query-time current-root proof does not certify the tree at this guard."} This is a static policy mismatch, not proof that a stale root is present or accepted in deployment.`,
        location: guard.location, ...(queries.length === 1 ? { source: queries[0].location } : {}), constraint: guard.location,
        callPath: guard.callPath.map(id => facts.program.symbols.get(id)!.name),
        trace: [...queries.map(query => ({ kind: "source", label: queries.length === 1 ? "native root check at query time" : "equivalent candidate query; saved occurrence not identified", location: query.location })),
          ...overlappingWrites.map(location => ({ kind: "effect", label: "possibly overlapping tree write", location })),
          { kind: "constraint", label: "positive check enforcement", location: guard.location }],
        remediation: "Use MerkleTree when historical membership is unwanted, or reset history and evaluate a fresh check without overlapping writes before enforcing it. If historical snapshots are intended, omit this policy. Later-effect freshness requires separate application review.",
        metadata: { reviewRequired: true, evidence: "required-native-check-without-current-root-certificate", freshnessPoint: "enforcement",
          reason, entry: entry.name, entryIdentity: policy.circuit, ledger: ledger.name, ledgerIdentity: policy.ledger,
          candidateQueries: queries.map(query => ({ receiver: query.args[0].region, location: query.location, invocationSites: query.callSites, writesBefore: query.writesBefore })),
          queryOccurrence: queries.length === 1 ? "exact" : "equivalent-candidates",
          guard: guard.location, guardInvocationSites: guard.callSites, overlappingWrites, guardWritesBefore: guard.writesBefore,
          effectTimeFreshness: "not-proven", staleRootAcceptance: "not-proven", pathFeasibility: "not-proven", deployedImpact: "not-proven" },
      }, JSON.stringify([policy, queries.map(query => spanId(query.location)), spanId(guard.location), reason]));
    });
  },
};
