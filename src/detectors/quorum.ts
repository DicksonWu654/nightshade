import type { Detector, Finding } from "./types.js";
import { finding, unique } from "./types.js";
import { quorumObservations } from "../dataflow/quorum.js";
import { QUORUM_RULE, quorumTargets } from "../semantic/quorum-targets.js";
import { ECDSA_VERIFIER } from "../semantic/signed-input-targets.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { spanId } from "../model.js";
export const quorumSignerUniquenessReview: Detector = {
  id: QUORUM_RULE, defaultEnabled: false,
  description: "Adjacent signer inequalities omit non-adjacent pairs in a verified threshold claim vector",
  requires: ["all-successful-predicates", "exact-entry-operands", "canonical-ecdsa-operands", "collection-operations", "direct-hash-inputs"],
  run(facts) {
    if (!facts.program.functions.has(ECDSA_VERIFIER)) return [];
    const incomplete = (message: string): Finding[] => {
      ruleObservationIssue(facts, QUORUM_RULE, "quorum-uniqueness-evidence-unavailable", message); return [];
    };
    if (!facts.digestEvidence || !facts.collectionEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states"
      || [...quorumTargets(facts.program)].some(target => !facts.invocationEvidence?.includes(target)))
      return incomplete("Quorum uniqueness review requires exact entry/verifier operands, digest inputs, collection operations and all uncompressed successful predicates");
    let allowance = 1_000_000;
    const findings: Finding[] = [], completed = new Set(facts.completedEntries);
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      const result = quorumObservations(path, allowance); allowance -= result.work;
      if (!result.complete) return incomplete("Quorum uniqueness review exhausted its allowance or required predicate/claim snapshots are unavailable");
      for (const observation of result.observations) {
        const entry = facts.program.symbols.get(path.entry)!.name;
        findings.push(finding(facts, {
          detectorId: QUORUM_RULE, severity: "info", confidence: "high",
          title: "Adjacent signer checks omit non-adjacent uniqueness pairs",
          message: `${entry} presents ${observation.sequence.items!.length} claims with required registry membership, key commitment binding and canonical ECDSA verification in this modeled successful history. Its fixed accepted count is checked against a supplied threshold. Required scalar inequalities cover adjacent commitments but omit ${observation.missingPairs.map(([a,b]) => `[${a}], [${b}]`).join("; ")}. Adjacent inequality alone does not establish pairwise uniqueness. Other protocol checks may establish uniqueness; duplicate feasibility, sole authorization and exploitability are unproven.`,
          location: observation.threshold.location, constraint: observation.threshold.location,
          trace: [...observation.signatures.map(signature => ({ kind: "call", label: "Required canonical ECDSA claim verification", location: signature.location })), { kind: "constraint", label: "Presented claim count checked against supplied threshold", location: observation.threshold.location }],
          callPath: observation.threshold.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "Review whether the threshold counts distinct registered signers. If required, enforce uniqueness across every pair or use a complete protocol-specific uniqueness constraint; document independently established uniqueness.",
          metadata: { reviewRequired: true, entry, evidence: "verified-threshold-claims-with-adjacent-only-scalar-inequalities", claimCount: observation.sequence.items!.length,
            missingPairs: observation.missingPairs, registrySnapshot: observation.registry, soleAuthorization: false, pathFeasibility: "not-proven", confidenceScope: "static-required-snapshot-relationship" },
        }, `${path.entry}:${spanId(observation.threshold.location)}:${observation.signatures.map(signature => spanId(signature.location)).join(":")}`));
      }
    }
    return unique(findings);
  },
};
