import { sourceClaimObservations } from "../dataflow/source-claims.js";
import { SOURCE_CLAIM_RULE } from "../semantic/source-claims.js";
import { finding, unique, type Detector } from "./types.js";

export const sourceClaimShieldedIssuanceReview: Detector = {
  id: SOURCE_CLAIM_RULE, defaultEnabled: false, policyRequired: true,
  description: "Review an explicit adjacent source claim paired with shielded issuance to a user key",
  requires: ["explicit-source-claim-policy", "parser-owned-exact-adjacent-comment", "canonical-mint-invocation", "complete-original-successful-histories"],
  run(facts, policies) {
    if (!facts.sourceClaimEvidence && !policies?.sourceClaims?.length) return [];
    const result = sourceClaimObservations(facts); facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(({ claim, operation }) => finding(facts, {
      detectorId: SOURCE_CLAIM_RULE, severity: "info", confidence: "high",
      title: "Review source claim and user-key shielded issuance",
      message: "The configured non-transferable shielded issuance claim exactly matches the complete comment immediately preceding this exported circuit. A complete modeled successful history invokes canonical mintShieldedToken with an active native user-key recipient. Review this source/API pairing against the application's intended issuance policy. Transferability, spendability, runtime behavior and application impact are not established.",
      location: operation.location, source: claim.source,
      trace: [{ kind: "call", label: "Canonical shielded mint to active user-key recipient", location: operation.location }],
      callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "Review the explicit claim and selected recipient API against the intended issuance policy.",
      metadata: { reviewRequired: true, claimKind: claim.kind, quote: claim.quote, entry: claim.circuit,
        activeArm: "left", recipientType: "Either<ZswapCoinPublicKey, ContractAddress>", claimMeaning: "explicit-policy",
        evidence: "exact-adjacent-comment-and-complete-successful-canonical-user-key-mint-history",
        transferability: "not-established", spendability: "not-established", runtimeBehavior: "not-established", applicationImpact: "not-inferred",
        compilerVersion: facts.program.compilerVersion, zkirVersion: facts.program.zkirVersion, fullRecordRecallCredit: false },
    }, claim.circuit + ":" + claim.kind)));
  },
};
