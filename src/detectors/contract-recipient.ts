import { contractRecipientObservations } from "../dataflow/contract-recipient.js";
import { CONTRACT_RECIPIENT_RULE } from "../semantic/contract-recipient.js";
import { finding, unique, type Detector } from "./types.js";
import type { AnalysisFacts } from "../dataflow/index.js";

export const shieldedContractRecipientReview: Detector = {
  id: CONTRACT_RECIPIENT_RULE, defaultEnabled: false,
  description: "Review canonical shielded sends with a modeled non-self ContractAddress recipient arm",
  requires: ["exact-canonical-send-operand", "complete-successful-histories", "non-self-contract-arm"],
  run(facts) {
    return contractRecipientReviewPass(facts).findings;
  },
};

/** Deferral is used only by the observer, which withholds all findings until
 * every named tag pass completes. Standalone Detector.run refuses pending tags. */
export function contractRecipientReviewPass(facts: AnalysisFacts, deferSuppliedTags = false) {
  const result = contractRecipientObservations(facts, deferSuppliedTags); facts.diagnostics.push(...result.diagnostics);
  const findings = unique(result.observations.map(item => finding(facts, {
    detectorId: CONTRACT_RECIPIENT_RULE, severity: "info", confidence: "high",
    title: "Shielded send admits a non-self contract recipient",
    message: "A complete modeled successful history reaches this canonical shielded send with its exact recipient selecting the ContractAddress arm and an enforced non-self address relation. Review how the transaction supplies the recipient contract's matching receive/claim composition. External same-transaction composition is unmodeled; this finding does not establish a missing claim, transaction rejection, concrete path feasibility or security impact.",
    location: item.operation.location,
    trace: [{ kind: "call", label: "canonical shielded send with exact non-self contract recipient", location: item.operation.location }],
    callPath: item.operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
    remediation: "Review the same-transaction recipient receive/claim composition. If contract recipients are unsupported by the intended application, enforce the account arm on every successful send history.",
    metadata: { reviewRequired: true, evidence: "complete-modeled-canonical-send-non-self-contract-arm", activeArm: "right", canonicalTarget: item.operation.name,
      compilerVersion: facts.program.compilerVersion, zkirVersion: facts.program.zkirVersion,
      specializedParameter: item.specializedParameter ?? null, recipientOperandIndex: 1, nonSelf: "enforced-exact-immutable-bytes-relation",
      claimPresence: "not-inferred", externalComposition: "unmodeled", transactionRejection: "not-inferred", applicationImpact: "not-inferred", pathFeasibility: "not-proven",
      naturalStaticPrecisionGate: "pending", lowVolumeActionabilityGate: "pending", fullRecordRecallCredit: false },
  }, item.entry)));
  return { findings, pendingParameters: result.pendingParameters };
}
