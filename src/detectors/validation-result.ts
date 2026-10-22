import { cachedSourceObservations } from "../analysis/source-observations.js";
import { finding, type Detector } from "./types.js";
import { hasSchnorrVerifier } from "../semantic/signature-targets.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";

/** A precise discarded-result lint; it makes no claim about arbitrary Boolean uses. */
export const ignoredValidationResult: Detector = {
  id: "ignored-validation-result",
  description: "A canonical signature verifier's Boolean outcome is discarded or retained only by unused local aliases",
  defaultEnabled: true,
  requires: ["resolved-calls", "resolved-source-references"],
  run(facts) {
    // A resolved canonical verifier must be materialized before any direct or
    // transparent-helper discard can exist. Namesakes and uninstantiated source
    // templates cannot supply that evidence. Avoid a second full lint traversal
    // when its only security observation is structurally absent.
    if (!hasSchnorrVerifier(facts.program)) return [];
    const source = cachedSourceObservations(facts.program, true);
    if (!source.complete) {
      ruleObservationIssue(facts, ignoredValidationResult.id, "source-observation-budget", "Source-observation work/depth allowance exhausted; discarded validation-result analysis is incomplete");
      return [];
    }
    return source.observations.filter(item => item.kind === ignoredValidationResult.id).map(item => finding(facts, {
      detectorId: ignoredValidationResult.id, severity: "medium", confidence: "high",
      title: "Signature verification outcome is discarded", message: item.message,
      location: item.location, trace: [{ kind: "call", label: "Discarded jubjubSchnorrVerify outcome", location: item.location }], callPath: [],
      remediation: "Assert the verification result, or reject the false branch before the transaction can succeed. Preserve intentional Boolean checker APIs; suppress intentional verifier-only tests with a reason.",
      metadata: { ...item.metadata, reviewRequired: true, scope: "root-source-reachable-circuits", pathFeasibility: "not-proven" },
    }));
  },
};
