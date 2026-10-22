import { cachedSourceObservations } from "../analysis/source-observations.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, type Detector } from "./types.js";

export const discardedShieldedSendResult: Detector = {
  id: "discarded-shielded-send-result",
  description: "Canonical shielded send or mint metadata is discarded or retained only by unused immutable aliases",
  defaultEnabled: true,
  requires: ["resolved-source-references", "typed-source-constants"],
  run(facts) {
    const source = cachedSourceObservations(facts.program, "shielded-send-results");
    if (!source.complete) {
      ruleObservationIssue(facts, discardedShieldedSendResult.id, "source-observation-budget",
        "Source-observation allowance exhausted; shielded send result review is incomplete");
      return [];
    }
    return source.observations.filter(item => item.kind === discardedShieldedSendResult.id && item.metadata.entry !== "constructor").map(item => finding(facts, {
      detectorId: discardedShieldedSendResult.id, severity: "info", confidence: "high",
      title: item.metadata.operation === "mintShieldedToken" ? "Shielded mint metadata is discarded" : "Shielded send metadata is discarded", message: item.message, location: item.location,
      source: item.location, trace: [{ kind: "observation", label: String(item.metadata.operation ?? "canonical shielded operation"), location: item.location }], callPath: [],
      remediation: "Consume the returned metadata when the application needs it, or document intentional discard and independently retained wallet or transaction metadata.",
      metadata: { ...item.metadata, reviewRequired: true, scope: "root-source-reachable-circuits", pathFeasibility: "not-proven", metadataRetentionOutsideSource: "not-analyzed" },
    }));
  },
};
