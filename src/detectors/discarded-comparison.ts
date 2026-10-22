import { cachedSourceObservations } from "../analysis/source-observations.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, type Detector } from "./types.js";

/** Source outcome-use fact; never an absence-of-guards or execution proof. */
export const discardedComparison: Detector = {
  id: "discarded-comparison",
  description: "A comparison not reduced to a source constant is discarded or kept only by unused immutable aliases",
  defaultEnabled: true,
  requires: ["resolved-source-references", "typed-source-constants"],
  run(facts) {
    const source = cachedSourceObservations(facts.program, "comparisons");
    if (!source.complete) {
      ruleObservationIssue(facts, discardedComparison.id, "source-observation-budget",
        "Source-observation work/depth allowance exhausted; discarded-comparison analysis is incomplete");
      return [];
    }
    return source.observations.filter(item => item.kind === discardedComparison.id).map(item => finding(facts, {
      detectorId: discardedComparison.id, severity: "low", confidence: "high",
      title: "Comparison outcome is discarded", message: item.message, location: item.location,
      trace: [], callPath: [],
      remediation: "Assert the comparison or consume its result in the intended control flow. Preserve intentional checker returns and operand effects; suppress intentional comparison-only tests with a reason.",
      metadata: { ...item.metadata, reviewRequired: true, scope: "root-source-reachable-circuits", pathFeasibility: "not-proven", otherGuards: "not-analyzed" },
    }));
  },
};
