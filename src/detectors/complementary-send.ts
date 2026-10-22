import { complementarySendObservations } from "../dataflow/complementary-send.js";
import { COMPLEMENTARY_SEND_RULE } from "../semantic/complementary-send-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const zeroAmountComplementarySendReview: Detector = {
  id: COMPLEMENTARY_SEND_RULE, defaultEnabled: false,
  description: "Review exact same-color complementary sends with two zero-inclusive amount envelopes",
  requires: ["canonical-send-operands", "complete-original-successful-histories", "immutable-unsigned-subtraction"],
  run(facts) {
    const result = complementarySendObservations(facts); facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(item => {
      const entry = facts.program.symbols.get(item.entry)!.name;
      const first = item.partSend.location.start <= item.remainderSend.location.start ? item.partSend : item.remainderSend;
      const second = first === item.partSend ? item.remainderSend : item.partSend;
      return finding(facts, {
        detectorId: COMPLEMENTARY_SEND_RULE, severity: "info", confidence: "high",
        title: "Complementary send amounts both include zero",
        message: `${entry} sends exact unsigned amounts P and T-P with the same immutable token color on one complete modeled successful invocation history. T has a proven positive modeled lower bound, while both actual sent amount envelopes have lower bound zero after all modeled mandatory checks. Review whether endpoint sends should be conditionally skipped under the application's allocation policy. Neither endpoint's feasibility, send rejection, node or proof behavior, loss, or application impact is established.`,
        location: first.location, source: second.location,
        trace: [{ kind: "call", label: "Complementary part P", location: item.partSend.location },
          { kind: "call", label: "Complementary remainder T-P", location: item.remainderSend.location }],
        callPath: first.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: "Review the zero/full allocation endpoints and conditionally skip exact zero sends when required by application policy. Intentional endpoint payments may be valid.",
        metadata: { reviewRequired: true, entry, pair: "P,T-P", tokenColor: "exact-immutable-same-operand",
          partLocation: item.partSend.location, remainderLocation: item.remainderSend.location,
          partCallSites: item.partSend.callSites, remainderCallSites: item.remainderSend.callSites,
          totalMinimum: String(item.total.minimum), totalMaximum: String(item.total.maximum),
          partMinimum: String(item.part.minimum), partMaximum: String(item.part.maximum),
          remainderMinimum: String(item.remainder.minimum), remainderMaximum: String(item.remainder.maximum),
          compilerVersion: facts.program.compilerVersion, zkirVersion: facts.program.zkirVersion,
          evidence: "complete-original-history-with-exact-complementary-amounts-and-zero-inclusive-envelopes",
          endpointFeasibility: "not-proven", sendRejection: "not-inferred", applicationImpact: "not-inferred",
          pathFeasibility: "not-proven", fullRecordRecallCredit: false },
      }, item.pairKey);
    }));
  },
};
