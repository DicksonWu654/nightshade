import { burnAmountWidths, BURN_AMOUNT_WIDTH_RULE } from "../semantic/burn-amount-width.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, unique, type Detector } from "./types.js";

export const shieldedBurnAmountWidth: Detector = {
  id: BURN_AMOUNT_WIDTH_RULE, defaultEnabled: false,
  description: "An exported Uint<64> amount is forwarded unchanged to a canonical shielded burn with Uint<128> coin and API amounts",
  requires: ["resolved-source", "canonical-stdlib-calls", "resolved-types"],
  run(facts) {
    const result = burnAmountWidths(facts.program);
    if (!result.complete) {
      ruleObservationIssue(facts, BURN_AMOUNT_WIDTH_RULE, "burn-amount-width-observation-budget", "Shielded burn amount source observation allowance exhausted; this rule is incomplete");
      return [];
    }
    return unique(result.observations.map(item => finding(facts, {
      detectorId: BURN_AMOUNT_WIDTH_RULE, severity: "info", confidence: "high",
      title: "Shielded burn entry amount is narrower than the coin value",
      message: "An exported Uint<64> parameter is forwarded unchanged to canonical shielded send with canonical shieldedBurnAddress. The input coin.value and send API amount are Uint<128>. This entry amount cannot express the full Uint<128> range. Intentional small burns can match. This width fact does not prove available balances, transaction feasibility, successful reach, inability to split burns or deployed impact.",
      location: item.location, source: item.parameter.span,
      callPath: [facts.program.symbols.get(item.entry)!.name],
      trace: [{ kind: "source", label: "Exported Uint<64> amount parameter", location: item.parameter.span }, { kind: "call", label: "Canonical shielded send to canonical burn address", location: item.location }],
      remediation: "Review the intended burn limit. Use Uint<128> at the entry boundary if it should accept the full coin-value range; document an intentional Uint<64> limit.",
      metadata: { evidence: "exact-exported-parameter-canonical-burn-width", reviewRequired: true,
        entry: item.entry, parameter: item.parameter.name, primitive: item.primitive, parameterType: "Uint<64>", coinValueType: "Uint<128>", apiAmountType: "Uint<128>",
        scope: "syntactic-entry-amount-route", compilerVersion: facts.program.compilerVersion, successfulReach: "not-proven", balanceAvailability: "not-proven", transactionFeasibility: "not-proven", deployedImpact: "not-proven" },
    }, item.entry)));
  },
};
