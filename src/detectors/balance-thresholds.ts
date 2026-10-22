import { balanceThresholds, BALANCE_THRESHOLD_RULE } from "../semantic/balance-thresholds.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, type Detector } from "./types.js";

export const exactBalanceThreshold: Detector = {
  id: BALANCE_THRESHOLD_RULE,
  description: "A threshold-only assertion uses the exact unshielded balance getter instead of its comparison API",
  defaultEnabled: false,
  requires: ["resolved-source", "canonical-stdlib-calls", "local-result-uses"],
  run(facts) {
    const result = balanceThresholds(facts.program);
    if (!result.complete) {
      ruleObservationIssue(facts, BALANCE_THRESHOLD_RULE, "balance-threshold-observation-budget",
        "Exact-balance source observation allowance exhausted; this rule is incomplete");
      return [];
    }
    return result.observations.map(item => finding(facts, {
      detectorId: BALANCE_THRESHOLD_RULE, severity: "info", confidence: "high",
      title: "Threshold guard pins the exact unshielded balance",
      message: `This assertion uses the canonical unshieldedBalance result only for a ${item.comparison} threshold. That getter requires the token balance at transaction application to equal its construction-time balance, even if the threshold still holds. ${item.replacement} records the comparison instead. Exact balance coupling can be intentional; transaction failure and deployed impact are not established.`,
      location: item.location, callPath: [facts.program.symbols.get(item.caller)!.name],
      trace: [{ kind: "call", label: "Canonical exact-balance getter", location: item.getter }],
      remediation: `Review whether exact construction/application balance equality is needed. If only this bound matters, consider ${item.replacement} with the same token color and amount; retain the getter for deliberate exact snapshot coupling.`,
      metadata: { evidence: "canonical-exact-balance-threshold-only-source-use", informational: true, reviewRequired: true,
        scope: "entry-referenced-source", caller: item.caller, entries: item.entries, getter: item.getter,
        comparison: item.comparison, replacement: item.replacement, compilerVersion: facts.program.compilerVersion,
        transactionFailure: "not-proven", deployedImpact: "not-proven", runtimeReachability: "not-proven" },
    }, JSON.stringify([item.caller, item.getter, item.replacement])));
  },
};
