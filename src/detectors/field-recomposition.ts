import { ReportIdentityKeys } from "../reporting/identity-keys.js";
import type { AnalysisFacts } from "../dataflow/index.js";
import { successfulIntegerConstraints } from "../dataflow/arithmetic-safety.js";
import { fieldRecomposition } from "../dataflow/field-recomposition.js";
import { FIELD_MODULUS } from "../semantic/types.js";
import { FIELD_RECOMPOSITION_RULE, recompositionTargets } from "../semantic/field-recomposition.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export function fieldRecompositionFindings(facts: AnalysisFacts, allowance = 20000, entries: readonly string[] = facts.program.entries): Finding[] {
  const scope = recompositionTargets(facts.program, allowance, entries);
  if (scope.complete && !scope.applicable) return [];
  const issue = (message: string) => ruleObservationIssue(facts, FIELD_RECOMPOSITION_RULE, "field-recomposition-incomplete", message);
  if (!scope.complete || entries.some(entry => !facts.completedEntries.includes(entry)) || !facts.mintQuantityEvidence || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
    issue("Field recomposition review requires bounded source observation and exact owned numeric expressions with all successful predicates"); return [];
  }
  let work = 0;
  const charge = (amount = 1) => { work += amount; if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance) throw new Error("Field recomposition review allowance exhausted"); };
  const findings = new Map<string, Finding>();
  const report = new ReportIdentityKeys(facts.program, FIELD_RECOMPOSITION_RULE, facts.program.rootSource.ast.span);
  try {
    for (const path of facts.paths) {
      if (!entries.includes(path.entry)) continue;
      if (!path.predicates || !facts.completedEntries.includes(path.entry)) throw new Error("Successful history evidence unavailable");
      // Histories without an equality/inequality predicate cannot contain a
      // recomposition finding. Skip them before charging the expensive
      // constraint reconstruction; this is a semantic filter, not a larger
      // allowance, and keeps repeated protocol paths within the fixed budget.
      if (!path.predicates.some(predicate => {
        let value = predicate.value;
        while (value.negated) value = value.negated;
        return !!value.comparison;
      })) continue;
      charge();
      const reconstructed = successfulIntegerConstraints(path.predicates, charge, path.integerDomains);
      if (reconstructed.status !== "complete") throw new Error(`Successful integer constraints ${reconstructed.status}`);
      for (const predicate of path.predicates) {
        charge();
        let value = predicate.value, truth = predicate.truth;
        while (value.negated) { charge(); value = value.negated; truth = !truth; }
        const comparison = value.comparison;
        if (!comparison || !(comparison.operator === "==" && truth || comparison.operator === "!=" && !truth)) continue;
        for (const [side, value] of [comparison.left, comparison.right].entries()) {
          const observed = fieldRecomposition(value, reconstructed.state, charge);
          if (!observed || observed.maximum < FIELD_MODULUS) continue;
          const range = (v: { minimum: bigint; maximum: bigint }) => ({ minimum: String(v.minimum), maximum: String(v.maximum) });
          const key = `${path.entry}:${spanId(predicate.location)}:${side}`;
          const history = { scale: String(observed.scale), quotientIdentity: observed.quotient.identity && report.key(observed.quotient.identity), remainderIdentity: observed.remainder.identity && report.key(observed.remainder.identity), callPath: predicate.callPath, callSites: predicate.callSites, branches: path.path, quotientBounds: range(observed.q), remainderBounds: range(observed.r), recompositionBounds: range(observed) };
          const existing = findings.get(key);
          if (existing) { (existing.metadata.histories as typeof history[]).push(history); continue; }
          findings.set(key, finding(facts, {
            detectorId: FIELD_RECOMPOSITION_RULE, severity: "info", confidence: "high",
            title: "Enforced Field recomposition has an envelope beyond the modulus",
            message: "An enforced Field equality retains a power-of-two multiply-plus-add relation on independently supplied scalar operands. The successful history's quotient/remainder envelopes have a mathematical upper endpoint at or above the Field modulus. This envelope fact does not establish jointly feasible operands, ambiguity, or an invalid execution. Modular arithmetic may be intentional.",
            location: predicate.location, callPath: predicate.callPath.map(id => facts.program.symbols.get(id)!.name),
            trace: [{ kind: "operation", label: "Enforced Field recomposition", location: predicate.location }],
            remediation: "Review whether integer recomposition is intended and enforce sufficiently tight bounds on these exact operands, or document intentional modular arithmetic.",
            metadata: { evidence: "owned-field-recomposition-envelope", entry: path.entry, scale: String(observed.scale), quotientIdentity: observed.quotient.identity && report.key(observed.quotient.identity), remainderIdentity: observed.remainder.identity && report.key(observed.remainder.identity), quotientBounds: range(observed.q), remainderBounds: range(observed.r), recompositionBounds: range(observed), fieldModulus: String(FIELD_MODULUS), branches: path.path, histories: [history], reviewRequired: true, pathFeasibility: "not-proven", ambiguity: "not-proven" },
          }, key));
        }
      }
    }
    return [...findings.values()];
  } catch (error) { issue(error instanceof Error ? error.message : "Field recomposition observation unavailable"); return []; }
}
export const fieldRecompositionReview: Detector = {
  id: FIELD_RECOMPOSITION_RULE, defaultEnabled: true,
  description: "Enforced Field recomposition retains quotient/remainder envelopes beyond the modulus",
  requires: ["owned-numeric-expressions", "successful-predicates", "resolved-types"],
  run: facts => fieldRecompositionFindings(facts),
};
