import type { AbstractValue, AnalysisFacts } from "../dataflow/index.js";
import { successfulIntegerConstraints, fieldArithmeticSafety } from "../dataflow/arithmetic-safety.js";
import { arithmeticTargets } from "../semantic/arithmetic-targets.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export const fieldArithmeticWraparound: Detector = {
  id: "field-arithmetic-wraparound",
  description: "A directly published Field operation on preserved unsigned quantities may wrap without a proved bound",
  // Corpus EcdhMask intentionally mixes a Uint message and a Field mask.
  // Quantity intent is not statically proven; retained intent-dependent review.
  defaultEnabled: false,
  requires: ["resolved-types", "numeric-operands", "successful-predicates", "public-sinks"],
  run(facts) { return detectFieldArithmetic(facts); },
};

export function detectFieldArithmetic(facts: AnalysisFacts, allowance = 200000): Finding[] {
  const scope = arithmeticTargets(facts.program);
  if (scope.complete && !scope.applicable) return [];
  if (!facts.arithmeticEvidence || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
    facts.diagnostics.push({ code: "arithmetic-evidence-unavailable", message: "Unsigned Field arithmetic review needs exact numeric operands and all successful predicates; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1): void => { work += amount; if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance) throw new Exhausted(); };
  const groups = new Map<string, Finding>();
  try {
    for (const path of facts.paths) {
      charge();
      const reconstructed = successfulIntegerConstraints(path.predicates ?? [], charge,path.integerDomains);
      if (reconstructed.status === "budget") throw new Exhausted();
      if (reconstructed.status === "inconsistent") {
        facts.diagnostics.push({ code: "arithmetic-constraints-incomplete", message: "Successful arithmetic predicates could not be reconstructed consistently; results are incomplete", location: facts.program.functions.get(path.entry)!.declaration.span });
        continue;
      }
      const constraints = reconstructed.state;
      for (const sink of path.sinks) {
        const pending = [sink.value], seen = new Set<AbstractValue>();
        while (pending.length) {
          charge();
          const value = pending.pop()!;
          if (seen.has(value)) continue;
          seen.add(value);
          for (const item of value.items ?? []) { charge(); pending.push(item); }
          for (const field of Object.values(value.fields ?? {})) { charge(); pending.push(field); }
          const operation = value.fieldArithmetic;
          if (!operation || !operation.operands.some(operand => operand.uintOrigin && operand.constant === undefined)) continue;
          charge((constraints.orderings?.size ?? 0) + constraints.excluded.size + (constraints.scalarEqualities?.size ?? 0) + 1);
          const risk = fieldArithmeticSafety(value,constraints);
          if (!risk) {
            facts.diagnostics.push({ code: "arithmetic-domain-incomplete", message: "Observed quantity arithmetic has unavailable or contradictory numeric domains; results are incomplete", location: operation.location });
            continue;
          }
          if (risk.status === "safe") continue;
          const key = `${path.entry}:${spanId(operation.location)}`;
          const effect = { kind: sink.kind, name: sink.name, location: sink.location };
          const existing = groups.get(key);
          if (existing) {
            const effects = existing.metadata.effects as typeof effect[];
            if (!effects.some(item => item.kind === effect.kind && item.name === effect.name && spanId(item.location) === spanId(effect.location))) effects.push(effect);
            continue;
          }
          const entry = facts.program.symbols.get(path.entry)!.name;
          groups.set(key,finding(facts, {
            detectorId: fieldArithmeticWraparound.id, severity: "medium", confidence: risk.status === "always-wrap" ? "high" : "medium",
            title: "Unsigned quantity arithmetic can wrap in Field",
            message: `${entry} publishes Field ${operation.operator} arithmetic with an operand preserved from Uint. Field arithmetic reduces modulo the field rather than enforcing unsigned quantity bounds. This successful history does not prove the operation stays within those bounds. ${risk.status === "always-wrap" ? "Every value in the retained operand intervals wraps." : "The retained operand intervals permit wrap; concrete path feasibility is not proved."} Intentional modular arithmetic requires review.`,
            location: operation.location,
            trace: [{ kind: "operation", label: `unchecked Field ${operation.operator}`, location: operation.location }, { kind: "sink", label: sink.name, location: sink.location }],
            callPath: sink.callPath.map(id => facts.program.symbols.get(id)!.name),
            remediation: "Use checked Uint quantity arithmetic before conversion to Field, or enforce bounds on the same immutable operands for every successful transaction. Preserve modular arithmetic only when it is intentional and document that intent.",
            metadata: { entry, operator: operation.operator, evidence: "direct-uint-origin-field-operation", wrap: risk.status, operandBounds: risk.operands.map(range => ({ minimum: String(range.minimum), maximum: String(range.maximum) })), effects: [effect], reviewRequired: true, pathFeasibility: "not-proven", modularIntentInferred: false },
          },path.entry));
        }
      }
    }
    return [...groups.values()];
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    facts.diagnostics.push({ code: "arithmetic-review-budget", message: "Unsigned Field arithmetic review exhausted its bounded constraint/traversal allowance; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
}
