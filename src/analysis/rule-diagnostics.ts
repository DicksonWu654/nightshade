import type { AnalysisFacts } from "../dataflow/index.js";

/** A compilation-unit observation failure invalidates this rule for every entry,
 * not the baseline transfer engine or unrelated rules. With no entries there is
 * no report row to carry a scope, so retain the explicit root diagnostic. */
export function ruleObservationIssue(facts: AnalysisFacts, detectorId: string, code: string, message: string): void {
  if (!facts.program.entries.length) {
    if (!facts.diagnostics.some(issue => issue.code === code && !issue.scope)) facts.diagnostics.push({
      code, message, location: facts.program.rootSource.ast.span,
    });
    return;
  }
  for (const entry of facts.program.entries) {
    if (facts.diagnostics.some(issue => issue.code === code && issue.scope?.detectorId === detectorId && issue.scope.entry === entry)) continue;
    facts.diagnostics.push({ code, message,
      location: facts.program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId, entry },
    });
  }
}
