import type { AnalysisFacts } from "../dataflow/index.js";
import { retainedListGrowth } from "../dataflow/list-growth.js";
import { LIST_GROWTH_RULE } from "../semantic/list-growth.js";
import { finding, type Detector, type Finding } from "./types.js";

export function retainedListGrowthFindings(facts: AnalysisFacts): Finding[] {
  const results: Finding[] = [];
  try {
    retainedListGrowth(facts, (item, key) => results.push(finding(facts, {
      detectorId: LIST_GROWTH_RULE, severity: "info", confidence: "high",
      title: "Zero-inclusive transfer accompanies retained recipient List growth",
      message: "A canonical unshielded send retains zero in its actual amount envelope and appends a retained record to the List selected by that exact user recipient on the same complete modeled history. Review whether this coupling is intended. This does not establish feasible zero transactions, unbounded growth, transaction contention or application impact.",
      location: item.append.location,
      callPath: item.append.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      trace: [{ kind: "call", label: "Canonical send with a zero-inclusive actual amount", location: item.send.location },
        { kind: "state-write", label: "Retained append selected by the exact user recipient", location: item.append.location }],
      remediation: "If zero transfers should not create recipient records, require a positive actual sent amount or skip the corresponding append for zero.",
      metadata: { evidence: "exact-recipient-zero-envelope-retained-list-append", reviewRequired: true,
        entry: facts.program.symbols.get(item.entry)?.name, ledger: facts.program.symbols.get(item.root)?.name,
        selectedAddress: item.address, revision: item.revision, minimum: String(item.minimum), maximum: String(item.maximum),
        sameRevisionLengthBeforeAppend: !!item.lengthBeforeAppend,
        ...(item.lengthBeforeAppend ? { lengthLocation: item.lengthBeforeAppend.location } : {}),
        pathFeasibility: "not-proven", contention: "not-inferred", unboundedGrowth: "not-inferred", applicationImpact: "not-inferred", fullRecordRecallCredit: false },
    }, key)));
    return results;
  } catch (error) {
    // Selected analysis reserves a fixed failure envelope before execution.
    // Refusal reports only that entry; unrelated exports cannot amplify work or
    // allocations after its allowance is exhausted. Unselected direct calls
    // receive one explicit root diagnostic without inventorying entries.
    const entry = facts.listGrowthEvidence?.entry;
    facts.diagnostics.push({ code: "list-growth-evidence-incomplete",
      message: error instanceof Error ? error.message : String(error),
      location: entry ? facts.program.functions.get(entry)!.declaration.span : facts.program.rootSource.ast.span,
      ...(entry ? { scope: { kind: "rule" as const, detectorId: LIST_GROWTH_RULE, entry } } : {}),
    });
    return [];
  }
}

export const zeroTransferRetainedListReview: Detector = {
  id: LIST_GROWTH_RULE, defaultEnabled: false,
  description: "Review zero-inclusive actual transfers paired with retained List append for the exact user recipient",
  requires: ["canonical-invocation-snapshots", "all-predicates", "exact-collection-selectors", "completed-entries"],
  run: retainedListGrowthFindings,
};
