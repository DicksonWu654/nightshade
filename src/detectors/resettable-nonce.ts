import { resettableNoncePairs } from "../dataflow/resettable-nonce.js";
import { finding, unique, type Detector } from "./types.js";
import { hasShieldedMint } from "../semantic/mint-targets.js";
export const resettableListNonce: Detector = {
  id: "resettable-list-nonce", defaultEnabled: false,
  description: "Canonical shielded coin nonce derives solely from a selected ledger List length that another exported entry can reset",
  requires: ["canonical-mint-observations", "completed-entries", "cross-entry-state-writes"],
  run(facts) { return resettableListNonceFindings(facts); },
};
export function resettableListNonceFindings(facts: Parameters<Detector["run"]>[0], entries = facts.completedEntries) {
  if (!facts.program.entries.some(entry => hasShieldedMint(facts.program, entry))) return [];
  const issue = (message: string) => {
    for (const entry of entries) facts.diagnostics.push({ code: "resettable-nonce-evidence-unavailable", message: `${message}; resettable nonce review is incomplete`,
      location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule" as const, detectorId: resettableListNonce.id, entry } });
  };
  if (facts.program.entries.length > 64) { issue("Cross-entry proof exceeds its 64-entry allowance"); return []; }
  if (facts.pathSemantics !== "equivalent-states" || !facts.mintEvidence || !facts.digestEvidence || facts.program.entries.some(entry => !facts.completedEntries.includes(entry))) {
    issue("Complete cross-entry histories and exact canonical nonce inputs required"); return [];
  }
  const checked = resettableNoncePairs(facts, entries);
  if (!checked.complete) { issue("Cross-entry source relationship allowance exhausted"); return []; }
  return unique(checked.pairs.map(pair => {
    const ledger = facts.program.symbols.get(pair.root)!.name;
    const resetEntry = facts.program.symbols.get(pair.resetEntry)!.name;
    return finding(facts, {
      detectorId: resettableListNonce.id, severity: "low", confidence: "high", title: "Coin nonce uses a resettable List extent",
      message: `This canonical shielded coin nonce derives solely from the current selected-list length in ${ledger}. Exported entry ${resetEntry} ${pair.exactRegion ? "resets that same list" : "resets a list whose storage selector may overlap this selection"} on a modeled successful history. Its extent is therefore not a monotonic uniqueness source across entries. Static nonce reuse is possible if this selected extent recurs; dynamic selector equality, actual recurrence, successful transactions, cryptographic impact and authorization intent are not established.`,
      location: pair.operation.location, source: pair.reset.location,
      trace: [{ kind: "source", label: `reset of ${ledger} in ${resetEntry}`, location: pair.reset.location }, { kind: "sink", label: "length-derived canonical coin nonce", location: pair.operation.location }],
      callPath: pair.operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "Use a separately maintained monotonic nonce source or an appropriate fresh nonce rather than a resettable collection extent.",
      metadata: { entry: facts.program.symbols.get(pair.entry)!.name, ledger, resetEntry, evidence: "exact-list-length-canonical-nonce-and-cross-entry-reset-overlap", selectedPath: pair.selectedPath, resetPath: pair.reset.region, selectorRelation: pair.exactRegion ? "exact-region" : "may-overlap", reviewRequired: true, transactionFeasibility: "not-proven", authorizationIntent: "not-analyzed" },
    }, pair.entry);
  }));
}
