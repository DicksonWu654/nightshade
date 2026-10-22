import { memoNoncePairs } from "../dataflow/memo-nonce.js";
import { MEMO_NONCE_APPEND, MEMO_NONCE_RULE } from "../semantic/memo-nonce-targets.js";
import { hasShieldedMint } from "../semantic/mint-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const resettableMemoNonce: Detector = {
  id: MEMO_NONCE_RULE, defaultEnabled: false,
  description: "Stored recipient List payload and canonical coin nonce both evolve from the same resettable selected List extent",
  requires: ["canonical-mint-observations", "memo-append-observations", "completed-entries", "cross-entry-state-writes"],
  run(facts) { return memoNonceFindings(facts); },
};

export function memoNonceFindings(facts: Parameters<Detector["run"]>[0], entries = facts.program.entries) {
  // Ordinary direct registry dispatch has not selected this observer. Preserve
  // its facts and diagnostics; selected scans request the marker explicitly.
  if (!facts.invocationEvidence?.includes(MEMO_NONCE_APPEND)) return [];
  if (!entries.some(entry => hasShieldedMint(facts.program, entry))) return [];
  const issue = (message: string) => {
    for (const entry of entries) facts.diagnostics.push({
      code: "memo-nonce-evidence-unavailable", message: `${message}; memo nonce source review is incomplete`,
      location: facts.program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId: MEMO_NONCE_RULE, entry },
    });
  };
  if (facts.program.entries.length > 64) { issue("Cross-entry proof exceeds its 64-entry allowance"); return []; }
  if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.mintEvidence || !facts.digestEvidence
    || facts.program.entries.some(entry => !facts.completedEntries.includes(entry))) {
    issue("Complete cross-entry histories and exact coin, recipient and memo append inputs required"); return [];
  }
  const checked = memoNoncePairs(facts, entries);
  if (!checked.complete) { issue("Cross-entry source relationship allowance exhausted"); return []; }
  return unique(checked.pairs.map(pair => {
    const ledger = facts.program.symbols.get(pair.root)!.name, resetEntry = facts.program.symbols.get(pair.resetEntry)!.name;
    return finding(facts, {
      detectorId: MEMO_NONCE_RULE, severity: "info", confidence: "high", title: "Coin nonce and stored evolved payload use a resettable recipient List extent",
      message: `The canonical coin nonce and the direct payload appended to the List in ${ledger} each use canonical evolveNonce with a constant seed and the same selected-list length revision. The selected key equals the active account recipient bytes on this modeled successful history. Exported entry ${resetEntry} ${pair.exactResetRegion ? "resets that same list" : "resets a list whose selector may overlap this selection"}. This paired source review identifies an extent that is not monotonic across potential resets. The stored payload's protocol role, actual recurrence, cross-transaction feasibility, memo encryption, confidentiality impact and authorization intent are not established.`,
      location: pair.append.location, source: pair.reset.location,
      trace: [{ kind: "source", label: `reset of ${ledger} in ${resetEntry}`, location: pair.reset.location },
        { kind: "sink", label: "length-derived canonical coin nonce", location: pair.mint.location },
        { kind: "sink", label: "direct length-derived stored evolved payload", location: pair.append.location }],
      callPath: pair.append.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "Review both uses of the resettable extent. If the stored payload must also remain unique, use a separately maintained monotonic source or appropriate fresh inputs independently of List pruning.",
      metadata: { entry: facts.program.symbols.get(pair.entry)!.name, ledger, resetEntry,
        evidence: "paired-canonical-evolution-exact-recipient-list-revision-direct-memo-append-and-cross-entry-reset-overlap",
        selectedPath: pair.selectedPath, resetPath: pair.reset.region, selectorRelation: pair.exactResetRegion ? "exact-region" : "may-overlap",
        consumerRelation: "same-exact-selected-list-revision", recipientRelation: "active-account-bytes-equal-selected-key",
        payloadRole: "not-inferred", reviewRequired: true, transactionFeasibility: "not-proven", cryptographicImpact: "not-proven", authorizationIntent: "not-analyzed" },
    }, pair.entry);
  }));
}
