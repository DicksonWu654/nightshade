import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { spanId } from "../model.js";
import { selfCoinSequences } from "../dataflow/self-coin-sequence.js";
import { REDUNDANT_RECEIVE_RULE, SELF_COIN_TARGETS, redundantReceiveScope, redundantReceiveCheckpoints } from "../semantic/redundant-receive-targets.js";
import { finding, unique, type Detector } from "./types.js";
import { autoReceiveProfile } from "../semantic/profile.js";
export const redundantSelfShieldedReceive: Detector = {
  id: REDUNDANT_RECEIVE_RULE, defaultEnabled: true,
  description: "Exact self-addressed canonical returned coin is subsequently passed to receiveShielded",
  requires: ["runtime-operations", "selected-invocation-observations", "canonical-mint-observations", "completed-entries"],
  run(facts) {
    const scope = redundantReceiveScope(facts.program);
    const issue = (message: string) => ruleObservationIssue(facts, REDUNDANT_RECEIVE_RULE, "redundant-receive-evidence-unavailable", `${message}; redundant receive review is incomplete`);
    if (!scope.complete) { issue("Applicability allowance exhausted"); return []; }
    if (!scope.applicable) return [];
    // The rule's claim relies on the library's own receive claim, absent before 0.28.107.
    if (!autoReceiveProfile(facts.program.compilerVersion)) { issue(`Compiler ${facts.program.compilerVersion} library helpers do not claim self-addressed receipts`); return []; }
    const checkpoints = redundantReceiveCheckpoints(facts.program, facts.completedEntries);
    if (!checkpoints.complete || checkpoints.present) { issue("Exact returned snapshots at reachable checkpoint prefixes are unavailable"); return []; }
    if (!facts.mintEvidence || ![...SELF_COIN_TARGETS].every(target => facts.invocationEvidence?.includes(target))) { issue("Exact returned coin invocation snapshots required"); return []; }
    let work = scope.work + checkpoints.work;
    const results = [];
    for (const path of facts.paths) {
      if (!facts.completedEntries.includes(path.entry)) continue;
      const checked = selfCoinSequences(path, Math.min(100000, 1000000 - work), facts.program.meteringIdentity); work += checked.work;
      if (!checked.complete) { issue("Immutable coin equality allowance exhausted"); return []; }
      for (const pair of checked.pairs) results.push(finding(facts, {
        detectorId: REDUNDANT_RECEIVE_RULE, severity: "info", confidence: "high",
        title: "Self-addressed output is explicitly received again",
        message: "An exact coin returned by canonical self-addressed mint/send is later passed to receiveShielded on this modeled history. The pinned library already invokes its receive claim for this recipient. Review this call sequence; ledger rejection, security impact and transaction feasibility are not established.",
        location: pair.received.location, source: pair.produced.location,
        trace: [{ kind: "effect", label: "self-addressed coin returned", location: pair.produced.location }, { kind: "effect", label: "explicit receive", location: pair.received.location }],
        callPath: pair.received.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: "Review removing the redundant explicit receive of this returned self-addressed output.",
        metadata: { entry: facts.program.symbols.get(path.entry)?.name, reviewRequired: true, evidence: "exact-returned-coin-snapshot-sequence", pathFeasibility: "not-proven", producer: pair.produced.name, invocationSites: pair.received.callSites ?? [], checkpointAtomicity: "not-claimed", scope: "mint-return-or-send-sent; right-kernel-self-recipient" },
      }, `${path.entry}:${JSON.stringify((pair.received.callSites ?? []).map(spanId))}`));
    }
    return unique(results);
  },
};
