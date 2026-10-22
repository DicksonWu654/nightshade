import { acknowledgedListReset } from "../dataflow/list-reset.js";
import { hasListWrites } from "../semantic/list-reset-targets.js";
import { parseType } from "../semantic/types.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export const destructiveListReset: Detector = {
  id: "destructive-list-reset", defaultEnabled: false,
  description: "Whole-list reset lacks a recognized same-revision count, empty-list or absent-slot acknowledgment",
  requires: ["successful-histories", "successful-predicates", "state-writes", "completed-entries"],
  run(facts) {
    const findings: Finding[] = [];
    let work = 0;
    for (const entry of facts.completedEntries) {
      if (!hasListWrites(facts.program, entry)) continue;
      const groups = new Map<string, { write: typeof facts.paths[number]["writes"][number]; histories: unknown[] }>();
      let unavailable = false;
      for (const path of facts.paths.filter(path => path.entry === entry)) for (const write of path.writes) {
        if (++work > 1000000) { unavailable = true; break; }
        if (!write.after.emptyList || parseType(facts.program.representationOf(write.before.region?.type ?? write.before.type ?? "unknown")).name !== "List") continue;
        if (facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states") { unavailable = true; break; }
        const checked = acknowledgedListReset(write, path, 1000000 - work);
        work += checked.work;
        if (!checked.complete) { unavailable = true; break; }
        if (checked.acknowledged) continue;
        const key = spanId(write.location);
        const group = groups.get(key) ?? { write, histories: [] };
        group.histories.push({ region: write.region, revision: write.before.region!.revision,
          invocationSites: write.callSites ?? [], branches: path.path });
        groups.set(key, group);
      }
      if (unavailable) {
        facts.diagnostics.push({ code: "list-reset-evidence-unavailable", message: "List-reset review lacks exact selector/revision/full-predicate evidence or exhausted its allowance; this entry is incomplete",
          location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: destructiveListReset.id, entry } });
        continue;
      }
      for (const { write, histories } of groups.values()) {
        const name = facts.program.symbols.get(entry)!.name, ledger = facts.program.symbols.get(write.ledger)!.name;
        findings.push(finding(facts, {
          detectorId: destructiveListReset.id, severity: "low", confidence: "medium", title: "Whole-list reset needs acknowledgment review",
          message: `${name} replaces a selected List in ${ledger} with an empty list on a modeled successful history without a recognized required check of that same list's current length or emptiness, or absence of that exact Map slot. If callers clear only items they previously observed, review an expected count or an authenticated append epoch. Intentional purges and custom epoch/digest protocols can match this review.`,
          location: write.location, trace: [{ kind: "sink", label: `whole-list reset in ${ledger}`, location: write.location }],
          callPath: write.callPath.map(id => facts.program.symbols.get(id)!.name),
          remediation: "For acknowledgment-based pruning, validate the caller's expected list extent or a correctly maintained per-list epoch, or consume only the acknowledged segment. Review and document intentional purges.",
          metadata: { reviewRequired: true, entry: name, ledger, evidence: "reset-without-recognized-list-acknowledgment", affectedHistories: histories,
            recognizedChecks: ["same-revision-list-length-equality-to-independent-value", "same-revision-list-empty", "same-revision-map-slot-absent"],
            customEpochOrDigest: "not-analyzed", doesNotProve: "unread-credit-loss-transaction-ordering-or-lockout" },
        }, entry));
      }
    }
    return findings;
  },
};
