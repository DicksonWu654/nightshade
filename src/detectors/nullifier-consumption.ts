import { unconsumedAbsences } from "../dataflow/collection-consumption.js";
import { collectionTargets } from "../semantic/collection-targets.js";
import { VALUE_TRANSFER_CIRCUITS } from "../semantic/value-transfers.js";
import { spanId } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

export const nullifierCheckWithoutInsert: Detector = {
  id: "nullifier-check-without-insert",
  defaultEnabled: false,
  description: "Required collection absence lacks a definite surviving insertion on a state-changing history",
  requires: ["collection-observations", "successful-predicates", "state-writes", "completed-entries"],
  run(facts) {
    const issue = (code: string, message: string) => facts.diagnostics.push({ code, message: `${message}; collection consumption review is incomplete`, location: facts.program.rootSource.ast.span });
    const scope = collectionTargets(facts.program);
    if (!scope.complete) { issue("predicate-analysis-budget", "Collection applicability exceeded its allowance"); return []; }
    if (!scope.applicable) return [];
    if (!facts.collectionEvidence || facts.predicateScope !== "all") { issue("predicate-evidence-unavailable", "Collection review requires query/effect observations and full predicates"); return []; }
    const completed = new Set(facts.completedEntries), findings: Finding[] = [];
    let work = scope.work;
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || facts.program.symbols.get(path.entry)!.kind === "constructor") continue;
      if (!path.writes.length && !(path.operations ?? []).some(operation => ["kernel-write", "native-witness"].includes(operation.kind)
        && operation.callPath.some(id => VALUE_TRANSFER_CIRCUITS.has(id)))) continue;
      const result = unconsumedAbsences(path, 1000000 - work);
      work += result.work;
      if (!result.complete) { issue("predicate-analysis-budget", "Collection matching exhausted its allowance or exact key/address evidence is unavailable"); return []; }
      for (const query of result.queries) {
        const entry = facts.program.symbols.get(path.entry)!.name;
        const collection = facts.program.symbols.get(query.args[0].region!.root)!.name;
        findings.push(finding(facts, {
          detectorId: nullifierCheckWithoutInsert.id, severity: "medium", confidence: "low",
          title: "Required absence lacks a surviving matching insertion",
          message: `${entry} has a modeled successful state-changing history requiring absence from ${collection}, without a definite surviving insertion of that exact value/key into the same collection. Review whether this check is intended to consume a one-use identifier.`,
          location: query.location, source: query.location,
          trace: [{ kind: "constraint", label: `required absence in ${collection}`, location: query.location }],
          callPath: query.callPath.map(id => facts.program.symbols.get(id)!.name),
          remediation: "If this is a one-use identifier, insert the checked value/key into the same persistent collection on every successful history and retain it through transaction completion. Review intentional absence validation separately.",
          metadata: { reviewRequired: true, entry, collection, replayIntent: "unknown", evidence: "required-absence-without-definite-surviving-insertion", doesNotProve: "cross-transaction-replay-or-exploitability" },
        }, `${path.entry}:${spanId(query.location)}`));
      }
    }
    return unique(findings);
  },
};
