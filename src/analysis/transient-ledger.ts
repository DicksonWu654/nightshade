import type { AnalysisFacts, StateWrite } from "../dataflow/index.js";
import { covers, mayOverlap } from "../dataflow/regions.js";
import type { TransientOrigin } from "../dataflow/transient-origins.js";
import { spanId, type Diagnostic } from "../model.js";
import { TRANSIENT_LEDGER_RULE, transientScope } from "../semantic/transient-targets.js";
import { parseType } from "../semantic/types.js";

export interface TransientLedgerObservation {
  entry: string;
  origin: TransientOrigin;
  writes: StateWrite[];
}

/** Terminal modeled storage operands, not all serialized ledger queries. */
export function transientLedgerObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: TransientLedgerObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  const charge = () => Number.isSafeInteger(allowance) && ++work <= allowance;
  for (const entry of facts.completedEntries) {
    const scope = transientScope(facts.program, entry, Math.max(0, allowance - work));
    work += scope.work;
    if (scope.complete && !scope.applicable) continue;
    const issue = (reason: string) => diagnostics.push({ code: "transient-ledger-evidence-unavailable", message: `${reason}; ${TRANSIENT_LEDGER_RULE} has no complete result for this entry`,
      location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: TRANSIENT_LEDGER_RULE, entry } });
    if (!scope.complete || !facts.transientEvidence || facts.pathSemantics !== "equivalent-states") { issue("Exact transient data origins are unavailable or applicability exhausted its allowance"); continue; }
    const groups = new Map<string, { observation: TransientLedgerObservation; writes: Set<string> }>();
    let unavailable: string | undefined;
    for (const path of facts.paths.filter(path => path.entry === entry)) {
      for (let index = 0; index < path.writes.length; index++) {
        if (!charge()) { unavailable = "Storage observation allowance exhausted"; break; }
        const write = path.writes[index];
        const origins = write.after.transientOrigins;
        if (!origins?.length && !write.after.transientOriginsUnavailable) continue;
        const region = { root: write.ledger, path: write.region, type: "unknown" };
        let killed = false, ambiguous = false;
        for (const later of path.writes.slice(index + 1)) {
          if (!charge()) { unavailable = "Storage lifetime allowance exhausted"; break; }
          const target = { root: later.ledger, path: later.region, type: "unknown" };
          if (covers(target, region)) { killed = true; break; }
          if (mayOverlap(region, target) || mayOverlap(target, region)) ambiguous = true;
        }
        if (unavailable) break;
        if (killed) continue;
        if (ambiguous || region.path.includes("key:*")) { unavailable = "May-alias or partial overwrites prevent a definite terminal storage operand"; break; }
        if (write.after.transientOriginsUnavailable) { unavailable = "Transient origins exceed their capacity or include a may-value union"; break; }
        const type = parseType(facts.program.representationOf(write.after.type ?? "unknown")).name;
        if (["List", "MerkleTree", "HistoricMerkleTree"].includes(type)) { unavailable = "Collection lifetime does not expose an exact retained payload"; break; }
        for (const origin of origins!) {
          if (!charge()) { unavailable = "Transient origin grouping allowance exhausted"; break; }
          const key = `${origin.primitive}:${spanId(origin.location)}`;
          const group = groups.get(key) ?? { observation: { entry, origin, writes: [] }, writes: new Set<string>() };
          const writeKey = JSON.stringify([spanId(write.location), write.region, write.callPath, write.callSites?.map(spanId)]);
          if (!group.writes.has(writeKey)) { group.writes.add(writeKey); group.observation.writes.push(write); }
          groups.set(key, group);
        }
        if (unavailable) break;
      }
      if (unavailable) break;
    }
    if (unavailable) issue(unavailable);
    else observations.push(...[...groups.values()].map(group => group.observation));
  }
  return { observations, diagnostics, work };
}
