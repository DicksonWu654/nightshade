import type { AbstractValue, AnalysisFacts, RuntimeOperation } from "./index.js";
import { immutableEqualities } from "./immutable-equalities.js";
import { mintQuantityEvidence } from "./mint-quantities.js";
import { mayOverlap } from "./regions.js";
import { numericBound, parseType, printType } from "../semantic/types.js";
import { unshieldedUserRecipient, LIST_GROWTH_APPEND, type ListGrowthCharge } from "../semantic/list-growth.js";
import { ZERO_SEND_TARGET } from "../semantic/zero-send-targets.js";

export interface RetainedListGrowth {
  entry: string; send: RuntimeOperation; append: RuntimeOperation; root: string; address: string;
  revision: number; minimum: bigint; maximum: bigint; lengthBeforeAppend?: RuntimeOperation;
}

/** Exact send/key pairing and final retention on one original atomic history.
 * Later may-alias destructive writes refuse the proof instead of inventing
 * equality/disjointness from wildcard addresses or independent input names. */
export function retainedListGrowth(facts: AnalysisFacts, emit: (item: RetainedListGrowth, key: string) => void) {
  const evidence = facts.listGrowthEvidence;
  const charge: ListGrowthCharge = (work = 1, values = 0) => {
    facts.metrics.steps += work; facts.metrics.abstractValues += values;
    if (!evidence || facts.metrics.steps > evidence.maxSteps || facts.metrics.abstractValues > evidence.maxValues)
      throw new Error("List-growth proof exhausted its shared preparation/execution allowance");
    return true;
  };
  if (!evidence || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all"
    || !facts.mintQuantityEvidence || !facts.invocationEvidence?.includes(ZERO_SEND_TARGET)
    || !facts.invocationEvidence.includes(LIST_GROWTH_APPEND) || facts.diagnostics.length
    || !facts.completedEntries.includes(evidence.entry) || facts.paths.length !== evidence.histories
    || facts.paths.length > evidence.maxPaths)
    throw new Error("Complete original retained List-growth history evidence is unavailable");
  charge(0, 3); const emitted = new Set<string>();
  for (const path of facts.paths) {
    charge();
    if (path.entry !== evidence.entry || !path.complementaryHistory || path.checkpointOutcomes
      || path.complementaryHistory.operations !== (path.operations?.length ?? 0)
      || path.complementaryHistory.predicates !== path.predicates?.length || path.complementaryHistory.writes !== path.writes.length)
      throw new Error("Original retained List-growth rows are missing or inconsistent");
    charge(0, 2); const appends: RuntimeOperation[] = [], sends: RuntimeOperation[] = [];
    for (const operation of path.operations ?? []) {
      charge();
      if (operation.kind === "list-append" && operation.name === "pushFront") { charge(0, 1); appends.push(operation); }
      if (operation.kind === "circuit-invocation" && operation.name === ZERO_SEND_TARGET) { charge(0, 1); sends.push(operation); }
    }
    if (!appends.length || !sends.length) continue;
    const equality = immutableEqualities(path, Math.max(0, evidence.maxSteps - facts.metrics.steps), charge);
    const key = (value: AbstractValue) => {
      const result = equality.key(value);
      if (!equality.complete || !result) throw new Error("Immutable recipient/key congruence is unavailable");
      return result;
    };
    const address = (value: AbstractValue) => {
      const result = equality.address(value);
      if (!equality.complete || !result) throw new Error("Exact selected List address is unavailable");
      return result;
    };
    charge(0, 4);
    const falseTag: AbstractValue = { flows: [], ledger: new Set(), type: "Boolean", constantKind: "boolean", constant: "false" };
    charge(0, 4);
    const trueTag: AbstractValue = { flows: [], ledger: new Set(), type: "Boolean", constantKind: "boolean", constant: "true" };
    const numeric = mintQuantityEvidence(path, work => { charge(work, 0); }, charge);
    for (const send of sends) {
      charge();
      const amount = send.args[1];
      const type = amount && facts.program.representationOf(amount.type ?? "unknown"), bound = type && numericBound(type);
      if (!amount || !type || typeof bound !== "bigint" || bound > 1n << 128n)
        throw new Error("Canonical sent amount lacks an exact unsigned snapshot");
      const { range } = numeric.bounds(amount, type);
      if (range.minimum !== 0n) continue;
      const recipient = send.args[2] && unshieldedUserRecipient(facts.program, send.args[2], tag => { const observed = key(tag); return observed === key(falseTag) ? true : observed === key(trueTag) ? false : undefined; }, charge);
      if (!recipient) continue;
      const recipientKey = key(recipient);
      for (const append of appends) {
        charge();
        const receiver = append.args[0], region = receiver?.region;
        if (!region) throw new Error("List append receiver provenance is unavailable");
        const root = facts.program.symbols.get(region.root);
        charge(1, 3);
        const shape = root && parseType(facts.program.representationOf(root.type));
        // Initial scope: one represented Bytes<32>-keyed Map selecting a List.
        if (!shape || shape.name !== "Map" || shape.args.length !== 2
          || facts.program.representationOf(printType(shape.args[0])) !== "Bytes<32>"
          || parseType(facts.program.representationOf(printType(shape.args[1]))).name !== "List") continue;
        const selectors = region.collectionSelectors;
        if (region.path.length !== 1 || selectors?.length !== 1 || selectors[0].index !== 0)
          throw new Error("Compound selected List receiver congruence is unavailable");
        if (key(selectors[0].value) !== recipientKey) continue;
        const selected = address(receiver), start = append.writesBefore;
        if (start === undefined || region.revision === undefined || !path.writes[start]
          || path.writes[start].ledger !== region.root || path.writes[start].region.length !== region.path.length
          || path.writes[start].region.some((part, index) => part !== region.path[index]) || facts.program.representationOf(path.writes[start].after.type ?? "unknown") !== facts.program.representationOf(region.type))
          throw new Error("Ordered append write or receiver revision is unavailable");
        for (let index = start + 1; index < path.writes.length; index++) {
          charge(); const write = path.writes[index];
          if (!mayOverlap(region, { root: write.ledger, path: write.region, type: write.after.type ?? "unknown" })) continue;
          let preserves = false;
          for (const later of appends) {
            charge();
            if (later.writesBefore === index) { preserves = true; break; }
          }
          if (!preserves) throw new Error("Later overlapping List/ancestor mutation prevents retained-append qualification");
        }
        let lengthBeforeAppend: RuntimeOperation | undefined;
        for (const query of path.operations ?? []) {
          charge(); const snapshot = query.result.listLengthSnapshot;
          if (query.kind !== "collection-query" || query.name !== "length" || !snapshot?.receiver
            || query.writesBefore !== start || snapshot.revision !== region.revision) continue;
          if (address(snapshot.receiver) === selected) { lengthBeforeAppend = query; break; }
        }
        let units = 12 + Math.ceil(path.entry.length / 64);
        for (const operation of [send, append]) {
          charge(); units += 4 + Math.ceil(operation.location.file.length / 64);
          for (const site of operation.callSites ?? []) { charge(); units += 4 + Math.ceil(site.file.length / 64); }
        }
        charge(0, units);
        const pairKey = JSON.stringify([path.entry, send.location.file, send.location.start, append.location.file, append.location.start,
          send.callSites?.map(site => [site.file, site.start]), append.callSites?.map(site => [site.file, site.start])]);
        if (emitted.has(pairKey)) continue;
        // Reserve the output record, trace and metadata before constructing it.
        charge(1, 48 + append.callPath.length * 2); emitted.add(pairKey);
        emit({ entry: path.entry, send, append, root: region.root, address: selected, revision: region.revision,
          minimum: range.minimum, maximum: range.maximum, ...(lengthBeforeAppend ? { lengthBeforeAppend } : {}) }, pairKey);
      }
    }
  }
}
