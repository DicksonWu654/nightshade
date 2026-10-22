import { pathLength, identityLength } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";
import { SOURCE_MAP_GETTER_RULE } from "../semantic/source-map-getters.js";
import type { Span } from "../model.js";

/** Exact original setter operands and surviving Map insertion; no dependency
 * union or equality between different invocations supplies a same-key proof. */
export function sourceMapGetterObservations(facts: AnalysisFacts) {
  const evidence = facts.sourceMapGetterEvidence;
  const observations: { setter: Span; returned: Span; constant: string }[] = [];
  let work = 0, values = 0;
  const charge = (steps = 1, retained = 0) => {
    work += steps; values += retained;
    if (!evidence || facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + values > evidence.maxValues) throw new Error("Source Map getter matching exhausted its shared allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  const exact = (value: AbstractValue): string => {
    const result = immutableOperandKey(value, Math.max(0, evidence!.maxSteps - facts.metrics.steps - work), undefined, charge);
    if (!result.complete || !result.key) throw new Error("Source Map getter immutable operand is unavailable");
    return result.key;
  };
  const history = (path: SuccessfulPath) => {
    charge(); const row = path.sourceClaimHistory;
    if (!row || row.operations !== (path.operations?.length ?? 0) || row.writes !== path.writes.length || row.predicates !== (path.predicates?.length ?? 0)) throw new Error("Original source Map getter history coverage is unavailable");
  };
  try {
    charge(1, 2);
    if (!evidence || facts.diagnostics.length || !facts.completedEntries.includes(evidence.claim.getter) || !facts.collectionEvidence || evidence.getterClosure !== "complete-without-selected-root-read" || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") throw new Error("Complete source Map getter evidence is unavailable");
    const claim = evidence.claim;
    if (!facts.sourceClaimEvidence || facts.sourceClaimEvidence.entry !== claim.getter || facts.sourceClaimEvidence.histories !== facts.paths.length
      || evidence.setterHistories !== evidence.setterPaths.length) throw new Error("Source Map original history inventory is unavailable");
    if (!facts.paths.length || !evidence.setterPaths.length) return { observations };
    let write: RuntimeOperation | undefined;
    for (const path of evidence.setterPaths) {
      if (path.entry !== claim.setter) throw new Error("Setter history entry identity is not isolated");
      history(path); let original: RuntimeOperation | undefined;
      for (const operation of path.operations ?? []) { charge(); if (operation.kind === "circuit-invocation" && operation.name === claim.setter) { if (original) throw new Error("Setter original argument boundary is ambiguous"); original = operation; } }
      if (!original || !original.args[claim.setterKeyIndex] || !original.args[claim.setterValueIndex]) throw new Error("Setter original parameter arguments are unavailable");
      const key = exact(original.args[claim.setterKeyIndex]), value = exact(original.args[claim.setterValueIndex]);
      charge(0, 2); const parents = new Map<string,string>(), defaults: string[] = [];
      const canonical = (operand: string) => {
        let depth = 0;
        while (parents.has(operand)) { charge(); if (++depth > 64) throw new Error("Setter final equality normalization is unavailable"); operand = parents.get(operand)!; }
        return operand;
      };
      for (const predicate of path.predicates ?? []) {
        const equalities = enforcedEqualities(predicate.value, predicate.truth, charge);
        if (!equalities.complete) throw new Error("Setter final equality evidence is unavailable");
        for (const equality of equalities.equalities) {
          charge(); if (!equality.equals) continue;
          const left = exact(equality.left), right = exact(equality.right), a = canonical(left), b = canonical(right);
          if (a !== b) { charge(1, 1); parents.set(a < b ? b : a, a < b ? a : b); }
          for (const operand of [equality.left,equality.right]) {
            charge(); const known = constantOf(operand);
            if (known && (known.kind === "bytes" ? /^0*$/.test(known.value) : known.kind === "integer" ? known.value === "0" : known.kind === "boolean" && known.value === "false")) {
              charge(0, 1); defaults.push(exact(operand));
            }
          }
        }
      }
      if (defaults.some(zero => { charge(); return canonical(zero) === canonical(value); })) return { observations };
      let selected: RuntimeOperation | undefined;
      for (const operation of path.operations ?? []) {
        charge(); if (operation.kind !== "collection-write" || operation.name !== "insert" || operation.args[0]?.region?.root !== claim.map || operation.args[0].region.path.length) continue;
        if (operation.writesBefore === undefined || operation.args.length !== 3) throw new Error("Setter insert receiver or ordering is unavailable");
        if (exact(operation.args[1]) !== key || exact(operation.args[2]) !== value) continue;
        if (constantOf(operation.args[2])) continue;
        const region = path.writes[operation.writesBefore]?.region;
        if (!region) throw new Error("Setter insert write boundary is unavailable");
        let survives = true;
        for (let index = operation.writesBefore + 1; index < path.writes.length; index++) {
          charge(); const later = path.writes[index];
          // Whole-root conservative refusal includes dynamic keys and nested changes.
          if (later.ledger === claim.map) survives = false;
        }
        if (survives) selected = operation;
      }
      if (!selected) return { observations };
      write ??= selected;
    }
    let constant: string | undefined, returned: Span | undefined;
    for (const path of facts.paths) {
      if (path.entry !== claim.getter) throw new Error("Getter history entry identity is not isolated");
      history(path); let output: AbstractValue | undefined;
      for (const sink of path.sinks) {
        charge(); if (sink.kind !== "exported-return" || sink.callPath[0] !== claim.getter) continue;
        if (output) throw new Error("Getter exported return boundary is ambiguous"); output = sink.value; returned ??= sink.location;
      }
      if (!output) throw new Error("Getter original returned value is unavailable");
      charge(1 + (output.constant?.length ?? 0)); const known = constantOf(output);
      if (!known) return { observations };
      const observed = `${known.kind}:${known.value}`;
      // The selected result must be the exact represented default, not merely
      // an unrelated constant of the same output type.
      if (known.kind === "bytes" ? !/^0*$/.test(known.value) : known.kind === "integer" ? known.value !== "0" : known.kind === "boolean" ? known.value !== "false" : true) return { observations };
      if (constant !== undefined && constant !== observed) return { observations };
      constant = observed;
    }
    if (write && returned && constant !== undefined) {
      let emission = 192 + claim.quote.length + identityLength(claim.setter, charge) + identityLength(claim.getter, charge) + identityLength(claim.map, charge) + identityLength(claim.setterKey, charge) + identityLength(claim.setterValue, charge) + identityLength(claim.getterKey, charge) + constant.length;
      for (const file of facts.program.files.keys()) { charge(); emission += pathLength(file, charge) + 4; }
      charge(emission, emission); observations.push({ setter: write.location, returned, constant });
    }
  } catch (error) {
    observations.length = 0; facts.diagnostics.push({ code: "source-map-getter-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.rootSource.ast.span, ...(evidence ? { scope: { kind: "rule" as const, detectorId: SOURCE_MAP_GETTER_RULE, entry: evidence.claim.getter } } : {}) });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
  return { observations };
}
