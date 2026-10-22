import type { AbstractValue, StateWrite, SuccessfulPath } from "./index.js";
import { listQueryIdentity } from "./lists.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";
import { regionKey } from "./regions.js";

/** An empty replacement cannot restart an extent proven empty (or a Map slot
 * proven absent) at this write's revision. Count acknowledgment alone is not
 * evidence of zero extent. Unknown initial storage remains unknown. */
export function listResetPreservesExtent(write: StateWrite, path: SuccessfulPath, allowance = 100000): {
  complete: boolean; preservesExtent: boolean; work: number;
} {
  let work = 0, complete = true, preservesExtent = !!write.before.emptyList;
  const charge = (units = 1, depth = 0) => complete &&= (work += units) <= allowance && depth <= 64;
  const region = write.before.region;
  if (!charge() || !region || region.revision === undefined || !path.predicates)
    return { complete: false, preservesExtent: false, work };
  if (region.path.includes("key:*")) return { complete, preservesExtent, work };
  const length = listQueryIdentity(region, region.revision, "length"), empty = listQueryIdentity(region, region.revision, "isEmpty");
  const boolean = (value: AbstractValue, truth: boolean, depth = 0): void => {
    if (!charge(1,depth) || value.predicateAlternatives || value.predicateStructureLost) return;
    if (value.negated) { boolean(value.negated,!truth,depth+1); return; }
    if (truth && value.identity === empty) preservesExtent = true;
    const absent = value.collectionPredicate;
    if (!truth && absent && !absent.empty && absent.key !== undefined && absent.revision === region.revision
      && regionKey({...absent.region,path:[...absent.region.path,`key:${absent.key}`]}) === regionKey(region)) preservesExtent = true;
    if (value.comparison) for (const [subject,other] of [[value.comparison.left,value.comparison.right],[value.comparison.right,value.comparison.left]]) {
      if (!charge()) return;
      const constant = constantOf(other);
      if (constant?.kind === "boolean") boolean(subject,(value.comparison.operator === "==" ? truth : !truth) === (constant.value === "true"),depth+1);
    }
  };
  for (const predicate of path.predicates) {
    if (!charge()) break;
    boolean(predicate.value,predicate.truth);
    if (predicate.value.predicateAlternatives || predicate.value.predicateStructureLost) continue;
    const decoded = enforcedEqualities(predicate.value,predicate.truth);
    if (!charge(decoded.work) || !decoded.complete) { complete = false; break; }
    for (const {left,right,equals} of decoded.equalities) {
      if (!charge()) break;
      if (!equals) continue;
      for (const [subject,other] of [[left,right],[right,left]]) {
        if (!charge()) break;
        const constant = constantOf(other);
        if (subject.identity === length && constant?.kind === "integer" && constant.value === "0") preservesExtent = true;
      }
    }
  }
  return { complete, preservesExtent: complete && preservesExtent, work };
}

/** Narrow acknowledgment of this selected List revision, not a proof of wallet
 * synchronization or cross-transaction safety. Bookkeeping `before` reads supply
 * the reset address/revision; only application predicates supply acknowledgment. */
export function acknowledgedListReset(write: StateWrite, path: SuccessfulPath, allowance = 1000000): {
  complete: boolean; acknowledged: boolean; work: number;
} {
  let work = 0, complete = true, acknowledged = !!write.before.emptyList;
  const charge = (units = 1, depth = 0) => complete &&= (work += units) <= allowance && depth <= 64;
  const region = write.before.region;
  if (!charge() || !region || region.revision === undefined || region.path.includes("key:*") || !path.predicates)
    return { complete: false, acknowledged: false, work };
  const length = listQueryIdentity(region, region.revision, "length");
  const empty = listQueryIdentity(region, region.revision, "isEmpty");
  const boolean = (value: AbstractValue, truth: boolean, depth = 0): void => {
    if (!charge(1, depth)) return;
    // Conservative alternatives never become a conjunction of must facts.
    if (value.predicateAlternatives || value.predicateStructureLost) return;
    if (value.negated) { boolean(value.negated, !truth, depth + 1); return; }
    if (truth && value.identity === empty) acknowledged = true;
    const absent = value.collectionPredicate;
    if (!truth && absent && !absent.empty && absent.key !== undefined && absent.revision === region.revision
      && regionKey({ ...absent.region, path: [...absent.region.path, `key:${absent.key}`] }) === regionKey(region)) acknowledged = true;
    if (value.comparison) {
      const { left, right, operator } = value.comparison;
      for (const [subject, other] of [[left, right], [right, left]]) {
        if (!charge()) return;
        const constant = constantOf(other);
        if (constant?.kind === "boolean") boolean(subject, (operator === "==" ? truth : !truth) === (constant.value === "true"), depth + 1);
      }
    }
  };
  const independent = (value: AbstractValue) => !value.ledger.size && (constantOf(value)?.kind === "integer"
    || value.flows.some(flow => flow.form === "raw" && ["entry-parameter", "witness"].includes(flow.source.kind)));
  for (const predicate of path.predicates) {
    if (!charge()) break;
    // A pure assertion after the reset can still constrain an immutable count
    // captured before it. A newly read post-reset count has a different revision.
    boolean(predicate.value, predicate.truth);
    if (predicate.value.predicateAlternatives || predicate.value.predicateStructureLost) continue;
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    if (!charge(decoded.work) || !decoded.complete) { complete = false; break; }
    for (const { left, right, equals } of decoded.equalities) {
      if (!charge()) break;
      if (!equals) continue;
      for (const [subject, other] of [[left, right], [right, left]]) {
        if (!charge()) break;
        if (subject.identity === length && other.identity !== length && independent(other)) acknowledged = true;
      }
    }
  }
  return { complete, acknowledged: complete && acknowledged, work };
}
