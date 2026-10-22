import type { AbstractValue, RuntimeOperation, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { mayOverlap, type Region } from "./regions.js";

export const CURRENT_ROOT_RULE = "current-root-policy-mismatch";
export interface EnforcedMerkleCheck { queries: { operation: RuntimeOperation; index: number }[]; predicate: SuccessfulPredicate }

/** Opaque transformations cannot silently discard an observed check Boolean.
 * Dependency is deliberately not equality or positive enforcement evidence. */
export function containsObservedMerkleCheck(value: AbstractValue, operations: readonly RuntimeOperation[], charge: () => boolean): boolean | undefined {
  const identities = new Set<string>();
  for (const operation of operations) {
    if (!charge()) return;
    if (operation.kind === "merkle-check" && operation.result.identity) identities.add(operation.result.identity);
  }
  const seen = new Set<AbstractValue>();
  const visit = (value: AbstractValue, depth = 0): boolean | undefined => {
    if (!charge() || depth > 64) return;
    if (value.predicateStructureLost || value.merklePredicate && !value.merklePredicate.full || value.identity && identities.has(value.identity)) return true;
    if (seen.has(value)) return false;
    seen.add(value);
    for (const part of [...value.items ?? [], ...Object.values(value.fields ?? {}), ...value.predicateAlternatives ?? [],
      ...value.comparison ? [value.comparison.left, value.comparison.right] : [],
      ...value.ordering ? [value.ordering.left, value.ordering.right] : [], ...value.negated ? [value.negated] : []]) {
      const found = visit(part, depth + 1);
      if (found !== false) return found;
    }
    return false;
  };
  return visit(value);
}

/** Decode actual immutable observed Booleans. A refined current-root query can
 * also carry an equality; that comparison must not erase its native observation.
 * Nonliteral Boolean relations are unavailable, never an absence certificate. */
export function enforcedMerkleChecks(path: SuccessfulPath, ledger: string,
  charge: (work?: number, values?: number) => boolean): EnforcedMerkleCheck[] | undefined {
  if (!path.predicates || !path.operations) return;
  const checks = new Map<string, EnforcedMerkleCheck["queries"]>();
  for (const [index, operation] of path.operations.entries()) {
    if (!charge()) return;
    if (operation.kind !== "merkle-check" || operation.args[0].region?.root !== ledger) continue;
    const key = operation.result.identity;
    if (!key) return;
    const queries = checks.get(key) ?? [];
    if (!charge(0, 1)) return;
    queries.push({ operation, index }); checks.set(key, queries);
  }
  const containsCheck = (value: AbstractValue, depth = 0): boolean | undefined => {
    if (!charge() || depth > 64) return;
    if (value.identity && checks.has(value.identity) || value.merklePredicate?.region.root === ledger) return true;
    for (const part of [...value.items ?? [], ...Object.values(value.fields ?? {}), ...value.predicateAlternatives ?? [],
      ...value.comparison ? [value.comparison.left, value.comparison.right] : [], ...value.negated ? [value.negated] : []]) {
      const found = containsCheck(part, depth + 1);
      if (found !== false) return found;
    }
    return false;
  };
  const enforced: EnforcedMerkleCheck[] = [];
  for (const predicate of path.predicates) {
    if (!charge()) return;
    const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
      // q == q alone does not require q to be true.
      if (equality.left.identity && equality.left.identity === equality.right.identity) return [];
      const first = containsCheck(equality.left), second = containsCheck(equality.right);
      return first === false && second === false ? [] : undefined;
    }, charge, undefined, (value, truth) => {
      const queries = value.identity && checks.get(value.identity);
      if (!queries) return value.merklePredicate?.region.root === ledger ? undefined : null;
      if (!truth) return [];
      if (!charge(queries.length, queries.length)) return;
      // Do not borrow an observation evaluated after this enforcing predicate.
      const prior = queries.filter(query => query.index < predicate.operationsBefore);
      return prior.length ? [{ key: value.identity!, value: { queries: prior, predicate } }] : undefined;
    });
    if (!projected) return;
    for (const check of projected.required.values()) {
      if (!charge(0, 1)) return;
      enforced.push(check);
    }
  }
  return enforced;
}

/** Epochs in MerkleFacts are not ledger revisions. Only ordered real writes
 * between query and enforcement certify freshness. Possible aliases remove
 * certification; they do not establish that a different root was stored. */
export function merkleFreshAtEnforcement(path: SuccessfulPath, query: EnforcedMerkleCheck["queries"][number],
  predicate: SuccessfulPredicate, charge: (work?: number, values?: number) => boolean): { complete: boolean; overlaps: number[] } {
  const start = query.operation.writesBefore, end = predicate.writesBefore, operations = predicate.operationsBefore;
  const region = query.operation.args[0].region;
  if (!region || start === undefined || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || !Number.isSafeInteger(operations)
    || start < 0 || end < start || end > path.writes.length || query.index >= operations || operations > (path.operations?.length ?? 0))
    return { complete: false, overlaps: [] };
  const overlaps: number[] = [];
  for (let index = start; index < end; index++) {
    if (!charge()) return { complete: false, overlaps: [] };
    const write = path.writes[index], target: Region = { root: write.ledger, path: write.region, type: "unknown" };
    // mayOverlap is directional when one region is an ancestor.
    if (mayOverlap(region, target) || mayOverlap(target, region)) {
      if (!charge(0, 1)) return { complete: false, overlaps: [] };
      overlaps.push(index);
    }
  }
  return { complete: true, overlaps };
}
