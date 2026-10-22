import type { AbstractValue, RuntimeOperation, SuccessfulPath } from "./index.js";
import { immutableCollectionAddress, immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";
import { mayOverlap } from "./regions.js";

/** Required absence with no definite surviving insertion in that same receiver.
 * This is one successful history, not cross-transaction replay feasibility. */
export function collectionAbsenceConsumption(path: SuccessfulPath, allowance = 1000000,
  options: { value?: AbstractValue; beforeOperation?: number; receiver?: AbstractValue; identityText?: (identity: string) => string } = {}): {
  complete: boolean; work: number; absences: { query: RuntimeOperation; survives: boolean; preservingInsertWrites: number[]; matchingInsertOperations: number[] }[];
} {
  let work = 0, complete = true;
  const charge = (units = 1) => { work += units; return complete &&= work <= allowance; };
  const failed = () => ({ complete: false, work, absences: [] });
  if (!path.predicates) return failed();
  // A bounded prefix consumer may require that the false query is already
  // enforced at a particular operation. Later constraints cannot donate that
  // guard. The full history still establishes surviving persistent insertion.
  const predicates = options.beforeOperation === undefined ? path.predicates : [];
  if (options.beforeOperation !== undefined) for (const predicate of path.predicates) {
    if (!charge()) return failed();
    if (predicate.operationsBefore <= options.beforeOperation) predicates.push(predicate);
  }
  const parents = new Map<string, string>();
  const find = (key: string): string => {
    let current = key;
    while (parents.has(current)) { if (!charge()) break; current = parents.get(current)!; }
    return current;
  };
  const rawKey = (value: AbstractValue): string | undefined => {
    const result = immutableOperandKey(value, Math.min(4096, allowance - work), undefined, undefined, options.identityText);
    charge(result.work); complete &&= result.complete;
    return result.key;
  };
  // Late equalities apply to the whole atomic successful history. They relate
  // actual immutable values, never a wildcard region or a dependency union.
  for (const predicate of predicates) {
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    if (!charge(decoded.work) || !decoded.complete) return failed();
    for (const { left, right, equals } of decoded.equalities) {
      if (!charge()) return failed();
      if (!equals) continue;
      const a = rawKey(left), b = rawKey(right);
      if (a && b) { const x = find(a), y = find(b); if (x !== y) parents.set(y, x); }
    }
  }
  const key = (value: AbstractValue): string | undefined => {
    const result = immutableOperandKey(value, Math.min(4096, allowance - work), find, undefined, options.identityText);
    charge(result.work); complete &&= result.complete;
    return result.key;
  };
  const address = (value: AbstractValue): string | undefined => {
    const result = immutableCollectionAddress(value, Math.min(4096, allowance - work), find, undefined, options.identityText);
    charge(result.work); complete &&= result.complete;
    return result.key;
  };
  // Boolean equality relays requirements without turning an ignored query or
  // tautology into a guard. Relations carry parity, so negation and != retain
  // their meaning. This is bounded propagation, not a general path solver.
  const required = new Map<string, boolean>(), values = new Map<string, AbstractValue>();
  const adjacent = new Map<string, Map<string, boolean>>(), pending: string[] = [];
  const registered = new WeakMap<AbstractValue, string | undefined>();
  let feasible = true;
  const require = (key: string, truth: boolean): void => {
    if (!charge()) return;
    const prior = required.get(key);
    if (prior !== undefined) { feasible &&= prior === truth; return; }
    required.set(key, truth); pending.push(key);
  };
  const relate = (first: string, second: string, same: boolean): void => {
    if (!charge()) return;
    if (first === second) { feasible &&= same; return; }
    for (const [a, b] of [[first, second], [second, first]]) {
      const edges = adjacent.get(a) ?? new Map<string, boolean>();
      const prior = edges.get(b);
      if (prior !== undefined) feasible &&= prior === same;
      edges.set(b, same); adjacent.set(a, edges);
      const truth = required.get(a);
      if (truth !== undefined) require(b, truth === same);
    }
  };
  const boolean = (value: AbstractValue) => value.type === "Boolean" || !!value.negated || !!value.comparison
    || !!value.ordering || !!value.collectionPredicate || constantOf(value)?.kind === "boolean";
  const register = (value: AbstractValue, depth = 0): string | undefined => {
    if (!charge() || depth > 64) { complete = false; return undefined; }
    if (registered.has(value)) return registered.get(value);
    const key = rawKey(value);
    registered.set(value, key);
    if (!key) return undefined;
    values.set(key, value);
    if (value.negated) {
      const child = register(value.negated, depth + 1);
      if (child) relate(key, child, false);
    } else if (value.comparison) {
      for (const operand of [value.comparison.left, value.comparison.right]) if (boolean(operand)) register(operand, depth + 1);
    }
    return key;
  };
  for (const predicate of predicates) {
    const key = register(predicate.value);
    if (key) require(key, predicate.truth);
  }
  for (let index = 0; index < pending.length && complete && feasible; index++) {
    if (!charge()) return failed();
    const key = pending[index], truth = required.get(key)!, value = values.get(key)!;
    for (const [other, same] of adjacent.get(key) ?? []) require(other, truth === same);
    if (value.comparison && boolean(value.comparison.left) && boolean(value.comparison.right)) {
      const { left, right, operator } = value.comparison;
      const first = registered.get(left), second = registered.get(right);
      if (!first || !second) continue;
      const same = operator === "==" ? truth : !truth;
      relate(first, second, same);
      if (first === second) continue;
      for (const [operand, key] of [[left, first], [right, second]] as const) {
        const constant = constantOf(operand);
        if (constant?.kind === "boolean") require(key, constant.value === "true");
      }
    }
  }
  if (!complete) return failed();
  if (!feasible) return { complete: true, work, absences: [] };
  const matchedKey = options.value && key(options.value);
  if (options.value && (!matchedKey || !complete)) return failed();
  const matchedReceiver = options.receiver && address(options.receiver);
  if (options.receiver && (!matchedReceiver || !complete)) return failed();
  const absences: { query: RuntimeOperation; survives: boolean; preservingInsertWrites: number[]; matchingInsertOperations: number[] }[] = [];
  const operations = path.operations ?? [];
  for (let index = 0; index < operations.length; index++) {
    if (!charge()) return failed();
    const query = operations[index];
    if (query.kind !== "collection-query") continue;
    if (options.beforeOperation !== undefined && index >= options.beforeOperation) continue;
    const observation = rawKey(query.result);
    if (!observation || required.get(observation) !== false) continue;
    const receiver = address(query.args[0]), member = key(query.args[1]), region = query.args[0].region;
    if (!receiver || !member || !region || query.writesBefore === undefined || !complete) return failed();
    if (matchedKey && member !== matchedKey) continue;
    if (matchedReceiver && receiver !== matchedReceiver) continue;
    let inserted = false, writeIndex = query.writesBefore;
    const preservingInsertWrites: number[] = [];
    const matchingInsertOperations: number[] = [];
    const invalidations = (until: number): void => {
      for (; writeIndex < until; writeIndex++) {
        if (!charge()) return;
        const write = path.writes[writeIndex];
        // Updating a Map value (including a Counter/List/nested Map) cannot
        // delete that Map entry. Only replacing this receiver or an ancestor
        // can erase its membership without a recorded collection removal.
        if (write.region.length <= region.path.length && mayOverlap(region, { root: write.ledger, path: write.region, type: "unknown" })) inserted = false;
      }
    };
    for (let operationIndex = index + 1; operationIndex < operations.length; operationIndex++) {
      const operation = operations[operationIndex];
      if (!charge()) return failed();
      if (operation.kind !== "collection-write") continue;
      if (operation.writesBefore === undefined) return failed();
      invalidations(operation.writesBefore);
      const other = operation.args[0].region;
      if (!other) return failed();
      const sameReceiver = address(operation.args[0]) === receiver;
      const otherKey = operation.args[1] && key(operation.args[1]);
      const sameKey = otherKey === member;
      const writes = path.writes.slice(operation.writesBefore, operation.writesBefore + 1);
      // Expose only definite same-receiver insertions, using the very same
      // component-wise equality closure as survival matching. Prefix users
      // must not invalidate an equality-alias receiver with raw address text.
      if (sameReceiver && ["insert", "insertDefault", "insertCoin"].includes(operation.name)) preservingInsertWrites.push(operation.writesBefore);
      if (sameReceiver && sameKey && ["insert", "insertDefault", "insertCoin"].includes(operation.name)) {
        inserted = true;
        matchingInsertOperations.push(operationIndex);
      }
      else if (other.path.length <= region.path.length && writes.some(write => mayOverlap(region, { root: write.ledger, path: write.region, type: "unknown" }))) {
        // A different insertion cannot remove an existing member of this same
        // collection. Removals with an unknown relationship may erase it.
        const sameCollectionInsert = other.path.length === region.path.length && ["insert", "insertDefault", "insertCoin"].includes(operation.name);
        const constantsDiffer = operation.args[1] && constantOf(query.args[1]) && constantOf(operation.args[1])
          && JSON.stringify(constantOf(query.args[1])) !== JSON.stringify(constantOf(operation.args[1]));
        if (!sameCollectionInsert && !(sameReceiver && operation.name === "remove" && constantsDiffer)) inserted = false;
      }
      writeIndex = operation.writesBefore + writes.length;
    }
    invalidations(path.writes.length);
    if (!complete) return failed();
    absences.push({ query, survives: inserted, preservingInsertWrites, matchingInsertOperations });
  }
  return complete ? { complete, work, absences } : failed();
}

/** A required absence is current at this exact insertion, enforced before it,
 * and this insertion survives without removal/replacement through completion.
 * The caller qualifies the receiver as a canonical Set. Later reinsertion does
 * not rescue an earlier removed key; any overlapping write before insertion
 * invalidates the earlier revision. Ordinary broad consumers remain unchanged. */
export function requiredAbsenceBeforeSurvivingInsertion(path: SuccessfulPath, insertionIndex: number, allowance = 200000, identityText?: (identity: string) => string): {
  complete: boolean; work: number; queries: RuntimeOperation[];
} {
  let work = 0;
  const failed = () => ({ complete: false, work, queries: [] });
  const charge = () => ++work <= allowance;
  const operations = path.operations;
  if (!Number.isSafeInteger(allowance) || allowance < 1 || !operations || !path.predicates
    || !Number.isSafeInteger(insertionIndex) || insertionIndex < 0 || insertionIndex >= operations.length) return failed();
  for (const predicate of path.predicates) {
    if (!charge()) return failed();
    if (!Number.isSafeInteger(predicate.operationsBefore) || predicate.operationsBefore < 0 || predicate.operationsBefore > operations.length
      || !Number.isSafeInteger(predicate.writesBefore) || predicate.writesBefore < 0 || predicate.writesBefore > path.writes.length) return failed();
  }
  for (const operation of operations) {
    if (!charge()) return failed();
    if (!["collection-query", "collection-write"].includes(operation.kind)) continue;
    if (!operation.args[0]?.region || operation.writesBefore === undefined || !Number.isSafeInteger(operation.writesBefore)
      || operation.writesBefore < 0 || operation.writesBefore > path.writes.length) return failed();
  }
  const insertion = operations[insertionIndex];
  const receiver = insertion.args[0], value = insertion.args[1], region = receiver?.region;
  const at = insertion.writesBefore;
  if (insertion.kind !== "collection-write" || insertion.name !== "insert" || !region || !value
    || at === undefined || !Number.isSafeInteger(at) || at < 0 || at >= path.writes.length) return failed();
  const result = collectionAbsenceConsumption(path, allowance - work,
    { value, receiver, beforeOperation: insertionIndex, identityText });
  work += result.work;
  if (!result.complete) return failed();
  const queries: RuntimeOperation[] = [];
  for (const absence of result.absences) {
    if (!charge()) return failed();
    let matches = false;
    for (const index of absence.matchingInsertOperations) {
      if (!charge()) return failed();
      if (index === insertionIndex) matches = true;
    }
    if (!matches || !absence.survives) continue;
    const start = absence.query.writesBefore;
    if (start === undefined || !Number.isSafeInteger(start) || start < 0 || start > at) return failed();
    let current = true;
    for (let index = start; index < at; index++) {
      if (!charge()) return failed();
      const write = path.writes[index];
      if (mayOverlap(region, { root: write.ledger, path: write.region, type: "unknown" })) current = false;
    }
    // These are preserving same-receiver insertions, not evidence of matching
    // keys. Exact pre-effect matching was certified independently above.
    const permitted = new Set<number>();
    for (const index of absence.preservingInsertWrites) {
      if (!charge()) return failed();
      permitted.add(index);
    }
    for (let index = at + 1; index < path.writes.length; index++) {
      if (!charge()) return failed();
      const write = path.writes[index];
      if (mayOverlap(region, { root: write.ledger, path: write.region, type: "unknown" })
        && !permitted.has(index)) current = false;
    }
    if (current) queries.push(absence.query);
  }
  return { complete: true, work, queries };
}

/** Existing one-use review: preserve the full atomic-history contract. */
export function unconsumedAbsences(path: SuccessfulPath, allowance = 1000000, identityText?: (identity: string) => string): {
  complete: boolean; work: number; queries: RuntimeOperation[];
} {
  const result = collectionAbsenceConsumption(path, allowance, { identityText });
  return { complete: result.complete, work: result.work,
    queries: result.absences.filter(absence => !absence.survives).map(absence => absence.query) };
}
