import type { AbstractValue, SuccessfulPath } from "./index.js";
import { predicateOperandKey } from "./predicates.js";
import { constantOf } from "./transfers.js";

export interface PredicateCover {
  status: "unconstrained" | "constrained" | "incomplete";
  work: number;
}

/** Can caller conditions cover every private Boolean valuation within one
 * identical recorded public-condition context? Never merge distinct public
 * conjunctions: independent Boolean encodings cannot prove that arbitrary public
 * comparisons (e.g. ledger == 1 and ledger == 2) coexist. This queries completed
 * histories without new execution. A non-cover does not certify authentication. */
export function privatePredicateCover(paths: readonly SuccessfulPath[], allowance = 100000, identityText: (identity: string) => string = identity => identity): PredicateCover {
  let work = 0, exhausted = false;
  const charge = () => { if (++work > allowance) exhausted = true; return !exhausted; };
  const cubes: Map<string, boolean>[] = [];
  const privateAtoms = new Set<string>();
  const boundedKey = (key: string | undefined): string | undefined => {
    if (key && identityText(key).length > 65536) { exhausted = true; return undefined; }
    return key;
  };
  // Children are bounded before composition, so even escaped nested keys have
  // bounded temporary allocation. The result must pass the same limit.
  const compositeKey = (parts: readonly (string | boolean)[]): string | undefined => {
    if (parts.some(part => typeof part === "string" && identityText(part).length > 65536)) { exhausted = true; return undefined; }
    return boundedKey(JSON.stringify(parts));
  };
  // Execution constants may come from earlier assumptions. Read the retained
  // immutable operand identities first, including equality/negation aliases;
  // otherwise an application re-use of a stdlib decision loses its correlation.
  // This view queries recorded conditions and never re-executes a program path.
  const literal = (value: AbstractValue) => !value.identity && !value.negated && !value.comparison && !value.ordering
    && !value.flows.length && !value.ledger.size ? constantOf(value) : undefined;
  const scalarKey = (value: AbstractValue, path: SuccessfulPath, depth: number): string | undefined => {
    if (!charge() || depth > 64) { exhausted = true; return undefined; }
    // Derived comparison identities can contain path-refined constants. Rebuild
    // Boolean operands from their immutable leaves, recursively, before deciding
    // two expressions are the same value. This also cancels equality aliases.
    if (value.negated || value.comparison || value.ordering) {
      const normalized = condition(value, true, path, depth + 1);
      return normalized.constant !== undefined ? compositeKey(["boolean", normalized.constant])
        : normalized.key ? compositeKey(["boolean", normalized.key, normalized.truth]) : undefined;
    }
    // Never recursively serialize aggregate DAGs to manufacture an atom.
    const key = boundedKey(value.identity || literal(value) ? predicateOperandKey(value, path) : undefined);
    if (!key) return undefined;
    if (value.type === "Boolean" || value.constantKind === "boolean") {
      const constant = literal(value);
      return constant ? compositeKey(["boolean", constant.value === "true"]) : compositeKey(["boolean", key, true]);
    }
    return key;
  };
  const condition = (value: AbstractValue, truth: boolean, path: SuccessfulPath, depth = 0): { key?: string; truth: boolean; private: boolean; constant?: boolean } => {
    const result = { truth, private: value.flows.length > 0 };
    if (!charge() || depth > 64) { exhausted = true; return result; }
    if (value.negated) return condition(value.negated, !truth, path, depth + 1);
    if (value.comparison) {
      const { left, right, operator } = value.comparison;
      const equals = operator === "==" ? truth : !truth;
      const first = scalarKey(left, path, depth + 1), second = scalarKey(right, path, depth + 1);
      if (first && first === second) return { ...result, constant: equals };
      for (const [subject, other] of [[left, right], [right, left]]) {
        const constant = literal(other);
        if (constant?.kind === "boolean") return condition(subject, equals === (constant.value === "true"), path, depth + 1);
      }
      const a = literal(left), b = literal(right);
      if (a && b) return { ...result, constant: equals === (a.kind === b.kind && a.value === b.value) };
      return { ...result, truth: equals, key: first && second ? compositeKey(["equality", ...[first, second].sort()]) : undefined };
    }
    if (value.ordering) {
      const { left, right, operator, numericType } = value.ordering;
      const first = scalarKey(left, path, depth + 1), second = scalarKey(right, path, depth + 1);
      if (first && first === second) return { ...result, constant: truth === (operator === "<=" || operator === ">=") };
      return { ...result, key: first && second ? compositeKey(["ordering", numericType, operator, first, second]) : undefined };
    }
    const constant = literal(value);
    return constant?.kind === "boolean" ? { ...result, constant: truth === (constant.value === "true") }
      : { ...result, key: boundedKey(value.identity ? predicateOperandKey(value, path) : undefined) };
  };
  for (const [pathIndex, path] of paths.entries()) {
    if (!path.predicates) return { status: "incomplete", work };
    const cube = new Map<string, boolean>();
    let contradictory = false;
    for (const [index, predicate] of path.predicates.entries()) {
      if (!charge()) return { status: "incomplete", work };
      // Recipient/change branches inside the canonical library are transaction
      // mechanics, not application checks on the caller.
      if (predicate.callPath.at(-1)?.startsWith("standard-library::")) continue;
      const { key, truth, private: dependsOnPrivate, constant } = condition(predicate.value, predicate.truth, path);
      if (exhausted) return { status: "incomplete", work };
      if (constant !== undefined) { contradictory ||= !constant; continue; }
      if (key && identityText(key).length > 65536) return { status: "incomplete", work };
      const atom = key ?? `opaque:${pathIndex}:${index}`;
      if (dependsOnPrivate) privateAtoms.add(atom);
      if (cube.has(atom) && cube.get(atom) !== truth) contradictory = true;
      cube.set(atom, truth);
    }
    if (!contradictory) cubes.push(cube);
  }
  const contexts = new Map<string, Map<string, boolean>[]>();
  for (const cube of cubes) {
    const publicConditions: [string, boolean][] = [], privateConditions = new Map<string, boolean>();
    for (const [key, truth] of cube) {
      if (!charge()) return { status: "incomplete", work };
      if (privateAtoms.has(key)) privateConditions.set(key, truth);
      else publicConditions.push([key, truth]);
    }
    const context = JSON.stringify(publicConditions.sort(([a], [b]) => a.localeCompare(b)));
    const rows = contexts.get(context) ?? []; rows.push(privateConditions); contexts.set(context, rows);
  }
  const covers = (rows: readonly Map<string, boolean>[], depth: number): boolean => {
    if (!charge() || depth > 64) { exhausted = true; return false; }
    for (const row of rows) { if (!charge()) return false; if (!row.size) return true; }
    if (!rows.length) return false;
    const atom = rows[0].keys().next().value!;
    const branch = (truth: boolean): Map<string, boolean>[] => {
      const result: Map<string, boolean>[] = [];
      for (const row of rows) {
        if (!charge()) break;
        if (row.has(atom) && row.get(atom) !== truth) continue;
        const next = new Map<string, boolean>();
        for (const [key, value] of row) { if (!charge()) break; if (key !== atom) next.set(key, value); }
        if (exhausted) break;
        result.push(next);
      }
      return result;
    };
    const left = branch(false);
    if (exhausted || !covers(left, depth + 1)) return false;
    const right = branch(true);
    return !exhausted && covers(right, depth + 1);
  };
  let unconstrained = false;
  for (const rows of contexts.values()) {
    if (covers(rows, 0)) unconstrained = true;
    if (exhausted) break;
  }
  return { status: exhausted ? "incomplete" : unconstrained ? "unconstrained" : "constrained", work };
}
