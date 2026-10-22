import { identityText, wrapIdentityMeter } from "../semantic/metering.js";
import type { AbstractValue } from "./index.js";
import type { Constant } from "./constants.js";
import type { ScalarConstraints } from "./transfers.js";

/** A conjunction of immutable scalar equalities/disequalities. No value or
 * provenance is renamed, and equal outputs never imply equal inputs. Rebuild
 * from the caller's retained facts so sibling states and selected hash arms
 * cannot share a stale equivalence class. The owning domain bounds the edges.
 */
export function scalarRelations(state: ScalarConstraints) {
  const charge = wrapIdentityMeter(state.scalarMeter, (work = 1, values = 0) => state.scalarMeter?.(work, values));
  charge(1, 10);
  const parents = new Map<string, string>();
  const constants = new Map<string, Constant>();
  const identities = new Map<string, string>();
  const identityKeys = new Map<string, string>();
  const identityKey = (identity: string): string => {
    let key = identityKeys.get(identity);
    if (key === undefined) identityKeys.set(identity, key = `identity:${identity}`);
    return key;
  };
  const different: [string, string][] = [];
  let consistent = true;
  const same = (a: Constant, b: Constant) => a.kind === b.kind && a.value === b.value;
  const find = (key: string): string => {
    let root = key;
    while (parents.has(root) && parents.get(root) !== root) { charge(); root = parents.get(root)!; }
    while (parents.has(key) && parents.get(key) !== root) {
      charge(); const next = parents.get(key)!; parents.set(key, root); key = next;
    }
    return root;
  };
  const join = (a: string, b: string): void => {
    a = find(a); b = find(b);
    if (a !== b) { charge(1, 1); parents.set(b, a); }
  };
  const remember = (key: string, value: Constant | undefined): void => {
    charge(1, 1); if (!value) return;
    const previous = constants.get(key);
    if (previous && !same(previous, value)) consistent = false;
    constants.set(key, value);
  };
  const constant = (value: AbstractValue): Constant | undefined => value.constantKind && value.constant !== undefined
    ? { kind: value.constantKind, value: value.constant } : undefined;
  const operand = (value: AbstractValue): string | undefined => {
    charge(1, 4 + Math.ceil((value.identity ? identityText(value.identity, state.scalarMeter).length : value.constant?.length ?? 0) / 64));
    if (value.items || value.fields) return;
    const normalized = state.hashRecipes?.refine(value, state) ?? value;
    const actual = constant(normalized);
    if (!normalized.identity) {
      if (!actual) return;
      const key = `constant:${JSON.stringify(actual)}`;
      remember(key, actual); return key;
    }
    const key = identityKey(normalized.identity);
    identities.set(key, normalized.identity);
    remember(key, state.known.get(normalized.identity)); remember(key, actual);
    if (value.identity && value.identity !== normalized.identity) {
      const original = identityKey(value.identity);
      identities.set(original, value.identity);
      remember(original, state.known.get(value.identity)); remember(original, constant(value));
      join(original, key);
    }
    return key;
  };
  for (const { left, right, equals } of state.scalarEqualities?.values() ?? []) {
    charge(1, 3); const a = operand(left), b = operand(right);
    if (!a || !b) continue;
    if (equals) join(a, b); else different.push([a, b]);
  }
  const known = new Map<string, Constant>();
  for (const [key, value] of constants) {
    charge(1, 1); const root = find(key), previous = known.get(root);
    if (previous && !same(previous, value)) consistent = false;
    known.set(root, value);
  }
  for (const [key, identity] of identities) {
    charge(1, 2); const value = known.get(find(key));
    if (value && state.excluded.get(identity)?.has(`${value.kind}:${value.value}`)) consistent = false;
  }
  const exclusions = new Set<string>();
  const excludedConstants = new Map<string, Set<string>>();
  for (const [key, identity] of identities) {
    charge(1, 2); const root = find(key), values = excludedConstants.get(root) ?? new Set<string>();
    for (const value of state.excluded.get(identity) ?? []) { charge(1, 1); values.add(value); }
    excludedConstants.set(root, values);
  }
  const pair = (a: string, b: string): string => { charge(1, 3 + Math.ceil((identityText(a, state.scalarMeter).length + identityText(b, state.scalarMeter).length) / 64)); return JSON.stringify([a, b].sort()); };
  for (const [a, b] of different) {
    charge(1, 1); const first = find(a), second = find(b), x = known.get(first), y = known.get(second);
    if (first === second || x && y && same(x, y)) consistent = false;
    exclusions.add(pair(first, second));
  }
  // Queries never add operands to the closure: its constants and classes are
  // frozen after construction. Original observations remain intact in State.
  const keyOf = (value: AbstractValue): string | undefined => {
    charge(1, 1 + Math.ceil(identityText(value.identity ?? "", state.scalarMeter).length / 64));
    if (value.items || value.fields) return;
    const identity = (state.hashRecipes?.refine(value, state) ?? value).identity;
    return identity ? identityKey(identity) : undefined;
  };
  const equality = (left: AbstractValue, right: AbstractValue): boolean | undefined => {
    charge(1, 4);
    const a = keyOf(left), b = keyOf(right);
    if (a && b) {
      charge(1, 1); const first = find(a), second = find(b);
      if (first === second) return true;
      if (exclusions.has(pair(first, second))) return false;
    }
    const x = constant(left) ?? (a ? state.known.get(a.slice(9)) ?? known.get(find(a)) : undefined);
    const y = constant(right) ?? (b ? state.known.get(b.slice(9)) ?? known.get(find(b)) : undefined);
    if (x && b && (excludedConstants.get(find(b))?.has(`${x.kind}:${x.value}`) || state.excluded.get(b.slice(9))?.has(`${x.kind}:${x.value}`))) return false;
    if (y && a && (excludedConstants.get(find(a))?.has(`${y.kind}:${y.value}`) || state.excluded.get(a.slice(9))?.has(`${y.kind}:${y.value}`))) return false;
    return x && y ? same(x, y) : undefined;
  };
  const propagate = (): void => {
    if (!consistent) return;
    for (const [key, identity] of identities) {
      charge(1, 2); const value = known.get(find(key));
      if (value && !state.known.has(identity)) {
        state.known.set(identity, value);
        state.hashRecipes?.invalidate(state, identity);
      }
    }
  };
  return { consistent, equality, propagate, identity: (value: AbstractValue): string | undefined => {
    const key = keyOf(value); return key ? find(key) : undefined;
  } };
}
