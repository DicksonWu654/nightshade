import type { AbstractValue } from "./index.js";

/** Rule-scoped conservative absence certificates. The isolated conservative
 * interpreter evaluates every expression that any exact successful history can
 * evaluate, over joined current values. A join of distinct incoming values is a
 * fresh `common:` may-value whose dependencies are the union of both arms; any
 * other value is the same value in every represented history, up to constant
 * refinement. Only a complete run without candidates is an absence claim. */
export interface RuleCertificate {
  status: "absent" | "candidate" | "incomplete";
  reason?: string;
  work: { steps: number; values: number };
}

export const mayJoinedValue = (value: AbstractValue): boolean =>
  typeof value.identity === "string" && value.identity.startsWith("common:");

/** Could a direct digest of this conservative input have, on some exact history,
 * a raw private leaf with a small declared domain (the low-entropy digest
 * criterion)? Publication, the single-private-leaf condition and predicate
 * structure are deliberately ignored: they can only remove a finding. A joined
 * leaf with any raw dependency is a candidate whatever its type. Returns
 * undefined when the bounded traversal or domain allowance is exhausted. */
export function digestInputCandidate(input: AbstractValue, smallDomain: (type: string) => boolean | undefined, charge: () => boolean): boolean | undefined {
  const pending = [input];
  while (pending.length) {
    if (!charge()) return undefined;
    const ingredient = pending.pop()!;
    if (ingredient.constant !== undefined) continue;
    if (ingredient.items || ingredient.fields) {
      pending.push(...ingredient.items ?? [], ...Object.values(ingredient.fields ?? {}));
      continue;
    }
    if (!ingredient.flows.some(flow => flow.form === "raw")) continue;
    if (mayJoinedValue(ingredient)) {
      // A common leaf can lose its original raw identity, but when every
      // incoming alternative has the same non-aggregate represented type the
      // exact detector will inspect that same type on any surviving leaf.
      // Unknown or mixed shapes still remain candidates.
      if (ingredient.digestJoinedLeafType !== ingredient.type) return true;
      const small = smallDomain(ingredient.type!);
      if (small !== false) return small === undefined ? undefined : true;
      continue;
    }
    if (!ingredient.type) return true;
    // A represented raw leaf is its own private source in every history. Any
    // other raw dependency is not a direct private leaf of this digest.
    if (!ingredient.flows.some(flow => flow.form === "raw" && flow.source.id === ingredient.identity)) continue;
    const small = smallDomain(ingredient.type);
    if (small !== false) return small === undefined ? undefined : true;
  }
  return false;
}

/** A native Either payload read can be reported only when its receiver tag is
 * (refined to) the constant selecting the other arm. A conservative constant
 * selecting this arm holds in every represented history. */
export function eitherReadCandidate(arm: "left" | "right", tag: AbstractValue | undefined): boolean {
  return !tag || tag.constantKind !== "boolean" || tag.constant !== String(arm === "left");
}
