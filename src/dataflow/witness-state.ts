import type { AbstractValue, Flow, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { constantOf } from "./transfers.js";
import { spanId } from "../model.js";

/** Value-specific assertion dependency, not proof that an assertion is adequate
 * authentication or an application invariant. Witness-return argument dependency
 * is not a circuit validation of the argument. Branch choices are not assertions. */
export function uncheckedWitnessState(path: SuccessfulPath, charge: (work?: number) => void) {
  if (!path.predicates) throw new Error("Successful assertion predicates are unavailable");
  const assertions = new Set(path.path.filter(step => step.kind === "constraint").map(step => spanId(step.location)));
  charge(path.path.length);
  const checked = new Set<string>();
  for (const predicate of path.predicates) {
    charge();
    if (!assertions.has(spanId(predicate.location))) continue;
    for (const source of assertionWitnessDependencies(predicate.value, predicate.truth, charge)) checked.add(source);
    // Exact short-circuit execution can return a literal RHS while the LHS is
    // a required conjunct. Recover only that source's own && transfer sites;
    // ordinary branches, negated conjunctions and implicit selections are not
    // such evidence. This also works for a saved Boolean passed to assert.
    for (const flow of predicate.value.flows) {
      charge(1 + flow.trace.length);
      if (flow.trace.some(step => step.kind === "implicit-flow" || step.kind === "expression" && step.label === "!")) continue;
      for (const step of flow.trace) if (step.kind === "expression" && step.label === "&&") {
        for (const prior of path.predicates) {
          charge();
          if (!prior.truth || spanId(prior.location) !== spanId(step.location)) continue;
          const dependencies = assertionWitnessDependencies(prior.value, true, charge);
          if (dependencies.has(flow.source.id)) checked.add(flow.source.id);
        }
      }
    }
  }
  const results: { flow: Flow; write: SuccessfulPath["writes"][number]; leaf: string[] }[] = [];
  for (const [index, write] of path.writes.entries()) {
    const visit = (value: AbstractValue, leaf: string[], depth = 0): void => {
      charge();
      if (depth > 12) throw new Error("Witness state projection exceeds 12 levels");
      if (value.fields) { for (const [name, field] of Object.entries(value.fields)) visit(field, [...leaf, `field:${name}`], depth + 1); return; }
      if (value.items) { value.items.forEach((item, position) => visit(item, [...leaf, `index:${position}`], depth + 1)); return; }
      if (value.constant !== undefined) return;
      const region = [...write.region, ...leaf];
      if (!region.some(part => part === "*" || part === "key:*")) {
        // Only definite later overwrites suppress this final-state review.
        // Wildcard may-alias addresses never supply must-overwrite evidence.
        const overwritten = path.writes.slice(index + 1).some(later => {
          charge(1 + later.region.length);
          return later.ledger === write.ledger && later.region.length <= region.length
            && later.region.every((part, position) => part !== "*" && part !== "key:*" && part === region[position]);
        });
        if (overwritten) return;
      }
      for (const flow of value.flows) {
        charge(1 + flow.trace.length);
        if (flow.source.kind !== "witness" || flow.form !== "raw" || checked.has(flow.source.id)) continue;
        // Explicit casts can enforce implicit input checks. This narrow review
        // excludes converted values rather than claiming the checks are absent.
        if (flow.trace.some(step => step.kind === "cast" || step.kind === "witness-argument")) continue;
        results.push({ flow, write, leaf });
      }
    };
    visit(write.after, []);
  }
  return results;
}

/** Required witness-leaf dependencies, not equalities or a proof that the
 * relation is adequate. Decode Boolean/aggregate alternatives before joining. */
export function assertionWitnessDependencies(value: AbstractValue, truth: boolean, charge: (work?: number) => void): ReadonlySet<string> {
  const memo = new WeakMap<AbstractValue, Map<boolean, ReadonlySet<string>>>();
  const same = (left: AbstractValue, right: AbstractValue) => {
    const a = immutableOperandKey(left), b = immutableOperandKey(right);
    charge(a.work + b.work);
    if (!a.complete || !b.complete) throw new Error("Assertion operand identity allowance exhausted");
    return !!a.key && a.key === b.key;
  };
  const merge = (parts: ReadonlySet<string>[], alternatives: boolean): ReadonlySet<string> => {
    charge(parts.reduce((size, part) => size + part.size, 1));
    if (!parts.length) return new Set();
    if (alternatives) return new Set([...parts[0]].filter(source => parts.every(part => part.has(source))));
    return new Set(parts.flatMap(part => [...part]));
  };
  const sources = (parts: AbstractValue[]) => {
    const result = new Set<string>();
    for (const part of parts) for (const flow of part.flows) {
      charge(1 + flow.trace.length);
      if (flow.source.kind === "witness" && !flow.trace.some(step => step.kind === "witness-argument")) result.add(flow.source.id);
    }
    return result;
  };
  const pair = (left: AbstractValue, right: AbstractValue, equals: boolean, depth: number): ReadonlySet<string> => {
    charge();
    if (depth > 32) throw new Error("Assertion dependency projection exceeds 32 levels");
    if (same(left, right)) return new Set();
    for (const [subject, other] of [[left,right],[right,left]]) {
      const constant = constantOf(other);
      if (constant?.kind === "boolean") return condition(subject, equals === (constant.value === "true"), depth + 1);
    }
    for (const [subject, other] of [[left,right],[right,left]]) if (subject.predicateAlternatives) {
      return merge(subject.predicateAlternatives.map(part => pair(part, other, equals, depth + 1)), true);
    }
    if (left.fields || right.fields || left.items || right.items) {
      let parts: [AbstractValue,AbstractValue][];
      if (left.fields && right.fields && Object.keys(left.fields).length === Object.keys(right.fields).length
        && Object.keys(left.fields).every(name => name in right.fields!)) parts = Object.entries(left.fields).map(([name,part]) => [part,right.fields![name]]);
      else if (left.items && right.items && left.items.length === right.items.length) parts = left.items.map((part,index) => [part,right.items![index]]);
      else throw new Error("Assertion aggregate layout is unavailable");
      return merge(parts.map(([a,b]) => pair(a,b,equals,depth+1)), !equals);
    }
    return sources([left,right]);
  };
  const condition = (part: AbstractValue, selected: boolean, depth = 0): ReadonlySet<string> => {
    charge();
    if (depth > 32 || part.predicateStructureLost) throw new Error("Assertion dependency structure is unavailable or exceeds 32 levels");
    const prior = memo.get(part)?.get(selected); if (prior) return prior;
    let result: ReadonlySet<string>;
    if (part.negated) result = condition(part.negated,!selected,depth+1);
    else if (part.comparison) result = pair(part.comparison.left,part.comparison.right,part.comparison.operator === "==" ? selected : !selected,depth+1);
    else if (part.ordering) result = same(part.ordering.left,part.ordering.right) ? new Set() : sources([part.ordering.left,part.ordering.right]);
    else if (part.predicateAlternatives) result = merge(part.predicateAlternatives.map(arm => condition(arm,selected,depth+1)),true);
    else if (part.flows.some(flow => flow.source.id === part.identity && flow.source.kind === "witness")) {
      // A short-circuit RHS denotes this Boolean leaf; the LHS's dependency
      // union is evaluation control, not validation of the LHS on this route.
      result = new Set(part.flows.filter(flow => flow.source.id === part.identity && flow.source.kind === "witness").map(flow => flow.source.id));
    } else if (part.constantKind === "boolean" && part.constant !== undefined) {
      // A computed literal with taint (e.g. x == x && true) is not validation.
      // A refined raw Boolean still denotes the constrained witness leaf.
      result = new Set(part.flows.filter(flow => flow.source.id === part.identity && flow.source.kind === "witness").map(flow => flow.source.id));
    } else result = sources([part]);
    let selections = memo.get(part); if (!selections) memo.set(part,selections=new Map());
    selections.set(selected,result);
    return result;
  };
  return condition(value,truth);
}
