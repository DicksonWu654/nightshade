import { directZeroRejection } from "./zero-rejection.js";
import type { AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { covers, mayOverlap, regionKey, type Region } from "./regions.js";
import { type Diagnostic, type Span } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import { parseType } from "../semantic/types.js";
import type { AbstractValue } from "./index.js";

export const ZERO_MAP_RULE = "zero-amount-initial-membership";
type Policy = NonNullable<ResolvedPolicies["zeroAmountMembership"]>[number];
interface Requirement { region: Region; key: string; location: Span; kind: "lookup" | "predicate"; callPath: string[]; callSites: Span[]; writesBefore: number }
export interface ZeroMembershipObservation { policy: Policy; requirement: Requirement; histories: Requirement[][]; zeroSuccesses: number }

/** Shared exact per-history initial Map preconditions. Failure withholds a
 * relation; the caller owns the rule's budget and diagnostic contract. */
export function initialMapRequirements(facts: AnalysisFacts, path: SuccessfulPath, map: string,
  charge: (amount?: number, retained?: number) => boolean, unavailable: (message: string) => never): Map<string, Requirement> {
  charge(0, 2);
  const required = new Map<string, Requirement>();
  // Match every actual write once; no lexical call/site equality is used
  // to bind separate helper invocations or their operands.
  const writes = new Map<number, RuntimeOperation>();
  for (const operation of path.operations ?? []) {
    charge();
    if (operation.kind === "collection-write") {
      if (operation.writesBefore === undefined || writes.has(operation.writesBefore))
        unavailable("Collection write lacks an exact ordered occurrence");
      charge(0, 1);
      writes.set(operation.writesBefore!, operation);
    }
  }
  const requirement = (region: Region, key: string | undefined, position: number | undefined, revision: number,
    source: Omit<Requirement, "region" | "key" | "writesBefore">): { key: string; value: Requirement }[] => {
    charge();
    let wildcard = false;
    for (const part of region.path) { charge(); wildcard ||= part === "key:*"; }
    if (!key || wildcard || position === undefined || !Number.isSafeInteger(position) || position < 0 || position > path.writes.length
      || source.callSites.length !== source.callPath.length)
      return unavailable("Membership lacks an exact key, receiver or query/write position");
    const keyUnits = 6 * (1 + Math.ceil(facts.program.meteringIdentity(key).length / 64));
    charge(keyUnits + region.path.length + 1, keyUnits + region.path.length + 4);
    const cell = { ...region, path: [...region.path, `key:${key}`] };
    const recordedKey = (target: Region) => {
      let units = 1 + Math.ceil(facts.program.meteringIdentity(target.root).length / 64);
      for (const part of target.path) { charge(); units += 1 + Math.ceil(facts.program.meteringIdentity(part).length / 64); }
      charge(6 * units, 6 * units + target.path.length + 1);
      return regionKey(target);
    };
    const cellKey = recordedKey(cell);
    let origin: "initial" | "supplied" | "absent" | "unknown" = "initial";
    let epoch = 0;
    for (let index = 0; index < position; index++) {
      charge(1, 1);
      const write = path.writes[index], target = { root: write.ledger, path: write.region, type: "unknown" };
      if (write.ledger === region.root) epoch++;
      charge(cell.path.length + target.path.length);
      if (!mayOverlap(cell, target)) continue;
      // Updating a descendant value cannot remove its containing entry.
      if (target.path.length > cell.path.length) continue;
      const operation = writes.get(index);
      const exact = recordedKey(target) === cellKey;
      if (exact && operation && ["insert", "insertDefault", "insertCoin", "remove"].includes(operation.name)) {
        origin = operation.name === "remove" ? "absent" : "supplied";
      } else if ((charge(target.path.length + region.path.length), covers(target, region))) {
        origin = write.after.emptyCollection ? "absent" : "unknown";
      } else if (!exact || operation) origin = "unknown";
      // An exact scalar/ADT value write preserves membership. Its own
      // lookup (if needed) is retained separately as a requirement.
    }
    if (epoch !== revision) return unavailable("Membership query revision does not match its retained ordered write position");
    if (origin === "unknown" || origin === "absent") return unavailable("Membership origin crosses a may-alias write or unqualified receiver replacement");
    if (origin === "supplied") { charge(0, 1); return []; }
    charge(0, 10);
    const value = { ...source, region, key, writesBefore: position };
    return [{ key: cellKey, value }];
  };
  for (const operation of path.operations ?? []) {
    charge();
    if (operation.kind !== "map-lookup" || operation.membership?.region.root !== map) continue;
    if (!operation.callSites) unavailable("Lookup lacks exact invocation sites");
    const membership = operation.membership!;
    charge(0, 5);
    for (const atom of requirement(membership.region, membership.key, operation.writesBefore, membership.revision, {
      kind: "lookup", location: operation.location, callPath: operation.callPath, callSites: operation.callSites! })) {
      charge(1, 1); required.set(atom.key, atom.value);
    }
  }
  if (!path.predicates) unavailable("Successful membership predicates were not retained");
  const selectedMember = (value: AbstractValue): boolean => {
    const member = value.collectionPredicate;
    if (!member || member.region.root !== map) return false;
    const type = facts.program.representationOf(member.region.type);
    charge(facts.program.meteringIdentity(type).length, facts.program.meteringIdentity(type).length);
    return parseType(type).name === "Map";
  };
  const containsMember = (value: AbstractValue, depth = 0): boolean => {
    charge(1, 1); if (depth > 64) return unavailable("Membership predicate traversal exceeds its depth allowance");
    if (selectedMember(value)) return true;
    for (const part of value.items ?? []) if (containsMember(part, depth + 1)) return true;
    for (const name in value.fields) if (containsMember(value.fields![name], depth + 1)) return true;
    for (const part of value.predicateAlternatives ?? []) if (containsMember(part, depth + 1)) return true;
    if (value.comparison && (containsMember(value.comparison.left, depth + 1) || containsMember(value.comparison.right, depth + 1))) return true;
    if (value.negated && containsMember(value.negated, depth + 1)) return true;
    return !!value.ordering && (containsMember(value.ordering.left, depth + 1) || containsMember(value.ordering.right, depth + 1));
  };
  for (const predicate of path.predicates!) {
    charge();
    const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
      if (containsMember(equality.left) || containsMember(equality.right))
        return unavailable("Membership is related to a nonconstant Boolean operand; exact relation projection is unavailable");
      charge(0, 1); return [];
    }, charge, (value, truth) => {
      const member = value.collectionPredicate!;
      if (!truth || member.empty || !selectedMember(value)) { charge(0, 1); return []; }
      charge(0, 5);
      return requirement(member.region, member.key, member.writesBefore, member.revision, {
        kind: "predicate", location: predicate.location, callPath: predicate.callPath, callSites: predicate.callSites });
    });
    if (!projected) unavailable("Required membership predicate structure is unavailable");
    for (const [key, atom] of projected!.required) { charge(1, 1); required.set(key, atom); }
  }
  return required;
}

/** The policy concerns the declared entry input, never an inferred helper
 * amount. Exact lookup preconditions and required saved member predicates are
 * traced through ordered writes. May-alias replacement certifies nothing. */
export function zeroMembershipObservations(facts: AnalysisFacts, policies?: ResolvedPolicies) {
  const observations: ZeroMembershipObservation[] = [], diagnostics: Diagnostic[] = [];
  const selected = policies?.zeroAmountMembership ?? [];
  const zero = facts.zeroEntry;
  let work = 0, values = 0;
  class Unavailable extends Error {}
  const charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (!zero || facts.metrics.steps + work > zero.maxSteps || facts.metrics.abstractValues + values > zero.maxValues)
      throw new Unavailable("Zero-entry membership evidence exhausted its shared work/value allowance");
    return true;
  };
  const unavailable = (message: string): never => { throw new Unavailable(message); };
  for (const policy of selected) {
    if (zero && (policy.circuit !== zero.entry || policy.amount !== zero.parameter)) continue;
    const location = facts.program.functions.get(policy.circuit)!.declaration.span;
    try {
      charge();
      if (!zero || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.collectionEvidence
        || !facts.completedEntries.includes(policy.circuit) || facts.diagnostics.length)
        unavailable("Complete exact declared-zero entry evidence is unavailable");
      const paths = facts.paths.filter(path => { charge(); return path.entry === policy.circuit; });
      if (!paths.length && zero!.rejection?.kind === "direct-nonzero-input" && zero!.rejection.ordinarySuccesses > 0 && directZeroRejection(facts)) continue;
      if (!paths.length) unavailable("No modeled full successful amount-zero invocation; membership dependency is unproven");
      const requirements = paths.map(path => initialMapRequirements(facts, path, policy.map, charge, unavailable));
      for (const [key, requirement] of requirements[0]) {
        charge();
        if (!requirements.every(history => { charge(); return history.has(key); })) continue;
        charge(1, 1);
        observations.push({ policy, requirement, zeroSuccesses: paths.length,
          histories: requirements.map(history => { charge(); return [history.get(key)!]; }) });
      }
    } catch (error) {
      if (!(error instanceof Unavailable)) throw error;
      diagnostics.push({ code: "zero-membership-unavailable", message: error.message, location,
        scope: { kind: "rule", detectorId: ZERO_MAP_RULE, entry: policy.circuit } });
    }
  }
  facts.metrics.steps += work; facts.metrics.abstractValues += values;
  return { observations, diagnostics };
}
