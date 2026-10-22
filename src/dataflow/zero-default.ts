import { identityLength, type IdentityMeter } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { exactMapDebits, type Debit } from "./map-debit.js";
import { initialMapRequirements } from "./zero-membership.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { directZeroRejection } from "./zero-rejection.js";
import { ZERO_DEFAULT_RULE } from "../semantic/zero-default-targets.js";
import { spanId, type Diagnostic, type Span } from "../model.js";

interface KeyPattern { signature: string; root: string; parts: string[]; parameters: string[] }
export interface ZeroDefaultGetter { entry: string; pattern: KeyPattern; location: Span; absences: Span[]; histories: number }
type Charge = (work?: number, retained?: number) => boolean;

// Bound generated text in addition to counting its dimensions. Source-owned
// scalar leaves and identifiers are borrowed; new serialized keys are charged
// in 64-code-unit chunks before serialization, including escaping overhead.
function textUnits(value: string, charge: Charge): number { return 1 + Math.ceil(identityLength(value, charge) / 64); }
function serialize(parts: readonly string[], charge: Charge): string {
  charge(0, 1);
  let units = 1;
  for (const part of parts) { charge(); units += 6 * textUnits(part, charge); }
  charge(units, units);
  return JSON.stringify(parts);
}
function sameParameters(first: readonly string[], second: readonly string[], charge: Charge, prefix = false): boolean {
  charge();
  if (!prefix && first.length !== second.length || first.length > second.length) return false;
  for (let index = 0; index < first.length; index++) { charge(); if (first[index] !== second[index]) return false; }
  return true;
}

/** Exact source parameter families, not equality across separate invocations.
 * Only raw scalar entry inputs and constants qualify. Repeated key inputs keep
 * their role, while canonical ledger declaration identities remain unchanged. */
function keyPattern(facts: AnalysisFacts, entry: string, operation: RuntimeOperation, charge: Charge): KeyPattern | undefined {
  const region = operation.args[0]?.region;
  charge();
  if (!region || !operation.args[1]) return;
  charge(0, 4);
  const parameters: string[] = [];
  const roles = new Map<string, number>();
  const key = (value: AbstractValue): string | undefined => {
    charge();
    const flow = value.flows.length === 1 ? value.flows[0] : undefined;
    const source = flow?.form === "raw" && flow.source.kind === "entry-parameter" && flow.source.id === value.identity ? flow.source : undefined;
    if (source?.symbol && !value.ledger.size && !value.fields && !value.items
      && !value.numericExpression && !value.comparison && !value.ordering && !value.negated) {
      let supplied = false;
      for (const parameter of facts.program.functions.get(entry)!.declaration.parameters) {
        charge();
        if (parameter.symbol === source.symbol) { supplied = true; break; }
      }
      if (!supplied) return;
      let role = roles.get(source.symbol);
      if (role === undefined) {
        charge(0, 2); role = parameters.length;
        roles.set(source.symbol, role); parameters.push(source.symbol);
      }
      // Keep the established numeric role encoding, including represented type.
      const type = facts.program.representationOf(facts.program.symbols.get(source.symbol)!.type);
      const units = 6 * (textUnits(type, charge) + 2);
      charge(units, units);
      return JSON.stringify(["parameter", role, type]);
    }
    if (!value.flows.length && !value.ledger.size && value.constant !== undefined && value.constantKind) {
      const units = 6 * (textUnits(value.constant, charge) + textUnits(value.constantKind, charge) + 1);
      charge(units, units);
      return JSON.stringify(["constant", value.constantKind, value.constant]);
    }
    return;
  };
  const selectors = new Map<number, AbstractValue>();
  for (const selector of region.collectionSelectors ?? []) { charge(1, 1); selectors.set(selector.index, selector.value); }
  const parts: string[] = [];
  for (const [index, part] of region.path.entries()) {
    charge();
    if (part === "key:*") return;
    const selector = selectors.get(index);
    if (selector) { const selected = key(selector); if (!selected) return; charge(0, 1); parts.push(selected); }
    else if (part.startsWith("key:")) return;
    else { charge(0, 1); parts.push(part); }
  }
  const selected = key(operation.args[1]);
  if (!selected) return;
  charge(0, 1); parts.push(selected);
  charge(0, 2);
  const signatureParts = [region.root];
  for (const part of parts) { charge(1, 1); signatureParts.push(part); }
  // A flat serialization preserves the root+ordered-parts relation; it is only
  // observer-local identity, not a user type or externally stored identifier.
  return { root: region.root, parts, parameters, signature: serialize(signatureParts, charge) };
}

function complete(facts: AnalysisFacts, entry: string, charge: Charge): void {
  let completed = false;
  for (const observed of facts.completedEntries) { charge(); if (observed === entry) { completed = true; break; } }
  if (!facts.mapDebitEvidence || facts.mapDebitEvidence.entry !== entry || !facts.collectionEvidence
    || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all"
    || !completed || facts.diagnostics.length)
    throw new Error("Complete exact getter/debit entry histories are unavailable");
}

/** The full getter history may only select this exact lookup chain. Each absent
 * prefix needs a successful explicit numeric-zero return, and a present history
 * must return the immutable numeric lookup. Unrelated gates donate no evidence. */
export function zeroDefaultGetterCertificate(facts: AnalysisFacts, entry: string): ZeroDefaultGetter | undefined {
  let work = 0, values = 0;
  const charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (!facts.mapDebitEvidence || facts.metrics.steps + work > facts.mapDebitEvidence.maxSteps
      || facts.metrics.abstractValues + values > facts.mapDebitEvidence.maxValues) throw new Error("Getter certificate exhausted its shared work/value allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  try {
    complete(facts, entry, charge);
    charge(0, 2);
    const paths: SuccessfulPath[] = [];
    for (const path of facts.paths) { charge(); if (path.entry === entry) { charge(0, 1); paths.push(path); } }
    let target: KeyPattern | undefined, location: Span | undefined;
    const zeroPaths = new Set<SuccessfulPath>();
    for (const path of paths) {
      charge();
      if (path.writes.length || !path.predicates || !path.operations) return;
      let returned: SuccessfulPath["sinks"][number] | undefined;
      for (const sink of path.sinks) {
        charge();
        if (sink.kind === "exported-return") { if (returned) return; returned = sink; }
      }
      if (!returned) return;
      const result = returned.value;
      if (result.constantKind === "integer" && result.constant === "0" && !result.numericExpression && !result.mapDebitLookupOrigin) {
        charge(0, 1); zeroPaths.add(path); continue;
      }
      let lookup: RuntimeOperation | undefined;
      for (const operation of path.operations) {
        charge();
        if (operation.kind === "map-lookup" && operation.result.mapDebitLookupOrigin
          && operation.result.mapDebitLookupOrigin === result.mapDebitLookupOrigin && operation.result.identity === result.identity) {
          lookup = operation; break;
        }
      }
      if (!lookup) return;
      const pattern = keyPattern(facts, entry, lookup, charge);
      if (!pattern || target && (target.signature !== pattern.signature
        || !sameParameters(target.parameters, pattern.parameters, charge))) return;
      charge(0, 2); target = pattern; location = returned.location;
    }
    if (!target || !location || !zeroPaths.size) return;
    charge(0, 3);
    const prefixes = new Set<string>(), prefixParts = [target.root];
    for (const part of target.parts) {
      charge(1, 1); prefixParts.push(part);
      const prefix = serialize(prefixParts, charge);
      charge(0, 1); prefixes.add(prefix);
    }
    // Alpha-renaming relates different exported parameter families only. Within
    // this getter, every prefix must use the actual parameters of the returned
    // lookup chain; member(otherKey) cannot donate lookup(actualKey) evidence.
    const sameGetterPrefix = (pattern: KeyPattern) => {
      charge(textUnits(pattern.signature, charge));
      return prefixes.has(pattern.signature) && sameParameters(pattern.parameters, target!.parameters, charge, true);
    };
    charge(0, 1);
    const absent = new Map<string, Span>();
    for (const path of paths) {
      charge(1, 1);
      const isZero = zeroPaths.has(path);
      const required = new Map<string, Span>();
      for (const operation of path.operations!) {
        charge();
        if (operation.kind !== "map-lookup" && operation.kind !== "collection-query" || operation.name !== "lookup" && operation.name !== "member") return;
        const pattern = keyPattern(facts, entry, operation, charge);
        if (!pattern || !sameGetterPrefix(pattern)) return;
      }
      for (const predicate of path.predicates!) {
        charge();
        const membershipOnly = (value: AbstractValue, depth = 0): boolean => {
          charge();
          if (depth > 64) throw new Error("Getter predicate traversal exceeds its depth allowance");
          if (value.predicateStructureLost) return false;
          if (value.negated) return membershipOnly(value.negated, depth + 1);
          if (value.collectionPredicate) return true;
          if (value.predicateAlternatives) {
            for (const part of value.predicateAlternatives) if (!membershipOnly(part, depth + 1)) return false;
            return true;
          }
          if (value.comparison) {
            const { left, right } = value.comparison;
            if (right.constantKind === "boolean" && right.constant !== undefined && membershipOnly(left, depth + 1)) return true;
            return left.constantKind === "boolean" && left.constant !== undefined && membershipOnly(right, depth + 1);
          }
          return value.constantKind === "boolean" && value.constant !== undefined && !value.ordering;
        };
        if (!membershipOnly(predicate.value)) return;
        const projected = projectEnforcedEqualities(predicate.value, predicate.truth, () => undefined, charge, (value, truth) => {
          let query: RuntimeOperation | undefined;
          for (const operation of path.operations!) {
            charge();
            if (operation.kind === "collection-query" && operation.result.identity === value.identity) { query = operation; break; }
          }
          if (!query || value.collectionPredicate?.empty) return undefined;
          const pattern = keyPattern(facts, entry, query, charge);
          if (!pattern || !sameGetterPrefix(pattern)) return undefined;
          charge(0, truth ? 1 : 3);
          return truth ? [] : [{ key: pattern.signature, value: predicate.location }];
        });
        if (!projected) return;
        for (const [key, span] of projected.required) { charge(1, 1); required.set(key, span); }
      }
      if (isZero && !required.size || !isZero && required.size) return;
      for (const [key, span] of required) { charge(1, 1); absent.set(key, span); }
    }
    for (const prefix of prefixes) { charge(textUnits(prefix, charge)); if (!absent.has(prefix)) return; }
    charge(0, 1);
    const absences: Span[] = [];
    for (const span of absent.values()) { charge(1, 1); absences.push(span); }
    charge(1, 6);
    return { entry, pattern: target, location, absences, histories: paths.length };
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
}

export function zeroDefaultObservations(facts: AnalysisFacts) {
  const observations: { getter: ZeroDefaultGetter; entry: string; amount: string; location: Span; lookup: RuntimeOperation; write: RuntimeOperation;
    parameters: string[]; initialRequirements: Span[]; zeroSuccesses: number }[] = [];
  const diagnostics: Diagnostic[] = [];
  if (!facts.zeroDefaultEvidence || !facts.zeroEntry) return { observations, diagnostics };
  const entry = facts.zeroEntry.entry, amount = facts.zeroEntry.parameter;
  let work = 0, values = 0;
  const charge = (units = 1, retained = 0) => {
    work += units; values += retained;
    if (facts.metrics.steps + work > facts.zeroEntry!.maxSteps || facts.metrics.abstractValues + values > facts.zeroEntry!.maxValues)
      throw new Error("Cross-entry getter/membership relation exhausted its shared work/value allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  const unavailable = (message: string): never => { throw new Error(message); };
  try {
    complete(facts, entry, charge);
    charge(0, 3);
    const paths: SuccessfulPath[] = [];
    for (const path of facts.paths) { charge(); if (path.entry === entry) { charge(0, 1); paths.push(path); } }
    if (!paths.length) {
      if (directZeroRejection(facts)) return { observations, diagnostics };
      unavailable("No full successful zero invocation or qualified explicit zero-rejection control is available");
    }
    type Candidate = { debit: Debit; pattern: KeyPattern; required: ReturnType<typeof initialMapRequirements>; cell: string; chain: Span[] };
    const histories: Candidate[][] = [];
    for (const path of paths) {
      charge(1, 2);
      const history: Candidate[] = [];
      histories.push(history);
      for (const debit of exactMapDebits(facts, path, amount, charge, () => { charge(0, 5); }, false)) {
        const pattern = keyPattern(facts, entry, debit.lookup, charge);
        if (!pattern) continue;
        let matched = false;
        for (const getter of facts.zeroDefaultEvidence.getters) { charge(textUnits(pattern.signature, charge)); if (getter.pattern.signature === pattern.signature) { matched = true; break; } }
        if (!matched) continue;
        const member = debit.lookup.membership!;
        const required = initialMapRequirements(facts, path, member.region.root, charge, unavailable);
        charge(0, 3);
        const selectedParts = [member.region.root], chain: Span[] = [];
        let cell = "";
        // Exact raw region operands, not normalized parameter-family roles,
        // select supporting outer-to-inner requirements for this lookup only.
        for (let index = 0; index <= member.region.path.length; index++) {
          charge(index === member.region.path.length ? textUnits(member.key!, charge) : 1,
            index === member.region.path.length ? textUnits(member.key!, charge) + 1 : 1);
          const part = index === member.region.path.length ? `key:${member.key}` : member.region.path[index];
          selectedParts.push(part);
          cell = serialize(selectedParts, charge);
          if (part.startsWith("key:")) {
            charge(textUnits(cell, charge));
            const requirement = required.get(cell);
            if (requirement) { charge(0, 1); chain.push(requirement.location); }
          }
        }
        charge(0, 7); history.push({ debit, pattern, required, cell, chain });
      }
    }
    charge(0, 1);
    const seen = new Set<string>();
    for (const candidate of histories[0]) {
      charge();
      if (!candidate.pattern || !candidate.required.has(candidate.cell)) continue;
      let every = true;
      for (const history of histories) {
        let matched = false;
        for (const other of history) {
          charge(textUnits(candidate.pattern.signature, charge) + textUnits(candidate.cell, charge), 2);
          if (other.pattern.signature === candidate.pattern.signature && other.cell === candidate.cell && other.required.has(other.cell)
            && spanId(other.debit.write.location) === spanId(candidate.debit.write.location)) { matched = true; break; }
        }
        if (!matched) { every = false; break; }
      }
      if (!every) continue;
      for (const getter of facts.zeroDefaultEvidence.getters) {
        charge(textUnits(candidate.pattern.signature, charge));
        if (getter.pattern.signature !== candidate.pattern.signature) continue;
        const requirement = candidate.required.get(candidate.cell)!;
        charge(0, 6);
        // Register this explicit span atom before its serialized key is metered.
        const id = serialize([getter.entry, entry, amount, candidate.cell, facts.program.spanIdentity(requirement.location)], charge);
        if (seen.has(id)) continue;
        const emission = 45 + 5 * getter.absences.length + 5 * candidate.pattern.parameters.length
          + candidate.debit.lookup.callPath.length + candidate.chain.length;
        charge(emission, emission); seen.add(id);
        observations.push({ getter, entry, amount, location: requirement.location, lookup: candidate.debit.lookup, write: candidate.debit.write,
          parameters: candidate.pattern.parameters, initialRequirements: candidate.chain, zeroSuccesses: paths.length });
      }
    }
  } catch (error) {
    observations.length = 0;
    diagnostics.push({ code: "zero-default-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: ZERO_DEFAULT_RULE, entry } });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
  return { observations, diagnostics };
}
