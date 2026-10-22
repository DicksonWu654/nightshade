import type { AbstractValue, AnalysisFacts, PrivateSource, RuntimeOperation, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { immutableCollectionAddress, immutableOperandKey } from "../dataflow/immutable-key.js";
import { constantOf } from "../dataflow/transfers.js";
import { parseType } from "../semantic/types.js";
import { collectionTargets } from "../semantic/collection-targets.js";
import { spanId, type Diagnostic, type Span } from "../model.js";

export interface MembershipGuard {
  query: RuntimeOperation; predicate: SuccessfulPredicate; source: PrivateSource;
  receiver: string; member: string; revision: number; queryIndex: number;
}
export interface MembershipEffect {
  kind: "ledger-write" | "kernel-write"; name: string; location: Span;
  callPath: string[]; callSites: Span[]; index: number; occurrence: number;
}
export interface MembershipReach { path: SuccessfulPath; effect: MembershipEffect; guard: MembershipGuard }
export interface MembershipObservation { entry: string; guard: MembershipGuard; reaches: MembershipReach[] }

const fieldsAre = (value: AbstractValue, names: string[]) => !!value.fields
  && Object.keys(value.fields).length === names.length && names.every(name => name in value.fields!);

/** Only exact value-preserving native encodings. A container's dependency union
 * cannot identify its active payload, and a custom type/name cannot supply it. */
export function rawNativePublicKey(value: AbstractValue): PrivateSource | undefined {
  const bytes = (part: AbstractValue): PrivateSource | undefined => {
    if (part.type !== "Bytes<32>" || part.fields || part.items || part.constant !== undefined || part.ledger.size
      || part.flows.length !== 1) return;
    const flow = part.flows[0];
    if (flow.form === "raw" && flow.source.kind === "witness" && flow.source.symbol === "intrinsic::ownPublicKey"
      && part.identity === flow.source.id) return flow.source;
  };
  if (value.type === "Bytes<32>") return bytes(value);
  if (value.type === "standard-type::ZswapCoinPublicKey" && fieldsAre(value, ["bytes"])) return bytes(value.fields!.bytes);
  if (value.type !== "standard-type::Either<standard-type::ZswapCoinPublicKey,standard-type::ContractAddress>"
    || !fieldsAre(value, ["is_left", "left", "right"])) return;
  const { is_left: tag, left, right } = value.fields!;
  if (constantOf(tag)?.kind !== "boolean" || constantOf(tag)?.value !== "true" || tag.flows.length
    || right.type !== "standard-type::ContractAddress" || !fieldsAre(right, ["bytes"])) return;
  const inactive = right.fields!.bytes;
  if (inactive.flows.length || inactive.ledger.size || constantOf(inactive)?.kind !== "bytes"
    || constantOf(inactive)?.value !== "0".repeat(64)) return;
  return rawNativePublicKey(left);
}

/** Required direct Boolean membership atoms. Negation and literal Boolean relays
 * preserve polarity; unknown/compound alternatives supply no required atom.
 * This deliberately does not solve arbitrary Boolean equalities. */
function requiredMembers(value: AbstractValue, truth: boolean, charge: (depth?: number) => boolean,
  depth = 0): AbstractValue[] | undefined {
  if (!charge(depth)) return;
  if (value.predicateStructureLost || value.predicateAlternatives || value.predicateHasAlternatives) return [];
  if (value.negated) return requiredMembers(value.negated, !truth, charge, depth + 1);
  if (value.comparison) {
    const { left, right, operator } = value.comparison;
    if (operator !== "==" && operator !== "!=") return [];
    for (const [subject, literal] of [[left, right], [right, left]]) {
      const constant = constantOf(literal);
      if (literal.flows.length || literal.ledger.size || constant?.kind !== "boolean") continue;
      return requiredMembers(subject, (operator === "==" ? truth : !truth) === (constant.value === "true"), charge, depth + 1);
    }
    return [];
  }
  return truth && value.collectionPredicate && !value.collectionPredicate.empty && value.identity ? [value] : [];
}

/** Exact entry/history consumer. Every effect invocation is intersected before
 * guard-source grouping; no source-query witness or wildcard address is promoted
 * to universal coverage. All retained matches keep their own immutable operands. */
export function publicKeyMembershipObservations(facts: AnalysisFacts, allowance = 1_000_000) {
  const observations: MembershipObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  for (const entry of facts.completedEntries) {
    if (facts.program.symbols.get(entry)!.kind === "constructor") continue;
    const location = facts.program.functions.get(entry)!.declaration.span;
    const scope = { kind: "rule" as const, detectorId: "public-key-membership-authorization", entry };
    let complete = true, unavailable = false;
    const charge = (depth = 0) => complete &&= ++work <= allowance && depth <= 64;
    const issue = (code: string, message: string) => diagnostics.push({ code, message, location, scope });
    // Direct facts consumers need the same bounded structural absence check as
    // the isolated observation pass. No Map/Set membership means no required
    // collection evidence, even when unrelated List operations have effects.
    const target = collectionTargets(facts.program, Math.min(20000, Math.max(0, allowance - work)), [entry]);
    work += target.work;
    if (!target.complete || work > allowance) {
      issue("membership-analysis-budget", "Public-key membership applicability exhausted its bounded allowance; this entry has no complete rule result"); continue;
    }
    if (!target.applicable) continue;
    if (!facts.collectionEvidence || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
      issue("membership-evidence-unavailable", "Public-key membership review requires exact successful histories, all predicates and collection observations"); continue;
    }
    const groups = new Map<string, { path: SuccessfulPath; effect: MembershipEffect; guards: Map<string, MembershipGuard> }[]>();
    for (const path of facts.paths) {
      if (!charge()) break;
      if (path.entry !== entry) continue;
      const enforced = new Map<string, SuccessfulPredicate>();
      for (const predicate of path.predicates ?? []) {
        const atoms = requiredMembers(predicate.value, predicate.truth, charge);
        if (!atoms) break;
        for (const atom of atoms) {
          if (!charge()) break;
          // Exact query-result identity already encodes receiver/key/revision.
          // The original predicate and its actual effect position stay intact.
          if (!enforced.has(atom.identity!)) enforced.set(atom.identity!, predicate);
        }
      }
      const guards = new Map<string, MembershipGuard>();
      for (const [queryIndex, query] of (path.operations ?? []).entries()) {
        if (!charge()) break;
        if (query.kind !== "collection-query" || query.name !== "member" || !query.result.identity) continue;
        const predicate = enforced.get(query.result.identity);
        if (!predicate) continue;
        const [receiver, key] = query.args, source = key && rawNativePublicKey(key), region = receiver?.region;
        if (!source || !region || !receiver.preexistingLedger?.has(region.root)) continue;
        const type = parseType(receiver.type ?? "unknown");
        if (!["standard-type::Map", "standard-type::Set"].includes(type.name)) continue;
        const revision = query.result.collectionPredicate?.revision;
        // An old ledger-local receiver can be re-read by a live query. Retain
        // only the exact unchanged preexisting receiver revision.
        if (revision === undefined || region.revision !== revision) continue;
        if (query.writesBefore !== 0) continue;
        if (!query.callSites || query.callSites.length !== query.callPath.length
          || !predicate.callSites || predicate.callSites.length !== predicate.callPath.length
          || !source.invocation || !path.witnessCalls) { unavailable = true; break; }
        if ((path.witnessCalls.get(source.invocation.site) ?? 0) <= source.invocation.occurrence) { unavailable = true; break; }
        const address = immutableCollectionAddress(receiver, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
        work += address.work; complete &&= address.complete && work <= allowance;
        const member = immutableOperandKey(key, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
        work += member.work; complete &&= member.complete && work <= allowance;
        if (!complete) break;
        if (!address.key || !member.key) continue;
        const guard: MembershipGuard = { query, predicate, source, receiver: address.key, member: member.key, revision, queryIndex };
        const id = JSON.stringify([spanId(query.location), query.callPath, query.callSites.map(spanId),
          spanId(predicate.location), predicate.callPath, predicate.callSites.map(spanId), spanId(source.location), source.symbol, source.invocation]);
        if (!guards.has(id)) guards.set(id, guard);
      }
      if (!complete || unavailable) break;
      const effects: MembershipEffect[] = [
        ...path.writes.map((write, index) => ({ kind: "ledger-write" as const, name: facts.program.symbols.get(write.ledger)!.name,
          location: write.location, callPath: write.callPath, callSites: write.callSites!, index, occurrence: 0 })),
        ...(path.operations ?? []).flatMap((operation, index) => operation.kind === "kernel-write" ? [{ kind: "kernel-write" as const,
          name: operation.name, location: operation.location, callPath: operation.callPath, callSites: operation.callSites!, index, occurrence: 0 }] : []),
      ];
      const occurrences = new Map<string, number>();
      for (const effect of effects) {
        if (!charge()) break;
        if (!effect.callSites || effect.callSites.length !== effect.callPath.length) { unavailable = true; break; }
        const site = JSON.stringify([effect.kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId)]);
        effect.occurrence = occurrences.get(site) ?? 0; occurrences.set(site, effect.occurrence + 1);
        const id = JSON.stringify([site, effect.occurrence]);
        const reaches = groups.get(id) ?? []; reaches.push({ path, effect, guards }); groups.set(id, reaches);
      }
      if (!complete || unavailable) break;
    }
    const grouped = new Map<string, MembershipObservation>();
    for (const reaches of groups.values()) {
      if (!complete || unavailable) break;
      for (const [id, guard] of reaches[0].guards) {
        const common = reaches.every(reach => {
          if (!charge()) return false;
          const required = reach.guards.get(id);
          if (!required || required.queryIndex >= required.predicate.operationsBefore) return false;
          return reach.effect.kind === "ledger-write" ? required.predicate.writesBefore <= reach.effect.index
            : required.predicate.operationsBefore <= reach.effect.index;
        });
        if (!complete) break;
        if (!common) continue;
        const groupId = spanId(guard.predicate.location);
        const observation = grouped.get(groupId) ?? { entry, guard, reaches: [] };
        observation.reaches.push(...reaches.map(reach => ({ path: reach.path, effect: reach.effect, guard: reach.guards.get(id)! })));
        grouped.set(groupId, observation);
      }
    }
    if (!complete) issue("membership-analysis-budget", "Public-key membership operand/guard intersection exhausted its bounded allowance; this entry has no complete rule result");
    else if (unavailable) issue("membership-evidence-unavailable", "Public-key membership history is missing predicate, ordered query or effect invocation evidence");
    else observations.push(...grouped.values());
  }
  return { observations, diagnostics, work, complete: !diagnostics.length };
}
