import type { AbstractValue, AnalysisFacts, PrivateSource, RuntimeOperation } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { mayOverlap, regionKey } from "./regions.js";
import { directZeroRejection } from "./zero-rejection.js";
import { initialMapRequirements } from "./zero-membership.js";
import { requiredDistinctSelectors } from "./selector-proof.js";
import { CALLER_ZERO_RULE } from "../semantic/caller-zero-targets.js";
import { parseType, printType } from "../semantic/types.js";
import type { Diagnostic } from "../model.js";

export interface CallerZeroObservation { entry: string; amount?: PrivateSource; key: PrivateSource; operation: RuntimeOperation; keyIdentity: string; zeroSuccesses: number }

/** Exact origin requires immutable identity, not dependency unions or names. */
function directInput(value: AbstractValue): PrivateSource | undefined {
  if (value.flows.length !== 1 || value.ledger.size || value.fields || value.items || value.directDigest
    || value.negated || value.comparison || value.ordering) return;
  const flow = value.flows[0];
  return flow.form === "raw" && flow.source.kind === "entry-parameter" && flow.source.id === value.identity ? flow.source : undefined;
}

/** Ordinary exact snapshots select the actual inserted parameter, never a
 * helper's formal name or an arbitrary zero-inclusive arithmetic dependency. */
export function callerZeroAmountCandidates(facts: AnalysisFacts, entry: string, allowance: number): string[] {
  let work = 0, values = 0;
  const charge = () => {
    if (!Number.isSafeInteger(allowance) || ++work > allowance) throw new Error("Caller-zero candidate operand allowance exhausted");
  };
  try {
    if (!facts.completedEntries.includes(entry) || facts.diagnostics.length || !facts.collectionEvidence || facts.predicateScope !== "all"
      || facts.pathSemantics !== "equivalent-states") throw new Error("Exact ordinary insertion operands are unavailable");
    if (!facts.paths.length) throw new Error("No full successful ordinary invocation supplies candidate evidence");
    const amounts = new Set<string>();
    for (const path of facts.paths) {
      charge(); if (path.entry !== entry) continue;
      for (const operation of path.operations ?? []) {
        charge();
        if (operation.kind !== "collection-write" || operation.name !== "insert") continue;
        const type = parseType(facts.program.representationOf(operation.args[0].region?.type ?? "unknown"));
        if (type.name !== "Map" || type.args.length !== 2 || printType(type.args[0]) !== "Bytes<32>"
          || !/^(Field|Uint<\d+>)$/.test(printType(type.args[1]))) continue;
        const input = operation.args[2] && directInput(operation.args[2]);
        if (input?.symbol && facts.program.functions.get(entry)!.declaration.parameters.some(parameter => parameter.symbol === input.symbol)
          && !amounts.has(input.symbol)) {
          values++;
          if (facts.callerZeroEvidence && facts.metrics.abstractValues + values > facts.callerZeroEvidence.maxValues)
            throw new Error("Caller-zero candidate value allowance exhausted");
          amounts.add(input.symbol);
        }
      }
    }
    return [...amounts];
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
}

/** One full successful zero history suffices for this source relation. Initial
 * membership uses the same ordered proof as the explicit membership policy. */
export function callerZeroObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: CallerZeroObservation[] = [], diagnostics: Diagnostic[] = [];
  const zero = facts.zeroEntry, observed = zero ?? facts.callerZeroEvidence;
  const location = observed ? facts.program.functions.get(observed.entry)!.declaration.span : facts.program.rootSource.ast.span;
  let work = 0, values = 0;
  class Unavailable extends Error {}
  const charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (!Number.isSafeInteger(allowance) || work > allowance || observed && (facts.metrics.steps + work > observed.maxSteps || facts.metrics.abstractValues + values > observed.maxValues))
      throw new Unavailable("Caller-key zero-entry evidence exhausted its work/value allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  try {
    if (!observed || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.collectionEvidence
      || facts.diagnostics.length || !facts.completedEntries.includes(observed.entry))
      throw new Unavailable("Complete exact entry-zero histories and collection evidence are required");
    if (!facts.paths.length) {
      if (!(zero?.rejection && directZeroRejection(facts))) throw new Unavailable("No modeled full successful zero invocation; rejection is unqualified");
    }
    for (const path of facts.paths) {
      charge();
      if (path.entry !== observed.entry || !path.predicates) throw new Unavailable("Successful history lacks ordered effects or predicates");
      for (const operation of path.operations ?? []) {
        charge();
        if (operation.kind !== "collection-write" || operation.name !== "insert") continue;
        const receiver = operation.args[0]?.region, keyValue = operation.args[1], amountValue = operation.args[2];
        if (!receiver || !keyValue || !amountValue) throw new Unavailable("Map insertion lacks exact operands");
        const type = parseType(facts.program.representationOf(receiver.type));
        if (type.name !== "Map" || type.args.length !== 2 || printType(type.args[0]) !== "Bytes<32>"
          || !/^(Field|Uint<\d+>)$/.test(printType(type.args[1]))) continue;
        const amount = directInput(amountValue), key = directInput(keyValue);
        const selectedAmount = zero ? amount?.symbol === zero.parameter : !amount && !amountValue.flows.length && !amountValue.ledger.size;
        if (!selectedAmount || amountValue.constantKind !== "integer" || amountValue.constant !== "0"
          || !key || facts.program.representationOf(keyValue.type ?? "unknown") !== "Bytes<32>"
          || !facts.program.functions.get(observed.entry)!.declaration.parameters.some(parameter => parameter.symbol === key.symbol)) continue;
        if (keyValue.constant !== undefined) continue;
        const operand = immutableOperandKey(keyValue, undefined, undefined, undefined, facts.program.meteringIdentity); charge(operand.work);
        if (!operand.complete || !operand.key || receiver.path.includes("key:*")) throw new Unavailable("Map key or receiver lacks an exact immutable identity");
        const keyIdentity = `identity:${operand.key}`, cell = { ...receiver, path: [...receiver.path, `key:${keyIdentity}`] };
        const position = operation.writesBefore;
        if (position === undefined || !Number.isSafeInteger(position) || position < 0 || position >= path.writes.length)
          throw new Unavailable("Insertion lacks an exact ordered write occurrence");
        const write = path.writes[position];
        if (regionKey(cell) !== regionKey({ root: write.ledger, path: write.region, type: "unknown" }))
          throw new Unavailable("Insertion operands disagree with its retained write");
        // A may-alias write withholds persistence unless its exact operation
        // selects this same Map with a provably distinct immutable key.
        if (path.writes.slice(position + 1).some((later, offset) => {
          charge();
          if (!mayOverlap(cell, { root: later.ledger, path: later.region, type: "unknown" })) return false;
          const index = position + 1 + offset;
          const operations = (path.operations ?? []).filter(candidate => {
            charge(); return candidate.kind === "collection-write" && candidate.writesBefore === index;
          });
          if (operations.length !== 1) return true;
          const candidate = operations[0], otherReceiver = candidate.args[0]?.region, otherKey = candidate.args[1];
          if (!["insert", "remove"].includes(candidate.name) || !otherReceiver || !otherKey
            || regionKey(otherReceiver) !== regionKey(receiver)) return true;
          // Match the ordered retained write too: ancestor replacements and
          // unknown effect records cannot borrow another operation's proof.
          const otherOperand = immutableOperandKey(otherKey, undefined, undefined, undefined, facts.program.meteringIdentity); charge(otherOperand.work);
          if (!otherOperand.complete) throw new Unavailable("Later Map selector identity allowance exhausted");
          if (!otherOperand.key || regionKey({ ...otherReceiver, path: [...otherReceiver.path, `key:identity:${otherOperand.key}`] })
            !== regionKey({ root: later.ledger, path: later.region, type: "unknown" })) return true;
          return !requiredDistinctSelectors(keyValue, otherKey, path.predicates!, charge, message => { throw new Unavailable(message); });
        })) continue;
        const bounded = new Set<string>(), aliases: [string, string][] = [];
        if (keyValue.constant !== undefined) bounded.add(key.id);
        for (const predicate of path.predicates) {
          charge();
          const projected = projectEnforcedEqualities<{ bounded?: string; alias?: [string, string] }>(predicate.value, predicate.truth, equality => {
            if (!equality.equals) return [];
            const atoms: { key: string; value: { bounded?: string; alias?: [string, string] } }[] = [];
            for (const [subject, other] of [[equality.left, equality.right], [equality.right, equality.left]]) {
              const supplied = directInput(subject);
              if (!supplied) continue;
              // Different literal alternatives share a finite-domain atom.
              // Another unknown caller input alone supplies no such bound.
              if (other.constantKind && other.constant !== undefined)
                atoms.push({ key: `domain:${supplied.id}`, value: { bounded: supplied.id } });
              else {
                const alias = directInput(other);
                if (alias) atoms.push({ key: JSON.stringify(["alias", ...[supplied.id, alias.id].sort()]), value: { alias: [supplied.id, alias.id] } });
              }
            }
            return atoms;
          }, charge);
          if (!projected) throw new Unavailable("Successful key-domain predicate projection is unavailable");
          for (const atom of projected.required.values()) {
            charge(1, 1);
            if (atom.bounded) bounded.add(atom.bounded);
            if (atom.alias) aliases.push(atom.alias);
          }
        }
        let changed = true;
        while (changed) {
          changed = false;
          for (const [left, right] of aliases) {
            charge();
            if (bounded.has(left) && !bounded.has(right)) { bounded.add(right); changed = true; }
            if (bounded.has(right) && !bounded.has(left)) { bounded.add(left); changed = true; }
          }
        }
        if (bounded.has(key.id)) continue;
        const sameKey = new Set([key.id]);
        changed = true;
        while (changed) {
          changed = false;
          for (const [left, right] of aliases) {
            charge();
            if (sameKey.has(left) && !sameKey.has(right)) { charge(0, 1); sameKey.add(right); changed = true; }
            if (sameKey.has(right) && !sameKey.has(left)) { charge(0, 1); sameKey.add(left); changed = true; }
          }
        }
        const initial = initialMapRequirements(facts, path, receiver.root, charge, message => { throw new Unavailable(message); });
        if ([...initial.values()].some(requirement => { charge(); return regionKey(requirement.region) === regionKey(receiver)
          && (requirement.key === keyIdentity || [...sameKey].some(identity => { charge(); return requirement.key === `identity:id:${identity}`; })); })) continue;
        charge(1, 1);
        observations.push({ entry: observed.entry, amount, key, operation, keyIdentity, zeroSuccesses: facts.paths.length });
      }
    }
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    observations.length = 0;
    diagnostics.push({ code: "caller-zero-evidence-unavailable", message: error.message, location,
      ...(observed ? { scope: { kind: "rule" as const, detectorId: CALLER_ZERO_RULE, entry: observed.entry } } : {}) });
  }
  facts.metrics.steps += work; facts.metrics.abstractValues += values;
  return { observations, diagnostics };
}
