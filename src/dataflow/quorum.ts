import type { AbstractValue, RuntimeOperation, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { enforcedEqualities, type EnforcedEquality } from "./predicates.js";
import { enforcedSignatureResults } from "./signed-effect-input.js";
import { constantOf } from "./transfers.js";
import { nativeIdentity } from "./natives.js";
import { ECDSA_VERIFIER } from "../semantic/signed-input-targets.js";

export interface QuorumObservation {
  sequence: AbstractValue; threshold: SuccessfulPredicate; signatures: RuntimeOperation[];
  missingPairs: [number, number][]; registry: string;
}
/** Exact supplied snapshots. A wildcard region, provenance union or common
 * storage path cannot establish an operand's equality to a presented claim. */
function key(value: AbstractValue): string | undefined {
  if (value.region || value.fields || value.items || !value.type) return;
  // Unrelated large byte/nominal operands cannot expand this rule's closure.
  if (!["Boolean", "Bytes<32>", "standard-type::Secp256k1Point", "standard-type::Secp256k1Scalar"].includes(value.type)
    && !value.type.startsWith("Uint<")) return;
  if (value.identity) return JSON.stringify([value.type, value.identity]);
  const constant = constantOf(value);
  return constant && JSON.stringify([value.type, constant.kind, constant.value]);
}

/** Deliberately bounded full-shape review: 3..16 directly presented claims,
 * one exact registry revision, per-claim ECDSA outcomes, key commitments and a
 * count-versus-threshold guard. Absence is only absence of required scalar
 * inequalities; this does not certify duplicate feasibility or authorization. */
export function quorumObservations(path: SuccessfulPath, allowance: number): {
  complete: boolean; work: number; observations: QuorumObservation[];
} {
  class BudgetError extends Error {}
  let work = 0;
  const observations: QuorumObservation[] = [];
  const fail = () => ({ complete: false, work, observations: [] });
  const spend = (amount = 1) => (work += amount) <= allowance;
  if (!path.predicates || !path.operations) return fail();
  const enforced = enforcedSignatureResults(path, path.writes.length, allowance - work);
  if (!spend(enforced.work) || !enforced.complete) return fail();
  const equalities: EnforcedEquality[] = [], parents = new Map<string, string>();
  const find = (id: string): string => {
    let root = id;
    while (parents.has(root)) { if (!spend()) throw new BudgetError(); root = parents.get(root)!; }
    while (parents.has(id)) { const next = parents.get(id)!; parents.set(id, root); id = next; }
    return root;
  };
  try {
    for (const predicate of path.predicates) {
      if (!spend() || predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) return fail();
      const decoded = enforcedEqualities(predicate.value, predicate.truth);
      if (!spend(decoded.work) || !decoded.complete) return fail();
      for (const equality of decoded.equalities) {
        if (!spend()) return fail();
        equalities.push(equality);
        const a = key(equality.left), b = key(equality.right);
        if (equality.equals && a && b) { const first = find(a), second = find(b); if (first !== second) parents.set(first, second); }
      }
    }
    const constants = new Map<string, string>();
    for (const equality of equalities) for (const value of [equality.left, equality.right]) {
      if (!spend()) return fail();
      const id = key(value), constant = constantOf(value);
      if (id && constant) constants.set(find(id), JSON.stringify([constant.kind,constant.value]));
    }
    const unequal = new Set<string>();
    const pair = (a: string, b: string) => JSON.stringify([find(a), find(b)].sort());
    for (const equality of equalities) {
      if (!spend()) return fail();
      const a = key(equality.left), b = key(equality.right);
      if (!equality.equals && a && b) unequal.add(pair(a,b));
    }
    const distinct = (a: string, b: string) => unequal.has(pair(a,b))
      || constants.has(find(a)) && constants.has(find(b)) && constants.get(find(a)) !== constants.get(find(b));
    const entry = path.operations.find(operation => { if (!spend()) throw new BudgetError(); return operation.kind === "circuit-invocation" && operation.name === path.entry && operation.callPath.length === 1; });
    if (!entry) return fail();
    for (const sequence of entry.args) {
      if (!spend()) return fail();
      if (!sequence.type?.startsWith("Vector<") || !sequence.items || sequence.items.length < 3) continue;
      // Ordinary sequences do not consume this capacity or qualify as claims.
      if (!spend(sequence.items.length)) return fail();
      if (!sequence.items.every(item => {
        if (!item.fields) return false;
        const fields = Object.values(item.fields);
        if (!spend(fields.length)) throw new BudgetError();
        return fields.some(value => value.type === "standard-type::Secp256k1EcdsaSignature");
      })) continue;
      if (sequence.items.length > 16) return fail();
      const claims = sequence.items.map(item => {
        const fields = Object.values(item.fields!);
        if (!spend(fields.length * 3)) throw new BudgetError();
        const select = (type: string) => { const selected = fields.filter(value => value.type === type); return selected.length === 1 ? selected[0] : undefined; };
        return { commitment: select("Bytes<32>"), signature: select("standard-type::Secp256k1EcdsaSignature"), publicKey: select("standard-type::Secp256k1Point") };
      });
      const threshold = path.predicates.find(predicate => {
        if (!spend()) throw new BudgetError();
        const ordering = predicate.truth && predicate.value.ordering;
        if (!ordering) return false;
        const [count, limit] = ordering.operator === ">=" ? [ordering.left, ordering.right] : ordering.operator === "<=" ? [ordering.right, ordering.left] : [];
        return !!count && constantOf(count)?.value === String(claims.length) && !!limit && limit.type?.startsWith("Uint<")
          && entry.args.some(argument => { if (!spend()) throw new BudgetError(); return !!key(argument) && key(argument) === key(limit); });
      });
      if (!threshold) continue;
      const signatures: RuntimeOperation[] = [], registries: Set<string>[] = [];
      let qualifies = true;
      for (const claim of claims) {
        if (!spend()) return fail();
        const { commitment, signature, publicKey } = claim;
        if (!commitment || !signature?.fields || !publicKey || !key(commitment) || !key(publicKey)) { qualifies = false; break; }
        const signatureKey = JSON.stringify(Object.entries(signature.fields).map(([name,value]) => [name,key(value)]).sort());
        const verifier = path.operations.find(operation => {
          if (!spend()) throw new BudgetError();
          const sig = operation.args[1];
          return operation.kind === "circuit-invocation" && operation.name === ECDSA_VERIFIER && !!operation.result.identity
            && enforced.identities.has(operation.result.identity) && key(operation.args[2]) === key(publicKey)
            && operation.args[0]?.directDigest?.primitive === "keccak256" && key(operation.args[0].directDigest.input) === key(commitment)
            && !!sig?.fields && Object.values(sig.fields).every(value => !!key(value))
            && JSON.stringify(Object.entries(sig.fields).map(([name,value]) => [name,key(value)]).sort()) === signatureKey;
        });
        const bound = equalities.some(equality => {
          if (!spend()) throw new BudgetError();
          return equality.equals && [[equality.left,equality.right],[equality.right,equality.left]].some(([a,b]) => {
            const input = b.directDigest?.primitive === "persistentHash" && b.directDigest.input.items;
            return key(a) === key(commitment) && !!input && input.length === 2 && input.every((coordinate,index) =>
              !coordinate.region && coordinate.identity === nativeIdentity(index === 0 ? "secp256k1PointX" : "secp256k1PointY", [publicKey], () => "unavailable"));
          });
        });
        const registry = new Set<string>();
        for (const operation of path.operations) {
          if (!spend()) return fail();
          const receiver = operation.args[0];
          if (operation.kind === "collection-query" && operation.name === "member" && operation.result.identity
            && enforced.identities.has(operation.result.identity) && key(operation.args[1]) === key(commitment)
            && receiver?.preexistingLedger?.size && receiver.region && !receiver.region.path.length
            && receiver.type?.startsWith("standard-type::Set<") && receiver.region.revision !== undefined)
            registry.add(JSON.stringify([receiver.region.root, receiver.region.revision]));
        }
        if (!verifier || !bound || !registry.size) { qualifies = false; break; }
        signatures.push(verifier); registries.push(registry);
      }
      if (!qualifies) continue;
      const registry = [...registries[0]].find(id => registries.every(values => values.has(id)));
      if (!registry) continue;
      const identities = claims.map(claim => key(claim.commitment!)!);
      if (identities.some((id,index) => index + 1 < identities.length && !distinct(id,identities[index + 1]))) continue;
      const missingPairs: [number,number][] = [];
      for (let first = 0; first < identities.length; first++) for (let second = first + 2; second < identities.length; second++) {
        if (!spend()) return fail();
        if (!distinct(identities[first],identities[second])) missingPairs.push([first,second]);
      }
      if (missingPairs.length) observations.push({ sequence, threshold, signatures, missingPairs, registry });
    }
    return { complete: true, work, observations };
  } catch (error) { if (error instanceof BudgetError) return fail(); throw error; }
}
