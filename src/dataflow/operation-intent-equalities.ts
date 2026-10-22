import type { AbstractValue, SuccessfulPredicate } from "./index.js";
import { enforcedEqualities, type EnforcedEquality } from "./predicates.js";
import { intentBooleanRequirements } from "./operation-intent-booleans.js";
import { merkleDigestKey } from "./merkle-enforcement.js";

/** One bounded mandatory equality graph, shared by key, Boolean and input obligations.
 * Every temporary graph edge/key is charged before retention; provenance is never an edge. */
export function intentEqualities(predicates: readonly SuccessfulPredicate[], charge: (work: number, values: number) => void) {
  charge(0, 3);
  const equalities: EnforcedEquality[] = [], adjacent = new Map<string,Set<string>>();
  let operationsBefore = 0;
  const key = (value: AbstractValue) => { charge(1, 1); return merkleDigestKey(value); };
  const add=(a:string,b:string)=>{
    let neighbors=adjacent.get(a);
    if (!neighbors) {charge(1,2);neighbors=new Set();adjacent.set(a,neighbors);}
    charge(1,1);neighbors.add(b);
  };
  for (const predicate of predicates) {
    charge(1, 0);
    operationsBefore = Math.max(operationsBefore,predicate.operationsBefore);
    if (predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) throw new Error("Mandatory predicate structure unavailable");
    const decoded = enforcedEqualities(predicate.value,predicate.truth,(work,values)=>{charge(work,values);return true;});
    if (!decoded.complete) throw new Error("Mandatory equality decoding unavailable");
    for (const equality of decoded.equalities) {
      charge(1,1); equalities.push(equality);
      if (!equality.equals) continue;
      const first=key(equality.left),second=key(equality.right);
      if (!first || !second) throw new Error("Exact mandatory scalar identity unavailable");
      add(first,second);add(second,first);
    }
  }
  const booleans = intentBooleanRequirements(predicates, charge);
  const closure = (seed: AbstractValue): Set<string> => {
    const first=key(seed);
    if (!first) throw new Error("Exact equality seed unavailable");
    charge(0,4);const reached=new Set([first]),pending=[first];
    for(let index=0;index<pending.length;index++) for(const next of adjacent.get(pending[index]) ?? []) {
      charge(1,0);if(reached.has(next))continue;
      charge(0,2);reached.add(next);pending.push(next);
    }
    if (seed.type === "Boolean") for (const equivalent of booleans.sameValues(seed)) {
      charge(1, 1); reached.add(equivalent);
    }
    return reached;
  };
  return {equalities,closure,operationsBefore, enforcedBooleans: booleans.trueKeys()};
}
