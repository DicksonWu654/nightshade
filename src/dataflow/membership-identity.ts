import { pathLength, identityLength } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, RuntimeOperation, StateWrite, SuccessfulPredicate } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { secretWitnessDeclaration, scalarSecretKeySource } from "../semantic/secret-binding.js";
import { MEMBERSHIP_IDENTITY_RULE, membershipIdentitySet, membershipIdentityMap, membershipIdentityList } from "../semantic/membership-identity.js";

export interface MembershipIdentityObservation {
  entry: string; groupId: string; write: StateWrite; digest: AbstractValue; member: RuntimeOperation;
  equality: SuccessfulPredicate; membership: SuccessfulPredicate; effectSites: StateWrite["location"][];
}

/** Exact scalar snapshots and required predicates in one original atomic
 * history. A public key equality is a relationship, never trusted-ledger auth. */
export function membershipIdentityObservations(facts: AnalysisFacts): MembershipIdentityObservation[] {
  const evidence = facts.secretBindingEvidence;
  let entry = evidence?.entrySteps.keys().next().value ?? facts.program.entries[0] ?? "";
  const observations: MembershipIdentityObservation[] = [];
  const charge = (work = 1, values = 0): boolean => {
    const prior = evidence?.entrySteps.get(entry);
    if (prior === undefined) throw new Error("Membership identity entry meter unavailable");
    evidence!.entrySteps.set(entry, prior + work); facts.metrics.steps += work; facts.metrics.abstractValues += values;
    if (prior + work > evidence!.maxSteps || facts.metrics.abstractValues > evidence!.maxValues)
      throw new Error("Membership identity matching exhausted its shared allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  const key = (value: AbstractValue): string | undefined => {
    charge();
    if (value.fields || value.items || value.region) return;
    const result = immutableOperandKey(value, 4096, undefined, charge);
    if (!result.complete) throw new Error("Scalar immutable snapshot identity unavailable");
    return result.key;
  };
  const witness = (value: AbstractValue): boolean => {
    charge(1 + value.flows.length);
    return facts.program.representationOf(value.type ?? "unknown") === "Bytes<32>" && !value.fields && !value.items && !value.region
      && !!value.identity && value.flows.length === 1 && value.flows[0].form === "raw"
      && value.flows[0].source.kind === "witness" && value.flows[0].source.id === value.identity
      && scalarSecretKeySource(facts.program,value.flows[0].source,charge,value.type)
      && !!secretWitnessDeclaration(facts.program,value.flows[0].source);
  };
  try {
    if (!evidence || facts.diagnostics.length || facts.predicateScope !== "all" || !facts.digestEvidence || !facts.collectionEvidence
      || facts.pathSemantics !== "equivalent-states") throw new Error("Complete original membership identity histories unavailable");
    const emitted = new Map<string, MembershipIdentityObservation>();
    const histories = new Map<MembershipIdentityObservation, Set<typeof facts.paths[number]>>(); charge(facts.completedEntries.length, facts.completedEntries.length);
    const completed = new Set(facts.completedEntries);
    for (const selected of evidence.entrySteps.keys()) { entry=selected;charge(); if (!completed.has(selected)) throw new Error("Selected history did not complete"); }
    for (const path of facts.paths) {
      entry = path.entry; charge(1, 5);
      if (!path.predicates || !path.operations) throw new Error("Predicate or collection operand history unavailable");
      const edges = new Map<string, Set<string>>();
      const digests: { value: AbstractValue; operand: AbstractValue; predicate: SuccessfulPredicate }[] = [];
      const members: { operation: RuntimeOperation; predicate: SuccessfulPredicate }[] = [];
      const queries = new Map<string, RuntimeOperation>();
      const listWrites = new Set<number>();
      for (const operation of path.operations) {
        charge();
        if (operation.kind === "collection-write" && membershipIdentityList(facts.program, operation.args[0]?.region?.type, charge)
          && ["pushFront","popFront","resetToDefault"].includes(operation.name)) {
          if (operation.writesBefore === undefined) throw new Error("Nested List mutation ordering unavailable");
          charge(0,1);listWrites.add(operation.writesBefore);
        }
        if (operation.kind !== "collection-query" || operation.name !== "member") continue;
        if (!membershipIdentitySet(facts.program,operation.args[0]?.type,charge)) continue;
        const id = operation.result.identity;
        if (!id || !operation.result.collectionPredicate) throw new Error("Exact Set membership query snapshot unavailable");
        charge(0, 2); queries.set(id, operation);
      }
      for (const predicate of path.predicates) {
        const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
          if (!equality.equals) return [];
          const a = key(equality.left), b = key(equality.right);
          if (!a || !b) return [];
          return [{ key: JSON.stringify([a,b].sort()), value: { kind: "equality" as const, a,b, left:equality.left,right:equality.right } }];
        }, charge);
        if (!projected) throw new Error("Required scalar equality projection unavailable");
        for (const atom of projected.required.values()) {
          charge(1,4);
          for (const [a,b] of [[atom.a,atom.b],[atom.b,atom.a]]) {
            const adjacent=edges.get(a)??new Set<string>(); adjacent.add(b); edges.set(a,adjacent);
          }
          for (const [value,operand] of [[atom.left,atom.right],[atom.right,atom.left]]) {
            charge();
            if (value.directDigest?.primitive === "persistentHash" && witness(value.directDigest.input)
              && facts.program.representationOf(operand.type ?? "unknown") === "Bytes<32>" && !operand.region) {
              charge(0,3); digests.push({value,operand,predicate});
            }
          }
        }
        const membership = projectEnforcedEqualities(predicate.value, predicate.truth, () => [], charge, (value, truth) => {
          if (!truth || !value.identity || !queries.has(value.identity)) return [];
          charge(0,2); return [{key:value.identity,value:queries.get(value.identity)!}];
        });
        if (!membership) throw new Error("Required Set membership projection unavailable");
        for (const operation of membership.required.values()) { charge(0,2); members.push({operation,predicate}); }
      }
      const connected = (a:string,b:string):boolean => {
        if(a===b)return true;
        charge(0,3); const pending=[a],seen=new Set([a]);
        for(let i=0;i<pending.length;i++)for(const other of edges.get(pending[i])??[]) {
          charge();if(other===b)return true;if(!seen.has(other)){charge(0,2);seen.add(other);pending.push(other);}
        }
        return false;
      };
      for(const digest of digests)for(const member of members) {
        charge();const input=member.operation.args[1];
        // Restrict to one raw supplied scalar membership input. Derived native
        // recipes require congruence logic beyond scalar equality observation.
        if(!input || !witness(input))continue;
        const a=key(digest.value), secret=key(digest.value.directDigest!.input), b=key(input), operand=key(digest.operand);
        if(!a||!b||!secret||!operand)throw new Error("Candidate scalar identity unavailable");
        if(connected(a,b)||connected(secret,b))continue;
        for(let index=0;index<path.writes.length;index++) {
          const write=path.writes[index];
          charge(1+write.region.length);
          if(!listWrites.has(index))continue;
          if(!membershipIdentityMap(facts.program,write.ledger,write.before.type,charge) || write.region.length!==1 || !write.region[0].startsWith("key:"))continue;
          if(write.region[0]==="key:*")throw new Error("Exact keyed mutation operand unavailable");
          charge(1,1+Math.ceil(identityLength(write.region[0], charge)/64));
          const target=write.region[0].startsWith("key:identity:")?write.region[0].slice(13):`constant:${write.region[0].slice(4)}`;
          if(!connected(operand,target))continue;
          charge(member.predicate.callSites.length+digest.predicate.callPath.length,8+Math.ceil((identityLength(entry, charge)+identityLength(a, charge)+identityLength(b, charge)+identityLength(member.operation.result.identity, charge)+identityLength(write.ledger, charge)+identityLength(write.region[0], charge))/64));
          const id=JSON.stringify([entry,member.predicate.location.file,member.predicate.location.start,a,b,member.operation.result.identity,write.region[0],write.ledger,member.predicate.callSites.map(site=>site.start),digest.predicate.callPath]);
          const previous = emitted.get(id);
          if(previous) {
            charge(0,1);histories.get(previous)!.add(path);
            charge(previous.effectSites.length);
            if(!previous.effectSites.some(site=>site.file===write.location.file && site.start===write.location.start)) {
              charge(0,4);previous.effectSites.push(write.location);
            }
            continue;
          }
          // Reserve report text, fingerprint source inventory and metadata.
          let units=identityLength(id, charge)+identityLength(entry, charge)+identityLength(write.ledger, charge);
          charge(facts.program.files.size*Math.max(1,Math.ceil(Math.log2(facts.program.files.size+1))),facts.program.files.size);
          for(const file of facts.program.files.keys()){charge();units+=pathLength(file, charge)+identityLength(id, charge);}
          charge(8+Math.ceil(units/64),100+Math.ceil(units/64)+write.callPath.length*4);
          const observation = {entry,groupId:id,write,digest:digest.value,member:member.operation,equality:digest.predicate,membership:member.predicate,effectSites:[write.location]};
          emitted.set(id,observation);histories.set(observation,new Set([path]));observations.push(observation);
        }
      }
    }
    return observations.filter(observation => {
      entry=observation.entry;
      // Optional membership in an alternative successful history does not
      // describe a mandatory composition at the same mutation occurrence.
      for (const path of facts.paths) {
        charge(); if(path.entry!==observation.entry || histories.get(observation)!.has(path))continue;
        for(const write of path.writes) {
          charge(observation.effectSites.length+1);
          if(write.ledger===observation.write.ledger && observation.effectSites.some(site=>site.file===write.location.file && site.start===write.location.start))return false;
        }
      }
      return true;
    });
  } catch(error) {
    facts.diagnostics.push({code:/allowance/.test(String(error))?"membership-identity-budget":"membership-identity-evidence",message:error instanceof Error?error.message:String(error),
      location:facts.program.functions.get(entry)?.declaration.span??facts.program.rootSource.ast.span,scope:{kind:"rule",detectorId:MEMBERSHIP_IDENTITY_RULE,entry}});
    return [];
  }
}
