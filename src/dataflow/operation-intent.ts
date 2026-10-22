import type { AbstractValue, AnalysisFacts, RuntimeOperation, StateWrite, SuccessfulPredicate } from "./index.js";
import type { ResolvedOperationIntentPolicy } from "../semantic/operation-intent.js";
import { intentEqualities } from "./operation-intent-equalities.js";
import { merkleDigestKey } from "./merkle-enforcement.js";
import { constantOf } from "./transfers.js";
import { nativeIdentity } from "./natives.js";
import { ECDSA_VERIFIER } from "../semantic/signed-input-targets.js";

export interface IntentMismatch { entry: string; location: StateWrite["location"]; callPath: string[]; missing: string[]; }
export interface IntentProof { complete: boolean; work: number; values: number; mismatches: IntentMismatch[]; reason?: string; }

/** Explicit policy proof over immutable values. Provenance alone never supplies a signed leaf. */
export function operationIntentProof(facts: AnalysisFacts, policy: ResolvedOperationIntentPolicy,
  limits: { steps: number; values: number }): IntentProof {
  let work = 0, values = 0;
  const mismatches: IntentMismatch[] = [];
  const unavailable = (reason: string): never => { throw new Error(reason); };
  const spend = (steps = 1, retained = 0) => {
    work += steps; values += retained;
    if (work > limits.steps || values > limits.values) unavailable("Operation-intent proof exhausted its shared allowance");
  };
  const constant = (value: AbstractValue) => { spend(1, 1); return constantOf(value); };
  const atom = (value: AbstractValue): string => {
    spend(1,1);
    const key = merkleDigestKey(value);
    if (!key || value.region?.path.some(part => part.includes("key:"))) unavailable("Exact scalar identity is unavailable");
    return key!;
  };
  const entryLedger = (value: AbstractValue, root: string) => {
    spend(1, 1);
    return !!value.preexistingLedger?.has(root) && value.preexistingLedger.size === 1 && value.region?.root === root
      && value.region.path.length === 0 && value.region.revision === 0 && !!merkleDigestKey(value);
  };
  try {
    if (!facts.operationIntentEvidence || facts.operationIntentEvidence.entry !== policy.circuit || facts.predicateScope !== "all"
      || facts.pathSemantics !== "equivalent-states" || !facts.completedEntries.includes(policy.circuit) || facts.diagnostics.length)
      unavailable("Complete original operation-intent histories unavailable");
    spend(1, 1);
    for (const path of facts.paths) {
      spend(); if (path.entry !== policy.circuit) continue;
      if (path.checkpointOutcomes?.length) unavailable("Checkpoint-separated intent/nonce histories require unavailable atomic linkage");
      spend(0,2);
      const protectedWrites: {write: StateWrite; index: number}[] = [], nonceWrites: {write: StateWrite; index: number}[] = [];
      for (let index=0;index<path.writes.length;index++) {
        spend();const write=path.writes[index];
        if (policy.ledgers.includes(write.ledger)) {spend(0,1);protectedWrites.push({write,index});}
        if (write.ledger===policy.nonce) {spend(0,1);nonceWrites.push({write,index});}
      }
      // Even a no-effect path must not reset or consume the declared nonce outside the declared operation.
      if (!protectedWrites.length) {
        if (nonceWrites.length) { spend(1, 1); mismatches.push({ entry: path.entry, location: nonceWrites[0].write.location, callPath: nonceWrites[0].write.callPath, missing: ["nonce-written-without-protected-effect"] }); }
        continue;
      }
      if (protectedWrites.some(({write}) => { spend(); return write.region.length || write.after.items || write.after.fields; })) unavailable("Protected Cell effect is not an exact scalar write");
      const last = protectedWrites.at(-1)!.index;
      const consumption = nonceWrites.length === 1 && nonceWrites[0].index > last ? nonceWrites[0].write : undefined;
      let consumes = false;
      if (consumption) {
        spend(); const expression = consumption.after.numericExpression;
        if (!expression) {
          if (constant(consumption.after)) consumes = false;
          else unavailable("Exact nonce increment operands unavailable");
        } else if (expression.operator === "+" && expression.operands.length === 2) {
          const [first, second] = expression.operands;
          spend(0, 1); const noncePredicates: SuccessfulPredicate[] = [];
          for (const predicate of path.predicates ?? []) {
            spend(); if (predicate.writesBefore <= nonceWrites[0].index) { spend(0, 1); noncePredicates.push(predicate); }
          }
          const nonceGraph = intentEqualities(noncePredicates, spend);
          consumes = constant(second)?.kind === "integer" && constant(second)?.value === "1"
            && entryLedger(consumption.before, policy.nonce) && nonceGraph.closure(first).has(atom(consumption.before))
            && consumption.after.type === consumption.before.type;
        }
      }
      for (const {write,index} of protectedWrites) {
        spend();
        spend(0, 1); const missing = new Set<string>();
        if (!consumes) missing.add("nonce-consumption");
        if (path.writes.some(effect => { spend(); return effect.ledger === policy.controllerCommitment; })) missing.add("controller-enrollment-write");
        for(let prior=0;prior<index;prior++) {
          spend();if(path.writes[prior].ledger===policy.nonce || path.writes[prior].ledger===policy.controllerCommitment) missing.add("authorization-state-revision");
        }
        spend(0,1);const predicates:SuccessfulPredicate[]=[];
        for(const predicate of path.predicates ?? []) {
          spend();if(predicate.writesBefore<=index) {spend(0,1);predicates.push(predicate);}
        }
        const graph=intentEqualities(predicates,spend);
        const enforced = graph.enforcedBooleans;
        spend(0,1);const candidates:RuntimeOperation[]=[];
        for(let ordinal=0;ordinal<(path.operations?.length ?? 0);ordinal++) {
          spend();const operation=path.operations![ordinal];
          if(operation.kind==="circuit-invocation" && operation.name===ECDSA_VERIFIER && ordinal<graph.operationsBefore
            && operation.result.identity && enforced.has(atom(operation.result))) {spend(0,1);candidates.push(operation);}
        }
        let best: string[] | undefined;
        for (const signature of candidates) {
          spend(1, 1); const failed = new Set<string>();
          const digest = signature.args[0]?.directDigest;
          if (!digest || digest.primitive !== "keccak256" || !digest.input.fields || digest.input.items) unavailable("Exact canonical signed statement fields unavailable");
          const fields = digest!.input.fields!, pk = signature.args[2];
          if (!pk || pk.fields || pk.items || !pk.identity || pk.type !== "standard-type::Secp256k1Point") unavailable("Exact verifier key identity unavailable");
          spend(0, 11);
          const expectedCoordinates = [nativeIdentity("secp256k1PointX", [pk!], () => "unavailable"), nativeIdentity("secp256k1PointY", [pk!], () => "unavailable")];
          const selected = (name: string): AbstractValue | undefined => { spend(); return Object.hasOwn(fields,name) ? fields[name] : undefined; };
          const self = selected(policy.statement.self);
          if (!self?.kernelSelf || self.type !== "standard-type::ContractAddress") failed.add("canonical-self");
          const tag = selected(policy.statement.operation), version = selected(policy.statement.version);
          spend(0, 7);
          for (const [value, expected, label] of [[tag,policy.operation,"operation"],[version,policy.version,"version"]] as const) {
            spend(); if (!value || constant(value)?.kind !== "integer" || constant(value)?.value !== BigInt(expected).toString()) failed.add(label);
          }
          const nonce = selected(policy.statement.nonce);
          let currentNonce = false;
          if (nonce) {
            const nonceClosure = graph.closure(nonce);
            currentNonce = entryLedger(nonce, policy.nonce);
            for (const equality of graph.equalities) for (let side = 0; side < 2; side++) {
              spend(); const leaf = side === 0 ? equality.left : equality.right;
              if (entryLedger(leaf, policy.nonce) && nonceClosure.has(atom(leaf))) currentNonce = true;
            }
            if (consumption && entryLedger(consumption.before, policy.nonce) && nonceClosure.has(atom(consumption.before))) currentNonce = true;
          }
          if (!currentNonce) failed.add("current-nonce");
          const decoded = graph.equalities;
          const pointClosure = graph.closure(pk!);
          spend(0, 2); const equivalentPoints = [pk!];
          for (const equality of decoded) for (let side = 0; side < 2; side++) {
            spend(); const leaf = side === 0 ? equality.left : equality.right;
            if (leaf.type === "standard-type::Secp256k1Point" && !leaf.fields && !leaf.items && pointClosure.has(atom(leaf))) {
              spend(0, 1); equivalentPoints.push(leaf);
            }
          }
          let trustedKey = false;
          for (const equality of decoded) {
            spend(); if (!equality.equals) continue;
            spend(0, 5);
            for (const [commitment,hash] of [[equality.left,equality.right],[equality.right,equality.left]]) {
              spend(); if (!entryLedger(commitment,policy.controllerCommitment)) continue;
              const coordinates = hash.directDigest?.primitive === "persistentHash"
                && hash.directDigest.inputType === "Vector<2,standard-type::Secp256k1Base>"
                && !hash.directDigest.input.fields && hash.directDigest.input.items;
              if (!hash.directDigest && !constant(hash)) unavailable("Registered key commitment preimage unavailable");
              if (!coordinates || coordinates.length !== 2) continue;
              for (const point of equivalentPoints) {
                spend(1, 11);
                const expected = point === pk ? expectedCoordinates : [nativeIdentity("secp256k1PointX", [point], () => "unavailable"), nativeIdentity("secp256k1PointY", [point], () => "unavailable")];
                trustedKey ||= coordinates.every((coordinate, ordinal) => {
                  spend(); return !coordinate.region && coordinate.type === "standard-type::Secp256k1Base" && coordinate.identity === expected[ordinal];
                });
              }
            }
          }
          if (!trustedKey) failed.add("registered-key");
          let writeValueDeclared = false;
          for (const input of policy.inputs) {
            spend(); const value = selected(input.field);
            if (!value) { failed.add(`input:${input.field}`); continue; }
            spend(1, 1);
            if (value.fields || value.items || !merkleDigestKey(value)) unavailable("Exact declared signed input leaf unavailable");
            const closure = graph.closure(value);
            let bound = false;
            if (input.ledger) {
              bound = entryLedger(value,input.ledger);
              // Exact equality to a retained initial ledger snapshot also qualifies.
              for (const equality of decoded) for (let side=0;side<2;side++) {
                const leaf=side===0 ? equality.left : equality.right;
                spend(); if (entryLedger(leaf,input.ledger) && closure.has(atom(leaf))) bound = true;
              }
            } else {
              // Entry source identity is retained at leaves; a transformed digest's source union cannot donate binding.
              for (const flow of value.flows) {
                spend(); if (flow.source.kind === "entry-parameter" && flow.source.symbol === input.parameter && value.identity === flow.source.id) {
                  bound = true;
                }
              }
              for (const equality of decoded) for (let side=0;side<2;side++) {
                const leaf=side===0 ? equality.left : equality.right;
                for (const flow of leaf.flows) {
                spend(); if (flow.source.kind === "entry-parameter" && flow.source.symbol === input.parameter && leaf.identity === flow.source.id && closure.has(atom(leaf))) {
                  bound = true;
                }
                }
              }
            }
            if (!bound) failed.add(`input:${input.field}`);
            if (input.writeValue === write.ledger) {
              writeValueDeclared = true;
              if (!closure.has(atom(write.after))) failed.add(`write-value:${input.field}`);
            }
          }
          // Context inputs never authorize an unrelated dynamic write value.
          let constantEffect = !!constant(write.after);
          const effectExpression = write.after.numericExpression;
          if (!constantEffect && write.after.type === "Field" && effectExpression?.operator === "-" && effectExpression.operands.length === 2)
            constantEffect = atom(effectExpression.operands[0]) === atom(effectExpression.operands[1]);
          if (!writeValueDeclared && !constantEffect) failed.add("undeclared-effect-value");
          if (!best || failed.size < best.length) {spend(0,failed.size+1);best = [...failed];}
        }
        if (!candidates.length) missing.add("enforced-operation-signature");
        else for (const reason of best!) { spend(); missing.add(reason); }
        if (missing.size) { spend(1,2+missing.size); mismatches.push({ entry: path.entry, location: write.location, callPath: write.callPath, missing: [...missing] }); }
      }
    }
    return {complete:true,work,values,mismatches};
  } catch (error) { return {complete:false,work,values,mismatches:[],reason:error instanceof Error ? error.message : String(error)}; }
}
