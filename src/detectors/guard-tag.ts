import { guardTagObservations, GUARD_TAG_RULE } from "../analysis/guard-tags.js";
import { spanId } from "../model.js";
import { finding, type Detector } from "./types.js";

export const publiclyDerivedGuardTag: Detector = {
  id: GUARD_TAG_RULE,
  description: "A supplied tag is required equal to a hash derived from preexisting public ledger data and caller-supplied inputs before an effect",
  defaultEnabled: false,
  requires: ["direct-hash-inputs", "all-successful-predicates", "exact-effect-histories"],
  run(facts) {
    const result = guardTagObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(({ entry, guard, reaches }) => {
      const entryName = facts.program.symbols.get(entry)!.name;
      const effects = [...new Map(reaches.map(reach => [JSON.stringify([reach.effect.kind, spanId(reach.effect.location), reach.effect.callPath, reach.effect.callSites.map(spanId), reach.effect.occurrence]), reach.effect])).values()];
      const names = (ids: string[]) => ids.map(id => facts.program.symbols.get(id)!.name);
      return finding(facts, {
        detectorId: GUARD_TAG_RULE, severity: "medium", confidence: "high",
        title: "Required guard tag is derived from ledger data and supplied inputs",
        message: `${entryName} requires a supplied tag to equal a ${guard.recipe.primitive} recipe containing definite preexisting public ledger data and only constants or unchanged caller-supplied input leaves before every modeled successful reach of ${effects.length} effect site(s). This relation alone does not verify a trusted signer or secret possession. Caller inputs are known to their supplier, but are not necessarily public. Other authentication proofs may apply; checksums and mock attestations can be intentional.`,
        location: guard.predicate.location, source: guard.supplied.location,
        trace: [{ kind: "source", label: "raw supplied tag", location: guard.supplied.location },
          { kind: "constraint", label: "required ledger/input-derived hash equality", location: guard.predicate.location },
          ...effects.map(effect => ({ kind: "sink", label: `${effect.kind} ${effect.name}`, location: effect.location }))],
        callPath: names(guard.predicate.callPath),
        remediation: "If this tag is intended to authenticate an attestor, use the protocol's reviewed signature or secret-possession verification bound to the intended signer and message. Document intentional checksum or mock use; this finding does not invalidate other protocol proofs.",
        metadata: { reviewRequired: true, evidence: "required-ledger-and-supplied-input-digest", entry: entryName,
          entryIdentity: entry, soleGate: "unproven", authenticationIntent: "unknown", pathFeasibility: "not-proven",
          callerInputsPublic: "not-proven", guardPosition: "before-effect",
          affectedEffects: effects.map(effect => ({ ...effect, callIdentities: effect.callPath, callPath: names(effect.callPath) })),
          historyEvidence: reaches.map(({ path, effect, guard: match }) => ({ branches: path.path, effect,
            supplied: match.supplied, recipe: match.recipe, predicateLocation: match.predicate.location,
            predicateCallPath: match.predicate.callPath, predicateCallSites: match.predicate.callSites,
            writesBefore: match.predicate.writesBefore, operationsBefore: match.predicate.operationsBefore })) },
      }, `${entry}:${spanId(guard.predicate.location)}`);
    });
  },
};
