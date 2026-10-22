import { nativeKeyObservations } from "../analysis/native-key.js";
import { NATIVE_KEY_RULE } from "../semantic/native-key-targets.js";
import { spanId } from "../model.js";
import { finding, type Detector } from "./types.js";
export const nativeKeyAuthenticationReview: Detector = {
  id: NATIVE_KEY_RULE, defaultEnabled: false,
  description: "Canonical prover-supplied ownPublicKey participates in a required ledger credential check",
  requires: ["all-successful-predicates", "direct-hash-inputs", "exact-effect-histories"],
  run(facts) {
    const result = nativeKeyObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(({ entry, guard, reaches }) => finding(facts, {
      detectorId: NATIVE_KEY_RULE, severity: "info", confidence: "high",
      title: "Prover-supplied native key participates in a credential check",
      message: `${facts.program.symbols.get(entry)!.name} requires canonical ownPublicKey data in a ledger equality on every modeled successful reach of the affected effect sites. The key is prover supplied and does not separately establish key control. Another secret credential can be sufficient authentication; legitimate intentional constructions can match this review observation. Transaction feasibility and an authentication bypass are not established.`,
      location: guard.predicate.location, source: guard.supplied.location, constraint: guard.predicate.location,
      trace: [{ kind: "source", label: "canonical prover-supplied key snapshot", location: guard.supplied.location }, { kind: "constraint", label: "required ledger credential equality", location: guard.predicate.location }, ...reaches.map(reach => ({ kind: "effect", label: reach.effect.name, location: reach.effect.location }))],
      callPath: guard.predicate.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "Review and document the intended key and secret-credential roles. If separate key control is required, enforce the protocol's appropriate proof of that control.",
      metadata: { entry: facts.program.symbols.get(entry)!.name, reviewRequired: true, evidence: "canonical-native-key-required-ledger-equality", credential: guard.credential, authenticationIntent: "unknown", pathFeasibility: "not-proven", confidenceScope: "static-source-relationship", affectedEffects: reaches.map(reach => reach.effect), historyEvidence: reaches.map(reach => ({ ledgerIdentity: reach.guard.ledgerIdentity })) },
    }, `${entry}:${spanId(guard.predicate.location)}`));
  },
};
