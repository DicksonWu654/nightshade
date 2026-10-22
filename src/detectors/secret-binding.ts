import { secretBindingComparisons } from "../dataflow/secret-binding.js";
import { SECRET_BINDING_RULE } from "../semantic/secret-binding.js";
import { finding, type Detector } from "./types.js";

export const secretBindingDivergenceReview: Detector = {
  id: SECRET_BINDING_RULE, defaultEnabled: false,
  description: "Same-key ledger writers enforce different domain-qualified secret-binding declaration families",
  requires: ["secret-binding-histories", "successful-predicates", "digest-inputs", "state-writes", "completed-entries"],
  run(facts) {
    const name = (id: string) => facts.program.symbols.get(id)?.name ?? id;
    return secretBindingComparisons(facts).map(({ weaker, peer, base, additional }) => finding(facts, {
      detectorId: SECRET_BINDING_RULE, severity: "info", confidence: "high",
      title: "Keyed writers enforce different secret-binding families",
      message: `${name(weaker.entry)} mutates ${name(weaker.write.ledger)} at its own affected key, bound to ${name(base.descriptor.trustedLedger)} by a private domain-qualified preimage. ${name(peer.entry)} binds its own affected key to that declaration family and an additional ${name(additional.descriptor.witness)} preimage against ${name(additional.descriptor.trustedLedger)}. The compared history lacks that additional declaration-family binding. No equality of values across entries is established. Review whether this source difference is intended.`,
      location: weaker.write.location, constraint: additional.predicate.location, source: additional.source.location,
      trace: [{ kind: "constraint", label: "shared base binding family", location: base.predicate.location },
        { kind: "constraint", label: "sibling additional binding family", location: additional.predicate.location },
        { kind: "effect", label: "sibling same-key mutation occurrence", location: peer.write.location },
        ...((weaker.write.callSites ?? []).slice(1).map(location => ({ kind: "call", label: "compared mutation invocation", location }))),
        { kind: "effect", label: "writer without additional binding", location: weaker.write.location }],
      callPath: weaker.write.callPath.map(name),
      remediation: "Review the operation-specific secret-binding policy. If this difference is intended, retain and document it; if both operations need the same bindings, enforce those bindings on their successful histories.",
      metadata: { reviewRequired: true, authenticationIntent: "unknown", authenticationStrength: "not-compared",
        pathFeasibility: "not-proven", applicationImpact: "not-inferred", crossEntryValueEquality: "not-inferred",
        entry: name(weaker.entry), sibling: name(peer.entry), target: name(weaker.write.ledger),
        baseBinding: base.descriptor, additionalBinding: additional.descriptor,
        effectCallSites: weaker.write.callSites, effectOrdinal: weaker.index,
        effectKind: "keyed-numeric-mutation-occurrence", sourceComparison: "declaration-families", majorityPremise: false },
    }, JSON.stringify([weaker.entry, weaker.write.location.start, weaker.index, weaker.write.callSites?.map(site => [site.file, site.start, site.end]), additional.key])));
  },
};
