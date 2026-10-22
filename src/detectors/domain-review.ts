import { domainReviewObservations } from "../dataflow/domain-review.js";
import { DOMAIN_REVIEW_RULE } from "../semantic/domain-review.js";
import { finding, unique, type Detector } from "./types.js";

export const publicTwoComponentDomainReview: Detector = {
  id: DOMAIN_REVIEW_RULE, defaultEnabled: false,
  description: "Review a public two-input native digest lacking represented self binding and component default exclusion",
  requires: ["exact-native-preimage", "canonical-self-provenance", "all-successful-predicates", "scalar-entry-input-identity"],
  run(facts) {
    const result = domainReviewObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(observation => finding(facts, {
      detectorId: DOMAIN_REVIEW_RULE, severity: "info", confidence: "high",
      title: "Review public two-component digest domain",
      message: "This public ledger value is a native persistent hash of two distinct supplied Bytes<32> components. Its represented preimage contains no canonical kernel.self() value, and both default components are compatible with the supported component-only scalar equality guards on this modeled history. Review whether this composition needs an instance discriminator or a component restriction. Component roles, globally feasible defaults, instance separation and application impact are not inferred.",
      location: observation.write.location, source: observation.hash,
      trace: [...observation.components.map(component => ({ kind: "source", label: "supplied Bytes<32> component", location: component.location })),
        { kind: "transform", label: "exact persistentHash preimage", location: observation.hash },
        { kind: "sink", label: "public ledger publication", location: observation.write.location }],
      callPath: observation.write.callPath.map(id => facts.program.symbols.get(id)!.name),
      remediation: "Review the intended publication domain. If instance binding is required, include the canonical kernel.self() value in the actual preimage. Review component restrictions separately; nonzero inputs alone do not prove uniqueness or instance separation. Intentional shared identifiers can retain this composition.",
      metadata: { reviewRequired: true, evidence: "public-two-scalar-input-native-digest", scope: "two-distinct-scalar-entry-bytes32-components",
        entryIdentity: observation.entry, ledgerIdentity: observation.write.ledger, primitive: "persistentHash", hash: observation.hash,
        components: observation.components.map(component => ({ identity: component.symbol, location: component.location })),
        representedSelfBinding: "absent", componentDefaultConstraints: "compatible", globallyFeasibleDefaults: "not-proven",
        componentRoles: "not-inferred", instanceSeparation: "not-proven", applicationPolicy: "not-inferred", deployedImpact: "not-proven", pathFeasibility: "not-proven" },
    }, `${observation.entry}:${observation.write.ledger}:${observation.hash.start}`)));
  },
};
