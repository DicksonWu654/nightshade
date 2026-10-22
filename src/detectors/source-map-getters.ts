import { sourceMapGetterObservations } from "../dataflow/source-map-getters.js";
import { SOURCE_MAP_GETTER_RULE } from "../semantic/source-map-getters.js";
import { finding, type Detector } from "./types.js";
export const sourceClaimMapGetterReview: Detector = {
  id: SOURCE_MAP_GETTER_RULE, defaultEnabled: false, policyRequired: true,
  description: "An explicitly documented configured Map getter returns only default without reading the selected Map",
  requires: ["explicit-source-map-getter-policy", "parser-owned-adjacent-comment", "complete-original-setter-getter-histories", "complete-getter-source-closure"],
  run(facts) {
    if (!facts.sourceMapGetterEvidence) return [];
    const claim = facts.sourceMapGetterEvidence.claim;
    return sourceMapGetterObservations(facts).observations.map(observation => finding(facts, {
      detectorId: SOURCE_MAP_GETTER_RULE, severity: "info", confidence: "high", title: "Review configured Map and fixed-default getter",
      message: "The explicit configured-state getter contract matches the exact adjacent setter comment. Complete modeled successful setter histories retain an insertion of the selected original key and value into the selected native Map. Complete getter histories return only the exact default constant, and the complete resolved getter source closure does not read that Map. Review the unused configuration and fixed getter against the supplied same-key contract. A feasible nondefault configuration, cross-invocation execution, deployed behavior and impact are not established.",
      location: observation.returned, source: claim.source, constraint: observation.setter, callPath: [],
      trace: [{ kind: "state-write", label: "Surviving selected original key/value insertion", location: observation.setter }, { kind: "sink", label: "Getter returns exact default", location: observation.returned }],
      remediation: "Make the selected getter reflect the configured Map value under the explicit contract, or remove the obsolete configuration state and documentation promise.",
      metadata: { reviewRequired: true, quote: claim.quote, setterIdentity: claim.setter, getterIdentity: claim.getter, mapIdentity: claim.map,
        setterKey: claim.setterKey, setterValue: claim.setterValue, getterKey: claim.getterKey, returnedConstant: observation.constant,
        evidence: "explicit-adjacent-contract-surviving-original-insert-default-return-and-no-map-read", policyMeaning: "explicit-same-key-configured-value", nondefaultConfigurationFeasibility: "not-established", runtimeBehavior: "not-established", applicationImpact: "not-inferred" },
    }, JSON.stringify([claim.setter,claim.getter,claim.map])));
  },
};
