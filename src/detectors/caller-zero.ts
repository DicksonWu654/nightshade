import { callerZeroObservations } from "../dataflow/caller-zero.js";
import { CALLER_ZERO_RULE } from "../semantic/caller-zero-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const callerKeyZeroEntryReview: Detector = {
  id: CALLER_ZERO_RULE, defaultEnabled: false,
  description: "Review a surviving zero numeric Map insertion at a direct caller Bytes32 key without required initial same-key membership",
  requires: ["entry-zero-history", "exact-map-preconditions", "all-successful-predicates", "ordered-writes"],
  run(facts) {
    if (!facts.zeroEntry && !facts.callerZeroEvidence) return [];
    const result = callerZeroObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(({ entry, amount, key, operation, keyIdentity, zeroSuccesses }) => finding(facts, {
      detectorId: CALLER_ZERO_RULE, severity: "info", confidence: "high",
      title: "Caller-key numeric Map insertion survives a zero-amount invocation",
      message: "With the actual inserted amount zero, a modeled full successful invocation retains a zero-valued numeric Map write at an unchanged caller-supplied Bytes<32> key. This history has no required initial membership for that exact key and no required finite literal key domain. Review whether unrestricted zero entries are intended. Intentional zero APIs can match this source relationship.",
      location: operation.location, source: amount?.location ?? operation.location,
      trace: [{ kind: "source", label: amount ? `${amount.name} fixed to zero` : "literal zero insertion amount", location: amount?.location ?? operation.location },
        { kind: "source", label: `unchanged caller key ${key.name}`, location: key.location },
        { kind: "sink", label: "surviving numeric Map insertion", location: operation.location }],
      callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "Confirm the intended key domain and zero-entry policy. If appropriate, constrain caller keys, require existing same-key membership, or reject zero on the actual inserted amount.",
      metadata: { reviewRequired: true, evidence: "surviving-entry-zero-caller-key-map-write",
        entry: facts.program.symbols.get(entry)?.name, entryIdentity: entry, amount: amount?.name ?? "literal zero", ...(amount ? { amountIdentity: amount.symbol } : {}),
        amountMode: amount ? "entry-zero-specialization" : "literal-zero",
        key: key.name, keyIdentity, mapIdentity: operation.args[0].region!.root, zeroSuccesses,
        declaredAmount: "0", initiallyMissing: "not-proven", newEntry: "not-proven", pathFeasibility: "not-proven",
        exhaustion: "not-proven", irreclaimability: "not-proven", deployedImpact: "not-proven" },
    }, `${entry}:${amount?.symbol ?? "literal-zero"}:${key.symbol}`)));
  },
};
