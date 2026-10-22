import { digestNarrowings, DIGEST_NARROWING_RULE } from "../semantic/digest-narrowing.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, type Detector } from "./types.js";

export const checkedDigestNarrowing: Detector = {
  id: DIGEST_NARROWING_RULE,
  description: "A full canonical hash is range-checked by a Uint cast on its source route to a ledger write or exported return",
  defaultEnabled: false,
  requires: ["resolved-source", "canonical-stdlib-calls", "resolved-types", "local-result-uses"],
  run(facts) {
    const result = digestNarrowings(facts.program);
    if (!result.complete) {
      ruleObservationIssue(facts, DIGEST_NARROWING_RULE, "digest-narrowing-observation-budget",
        "Checked-digest source observation allowance exhausted; this rule is incomplete");
      return [];
    }
    return result.observations.map(item => finding(facts, {
      detectorId: DIGEST_NARROWING_RULE, severity: "info", confidence: "high",
      title: "Full digest cast checks its range instead of truncating",
      message: `An unchanged Bytes<32> result of canonical ${item.primitive} is cast to ${item.targetType} and used in a direct ledger assignment or exported return. Compact decodes all 32 bytes as a little-endian integer and rejects a value above ${item.maximum}; it does not select the low bits. Intentional checked conversions or work targets can match. No runtime failure, hash-output distribution, successful reach or deployed impact is established.`,
      location: item.cast, source: item.hash, callPath: [facts.program.symbols.get(item.caller)!.name],
      trace: [{ kind: "call", label: `Canonical ${item.primitive}`, location: item.hash },
        ...item.uses.map(use => ({ kind: "sink" as const, label: use.kind, location: use.location }))],
      remediation: "Retain the full digest when it is an identifier. If an integer projection is intended, select and document the exact bytes or other protocol-approved projection before conversion. Keep a deliberate full-digest range check; changing a stored encoding requires protocol and migration review.",
      metadata: { evidence: "canonical-full-digest-checked-uint-source-route", informational: true, reviewRequired: true,
        scope: "entry-referenced-source", caller: item.caller, entries: item.entries, primitive: item.primitive,
        inputType: "Bytes<32>", targetType: item.targetType, maximum: item.maximum, sourceUses: item.uses,
        compilerVersion: facts.program.compilerVersion, runtimeFailure: "not-proven", hashDistribution: "not-proven",
        successfulReach: "not-proven", deployedImpact: "not-proven" },
    }, JSON.stringify([item.caller, item.cast, item.targetType])));
  },
};
