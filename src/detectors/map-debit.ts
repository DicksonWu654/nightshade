import { ReportIdentityKeys } from "../reporting/identity-keys.js";
import { mapDebitObservations } from "../dataflow/map-debit.js";
import { MAP_DEBIT_RULE } from "../semantic/map-debit-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const zeroAmountUnguardedMapDebitReview: Detector = {
  id: MAP_DEBIT_RULE, defaultEnabled: false,
  description: "Review an amount-zero successful numeric Map debit whose exact lookup has unknown prior membership",
  requires: ["entry-zero-history", "exact-map-lookup", "numeric-subtraction", "ordered-writes"],
  run(facts) {
    const report = new ReportIdentityKeys(facts.program, MAP_DEBIT_RULE, facts.program.rootSource.ast.span);
    if (!facts.mapDebitEvidence) return [];
    const result = mapDebitObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(({ entry, lookup, write, amount, zeroSuccesses }) => finding(facts, {
      detectorId: MAP_DEBIT_RULE, severity: "info", confidence: "high",
      title: "Review zero-amount Map debit lookup with unknown prior membership",
      message: "A modeled full successful invocation with the actual debit amount zero looks up this numeric Map entry while same-entry membership is unknown, subtracts that zero from the exact immutable lookup result, and writes the result to the same exact entry. Review whether this source relationship is intended.",
      location: lookup.location, source: lookup.location,
      trace: [{ kind: "source", label: "same-entry membership unknown before numeric lookup", location: lookup.location },
        { kind: "effect", label: "exact lookup result minus actual zero debit amount written to same entry", location: write.location }],
      callPath: lookup.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
      remediation: "If the debit requires an existing entry, enforce membership for this exact Map entry before the lookup; otherwise document the intended zero-amount behavior.",
      metadata: { reviewRequired: true, evidence: "successful-zero-amount-unguarded-exact-map-debit", entry: facts.program.symbols.get(entry)?.name,
        entryIdentity: entry, amountIdentity: amount ?? "literal-zero", amountMode: amount ? "entry-zero-specialization" : "literal-zero",
        mapIdentity: lookup.membership!.region.root, zeroSuccesses, membershipBeforeLookup: "unknown",
        initiallyMissing: "not-proven", lookupFailure: "not-proven", newEntry: "not-proven", pathFeasibility: "not-proven",
        deployedImpact: "not-proven" },
    }, `${entry}:${amount ?? "literal-zero"}:${lookup.membership!.region.root}:${report.key(lookup.membership!.key ?? "")}`)));
  },
};
