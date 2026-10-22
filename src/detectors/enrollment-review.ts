import { enrollmentReviewObservations } from "../dataflow/enrollment-review.js";
import { STORED_ENROLLMENT_RULE } from "../semantic/enrollment-review.js";
import { finding, unique, type Detector } from "./types.js";

export const storedSchnorrKeyEnrollmentReview: Detector = {
  id: STORED_ENROLLMENT_RULE, defaultEnabled: false,
  description: "Review stored supplied Schnorr keys with enrollment and enforced canonical use lacking modeled identity rejection",
  requires: ["complete-cell-writers", "surviving-point-write", "exact-enforced-signature-outcome", "original-all-predicate-histories"],
  run(facts) {
    const result = enrollmentReviewObservations(facts); facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(item => finding(facts, {
      detectorId: STORED_ENROLLMENT_RULE, severity: "info", confidence: "high",
      title: "Stored Schnorr key lacks modeled enrollment and use identity rejection",
      message: "A complete modeled enrollment history stores an exact supplied Jubjub point in this whole persistent Cell without represented identity exclusion for the surviving point. A separate modeled history uses an unknown entry-storage snapshot of the same Cell at the canonical Schnorr verifier and enforces that exact outcome true, without represented caller or internal identity exclusion. Review the point invariant and initialization policy. Same-declaration sites do not establish equal values across transactions, a transaction sequence, identity feasibility, unsafe enrollment, sole authorization or application impact.",
      location: item.write.location, source: item.use.location,
      trace: [{ kind: "source", label: "exact supplied point", location: item.parameter.location },
        { kind: "sink", label: "surviving whole-Cell enrollment", location: item.write.location },
        { kind: "call", label: "same declared Cell snapshot at enforced canonical verifier", location: item.use.location }],
      callPath: item.write.callPath.map(id => facts.program.symbols.get(id)!.name),
      remediation: "Review identity rejection at every enrollment/replacement and at use, or establish a complete storage invariant. Review initialization, curve and subgroup policy separately. The pinned 0.35.0 and 0.35.0-rc.1 canonical verifiers reject identity internally; upgrading requires separate compatibility review.",
      metadata: { reviewRequired: true, evidence: "surviving-supplied-point-write-and-enforced-same-cell-snapshot-use", scope: "whole-persistent-jubjub-cell;raw-entry-parameter;canonical-schnorr",
        ledgerIdentity: item.write.ledger, writerEntry: item.writerEntry, useEntry: item.useEntry, writerCallSites: item.write.callSites,
        verifier: item.use.name, compilerVersion: facts.program.compilerVersion, zkirVersion: facts.program.zkirVersion,
        allWriterCoverage: "complete", dependentEntries: facts.enrollmentReviewEvidence!.entries,
        constructorEntries: facts.enrollmentReviewEvidence!.constructors, nativeTypeDefault: "JubjubPoint:identity",
        initialization: "separately-inventoried;not-a-trust-or-reachability-claim",
        writeIdentityExclusion: "not-modeled", useIdentityExclusion: "not-modeled", signatureResultEnforced: true,
        sameDeclarationOnly: true, crossTransactionEqualityProven: false, transactionSequenceProven: false,
        identityFeasibility: "not-proven", unsafeEnrollmentProven: false, curveMembershipModeled: false, subgroupMembershipModeled: false,
        soleAuthorization: false, pathFeasibility: "not-proven", applicationImpact: "not-inferred" },
    }, `${item.write.ledger}:${item.writerEntry}:${item.useEntry}:${item.use.location.start}`)));
  },
};
