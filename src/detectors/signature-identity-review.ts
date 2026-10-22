import { signatureIdentityObservations } from "../dataflow/signature-identity-review.js";
import { SIGNATURE_IDENTITY_REVIEW } from "../semantic/signature-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const signatureKeyIdentityExclusionReview: Detector = {
  id: SIGNATURE_IDENTITY_REVIEW, defaultEnabled: false,
  description: "Review unknown native signature keys without modeled exact identity exclusion",
  requires: ["canonical-native-verifier-operands", "complete-original-successful-histories", "typed-immutable-key-exclusion"],
  run(facts) {
    const result = signatureIdentityObservations(facts); facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(item => {
      const symbol = facts.program.symbols.get(item.source.symbol)!;
      const entry = facts.program.symbols.get(item.entry)!.name;
      return finding(facts, {
        detectorId: SIGNATURE_IDENTITY_REVIEW, severity: "info", confidence: "high",
        title: "Signature key lacks modeled identity exclusion",
        message: `${entry} passes an unknown ${item.source.kind === "caller-key" ? "caller key" : "whole persistent Cell snapshot"} to the canonical ${item.curve === "JubjubPoint" ? "Jubjub Schnorr" : "secp256k1 ECDSA"} verifier on a complete modeled successful history. No modeled mandatory caller or internal check excludes this curve's identity for that exact immutable operand. Review key validation and trusted initialization policy. This does not establish an identity key, identity feasibility, unsafe enrollment, curve or subgroup validity, signature enforcement, sole authorization or application impact.`,
        location: item.operation.location, source: symbol.span,
        trace: [{ kind: "source", label: `Exact ${item.source.kind}: ${symbol.name}`, location: symbol.span },
          { kind: "call", label: "Canonical native verifier with unknown key", location: item.operation.location }],
        callPath: item.operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: "Review exact identity rejection at verification and enrollment when required, or establish a complete trusted storage invariant. Review curve and subgroup validation separately. Pinned 0.35.0/0.35.0-rc.1 Schnorr rejection is modeled only under its supported exact profile.",
        metadata: { reviewRequired: true, entry, verifier: item.operation.name, curve: item.curve, keySource: item.source.kind,
          keySymbol: symbol.name, compilerVersion: facts.program.compilerVersion, zkirVersion: facts.program.zkirVersion,
          evidence: "complete-original-history-without-modeled-exact-key-identity-exclusion", identityExclusion: "not-modeled",
          keyKnownIdentity: false, identityFeasibility: "not-proven", unsafeEnrollmentProven: false, curveMembershipModeled: false,
          subgroupMembershipModeled: false, signatureEnforcementProven: false, soleAuthorization: false, applicationImpact: "not-inferred",
          pathFeasibility: "not-proven", fullRecordRecallCredit: false },
      }, `${item.entry}:${item.source.symbol}:${item.operation.location.file}:${item.operation.location.start}`);
    }));
  },
};
