import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { persistentSignatureKeySnapshot, signatureKeyIdentityExclusions } from "../dataflow/signature-key.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { ENROLLED_SIGNATURE_KEY_RULE, hasSchnorrVerifier, persistentSchnorrKeyCell, schnorrVerifier } from "../semantic/signature-targets.js";
import type { Detector, Finding } from "./types.js";
import { finding, unique } from "./types.js";

export const enrolledSignatureKeyReview: Detector = {
  id: ENROLLED_SIGNATURE_KEY_RULE, defaultEnabled: false,
  description: "Review unknown persistent Schnorr keys without modeled identity rejection",
  requires: ["successful-signature-calls", "all-predicates", "original-write-history"],
  run(facts) {
    if (!hasSchnorrVerifier(facts.program)) return [];
    const incomplete = (code: string, message: string): Finding[] => {
      ruleObservationIssue(facts, ENROLLED_SIGNATURE_KEY_RULE, code, message); return [];
    };
    if (!facts.signatureEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
      return incomplete("signature-key-review-evidence-unavailable", "Persistent signature-key review requires canonical call snapshots, all predicates and original successful histories");
    let allowance = 1000000;
    const results: Finding[] = [], completed = new Set(facts.completedEntries);
    for (const path of facts.paths) {
      if (!completed.has(path.entry)) continue;
      let exclusion: ReturnType<typeof signatureKeyIdentityExclusions> | undefined;
      for (const operation of path.operations ?? []) {
        if (--allowance < 0) return incomplete("signature-key-review-budget", "Persistent signature-key review allowance exhausted; results are incomplete");
        if (operation.kind !== "signature-verification" || !schnorrVerifier(operation.name)) continue;
        const key = operation.args[2];
        if (!key || typeof operation.signatureKeyExcludesIdentity !== "boolean")
          return incomplete("signature-key-review-evidence-unavailable", "Canonical signature-key snapshot or identity-exclusion observation is unavailable; review is incomplete");
        const root = persistentSignatureKeySnapshot(key);
        if (!root || !persistentSchnorrKeyCell(facts.program, root) || operation.signatureKeyExcludesIdentity) continue;
        if (!exclusion) {
          exclusion = signatureKeyIdentityExclusions(path, allowance, undefined, undefined, undefined, facts.program.meteringIdentity); allowance -= exclusion.work;
          if (!exclusion.complete) return incomplete("signature-key-review-predicate-unavailable", "Mandatory signature-key predicate closure is unavailable or exhausted; review is incomplete");
        }
        const snapshot = immutableOperandKey(key, Math.min(4096, allowance), undefined, undefined, facts.program.meteringIdentity); allowance -= snapshot.work;
        if (!snapshot.complete || !snapshot.key)
          return incomplete("signature-key-review-evidence-unavailable", "Persistent verification key has no bounded immutable identity; review is incomplete");
        if (exclusion.excluded.has(snapshot.key)) continue;
        const entry = facts.program.symbols.get(path.entry)!.name, ledger = facts.program.symbols.get(root)!;
        results.push(finding(facts, {
          detectorId: ENROLLED_SIGNATURE_KEY_RULE, severity: "info", confidence: "medium",
          title: "Persistent Schnorr key lacks modeled identity rejection",
          message: `${entry} passes an unknown entry-storage snapshot of ${ledger.name} to the canonical jubjubSchnorrVerify. No modeled mandatory check on this successful history excludes the identity point for that exact snapshot. Review key enrollment and application policy; validation in other transactions or trusted initialization may make this intentional. This does not establish an identity key, unsafe enrollment, curve or subgroup membership, signature enforcement, sole authorization, or concrete feasibility.`,
          location: operation.location, source: ledger.span,
          trace: [{ kind: "source", label: `Persistent key ${ledger.name}`, location: ledger.span },
            { kind: "call", label: "Canonical Schnorr verifier with unknown persistent key", location: operation.location }],
          callPath: operation.callPath.map(id => facts.program.symbols.get(id)!.name),
          remediation: "Review the intended trusted signer and reject identity keys at enrollment and verification when required. Review curve and subgroup validation separately; this rule does not model them. Pinned 0.35.0 and 0.35.0-rc.1 verifiers reject identity keys internally.",
          metadata: { reviewRequired: true, entry, ledger: ledger.name, verifier: operation.name,
            compilerVersion: facts.program.compilerVersion, evidence: "unknown-entry-storage-cell-without-modeled-identity-rejection",
            keyKnownIdentity: false, unsafeEnrollmentProven: false, curveMembershipModeled: false,
            subgroupMembershipModeled: false, signatureEnforcementProven: false, soleAuthorization: false, pathFeasibility: "not-proven" },
        }, `${path.entry}:${root}`));
      }
    }
    return unique(results);
  },
};
