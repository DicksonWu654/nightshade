import { hasSchnorrVerifier } from "../semantic/signature-targets.js";
import type { Detector, Finding } from "./types.js";
import { finding, unique } from "./types.js";

export const identitySignatureKey: Detector = {
  id: "identity-signature-key",
  description: "A successful history passes a known identity point to the pinned Schnorr verifier",
  requires: ["resolved-calls", "constants", "successful-signature-calls"],
  run(facts) {
    if (!facts.signatureEvidence && hasSchnorrVerifier(facts.program)) {
      facts.diagnostics.push({ code: "signature-evidence-unavailable", message: "Signature-key analysis requires successful call-operand observations; results are incomplete", location: facts.program.rootSource.ast.span });
      return [];
    }
    const results: Finding[] = [];
    for (const path of facts.paths) for (const operation of path.operations ?? []) {
      if (operation.kind !== "signature-verification") continue;
      const key = operation.args[2];
      if (key?.constantKind !== "point" || key.constant !== "JubjubPoint:identity") continue;
      const entry = facts.program.symbols.get(path.entry)!.name;
      results.push(finding(facts, {
        detectorId: identitySignatureKey.id, severity: "medium", confidence: "high",
        title: "Schnorr verification uses an identity key",
        message: `${entry} can pass the known Jubjub identity point as the verification key to the pinned jubjubSchnorrVerify on a modeled successful history. Identity keys do not supply the intended signature authentication. This is a static key-validation finding; authentication intent and concrete feasibility require review.`,
        location: operation.location,
        trace: [{ kind: "call", label: "jubjubSchnorrVerify with identity key", location: operation.location }],
        callPath: operation.callPath.map(id => facts.program.symbols.get(id)!.name),
        remediation: "Reject the identity point before verification and bind the verification key to the intended trusted signer. The pinned 0.35.0 and 0.35.0-rc.1 verifiers reject identity keys internally; upgrading requires separate compatibility review.",
        metadata: { reviewRequired: true, entry, key: "JubjubPoint:identity", verifier: operation.name,
          compilerVersion: facts.program.compilerVersion, evidence: "known-key-on-successful-history", pathFeasibility: "not-proven" },
      }, path.entry));
    }
    return unique(results);
  },
};
