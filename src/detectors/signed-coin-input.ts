import type { AnalysisFacts } from "../dataflow/index.js";
import { enforcedSignatureResults, predicatesBeforeOperation, signedMessageInputs, signedScalarEqualityClosure } from "../dataflow/signed-effect-input.js";
import { schnorrVerifier } from "../semantic/signature-targets.js";
import { ECDSA_VERIFIER, SIGNED_COIN_SEND } from "../semantic/signed-input-targets.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { merkleDigestKey } from "../dataflow/merkle-enforcement.js";
import { finding, unique, type Finding } from "./types.js";

/** Exact nonce-dependency review. Does not claim that a nonce identifies a coin,
 * that a signer is trusted, or that the protocol's serialization is injective. */
export function signedCoinInputFindings(facts: AnalysisFacts, allowance = 1000000): Finding[] {
  const rule = "signed-effect-input";
  const fail = (message: string): Finding[] => {
    ruleObservationIssue(facts, rule, "signed-coin-evidence-unavailable", `${message}; signed coin input review is incomplete`);
    return [];
  };
  if (!facts.program.functions.has(SIGNED_COIN_SEND)) return [];
  if (!facts.invocationEvidence?.includes(SIGNED_COIN_SEND)) return fail("Exact canonical send invocation snapshots unavailable");
  if (facts.program.functions.has(ECDSA_VERIFIER) && !facts.invocationEvidence?.includes(ECDSA_VERIFIER))
    return fail("Exact canonical ECDSA verification snapshots unavailable");
  const results: Finding[] = [];
  for (const path of facts.paths) {
    if (--allowance < 0) return fail("Signed coin review allowance exhausted");
    if (!facts.completedEntries.includes(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
    const operations = path.operations ?? [];
    for (const effect of operations) {
      if (--allowance < 0) return fail("Signed coin review allowance exhausted");
      if (effect.kind !== "circuit-invocation" || effect.name !== SIGNED_COIN_SEND) continue;
      allowance -= path.predicates?.length ?? 0;
      if (allowance < 0) return fail("Pre-effect predicate selection allowance exhausted");
      const before = effect.operationsBefore === undefined ? undefined : predicatesBeforeOperation(path, effect.operationsBefore);
      if (!before) return fail("Canonical send pre-effect ordering boundary unavailable");
      const nonce = effect.args[0]?.fields?.nonce;
      if (!nonce || nonce.fields || nonce.items) return fail("Exact scalar input coin nonce snapshot unavailable");
      const enforcement = enforcedSignatureResults(before, Infinity, allowance);
      allowance -= enforcement.work;
      if (!enforcement.complete) return fail("Pre-effect signature enforcement closure unavailable");
      for (let index = 0; index < effect.operationsBefore!; index++) {
        if (--allowance < 0) return fail("Signed coin review allowance exhausted");
        const signature = operations[index];
        if (!(signature.kind === "signature-verification" && schnorrVerifier(signature.name)
          || signature.kind === "circuit-invocation" && signature.name === ECDSA_VERIFIER)
          || !signature.result.identity || !enforcement.identities.has(signature.result.identity)
          || index >= enforcement.operationsBefore) continue;
        const message = signature.args[0];
        if (!message) return fail("Exact signature message unavailable");
        const signed = signedMessageInputs(message, allowance);
        allowance -= signed.work;
        if (!signed.complete) return fail("Signed message dependence allowance exhausted");
        const binding = signedScalarEqualityClosure(before, Infinity, signed.scalars, allowance);
        allowance -= binding.work;
        if (!binding.complete) return fail("Pre-effect scalar binding closure unavailable");
        const nonceKey = merkleDigestKey(nonce);
        const missing = [];
        for (const flow of nonce.flows) {
          if (--allowance < 0) return fail("Input coin dependency allowance exhausted");
          if (!signed.sources.has(flow.source.id) && !(nonce.identity === flow.source.id && !!nonceKey && binding.keys.has(nonceKey))) missing.push(flow);
        }
        if (!missing.length) continue;
        const entry = facts.program.symbols.get(path.entry)!.name;
        results.push(finding(facts, {
          detectorId: rule, severity: "low", confidence: "medium",
          title: "Input coin nonce absent from signed message dependencies",
          message: `${entry} enforces a canonical signature before sendShielded, but the input coin nonce derives from caller or witness sources absent from the signed message dependencies. Review whether the signer should select this coin. This does not prove sole authorization, coin identity, signature trust, replay or exploitability.`,
          location: effect.location, constraint: signature.location, source: missing[0].source.location,
          trace: [{ kind: "call", label: "Enforced canonical signature", location: signature.location }, { kind: "call", label: "Canonical shielded send input", location: effect.location }],
          callPath: effect.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "If approval should select the spent coin, include the protocol's full coin commitment or equivalent identity in the approved digest. Review nonce, color, value, operation, recipient and domain requirements separately.",
          metadata: { reviewRequired: true, entry, evidence: "input-coin-nonce-absent-from-signed-message-dependencies",
            effect: "sendShielded", operand: "input.nonce", signature: signature.name,
            invocationSites: effect.callSites ?? [], sources: [...new Set(missing.map(flow => flow.source.name))],
            pathFeasibility: "not-proven", soleAuthorization: false, coinIdentity: "not-claimed", protocolBinding: "not-proven" },
        }, `${path.entry}:${signature.location.file}:${signature.location.start}`));
      }
    }
  }
  return unique(results);
}
