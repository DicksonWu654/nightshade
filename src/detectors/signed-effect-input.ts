import type { Detector, Finding } from "./types.js";
import { finding, unique } from "./types.js";
import { enforcedSignatureResults, signedScalarEqualityClosure } from "../dataflow/signed-effect-input.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { hasSchnorrVerifier, schnorrVerifier } from "../semantic/signature-targets.js";
import { signedCoinInputFindings } from "./signed-coin-input.js";
import { ECDSA_VERIFIER } from "../semantic/signed-input-targets.js";
import { merkleDigestKey } from "../dataflow/merkle-enforcement.js";

export const signedEffectInput: Detector = {
  id: "signed-effect-input", defaultEnabled: false,
  description: "Review ordinary state or shielded input coin sources absent from enforced signature message dependencies",
  requires: ["successful-signature-calls", "all-predicates", "original-write-history"],
  run(facts) {
    if (!hasSchnorrVerifier(facts.program) && !facts.program.functions.has(ECDSA_VERIFIER)) return [];
    const incomplete = (code: string, message: string): Finding[] => {
      ruleObservationIssue(facts, signedEffectInput.id, code, message); return [];
    };
    if ((hasSchnorrVerifier(facts.program) && !facts.signatureEvidence) || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
      return incomplete("signed-effect-evidence-unavailable", "Signed-effect-input review requires exact signature observations, all predicates and uncompressed original successful histories");
    let allowance = 1000000;
    const results: Finding[] = signedCoinInputFindings(facts), completed = new Set(facts.completedEntries);
    if (facts.diagnostics.some(issue => issue.scope?.detectorId === signedEffectInput.id)) return [];
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      for (let index = 0; index < path.writes.length; index++) {
        if (--allowance < 0) return incomplete("signed-effect-budget", "Signed-effect-input review allowance exhausted; results are incomplete");
        const write = path.writes[index], symbol = facts.program.symbols.get(write.ledger);
        if (!symbol || write.region.length || write.after.fields || write.after.items) continue;
        const representation = facts.program.representationOf(symbol.type);
        if (!/^(Boolean|Field|Uint<|Bytes<|Cell<)/.test(representation)) continue;
        const enforcement = enforcedSignatureResults(path, index, allowance);
        allowance -= enforcement.work;
        if (!enforcement.complete) return incomplete("signed-effect-budget", "Signed-effect-input predicate closure unavailable or exhausted; results are incomplete");
        for (let operationIndex = 0; operationIndex < (path.operations?.length ?? 0); operationIndex++) {
          if (--allowance < 0) return incomplete("signed-effect-budget", "Signed-effect-input review allowance exhausted; results are incomplete");
          const signature = path.operations![operationIndex];
          if (signature.kind !== "signature-verification" || !schnorrVerifier(signature.name)
            || operationIndex >= enforcement.operationsBefore || !signature.result.identity
            || !enforcement.identities.has(signature.result.identity)) continue;
          const message = signature.args[0];
          if (!message) return incomplete("signed-effect-evidence-unavailable", "Signature message snapshot unavailable; signed-effect-input review is incomplete");
          const signed = new Set<string>();
          const signedScalars = [];
          // Traverse represented aggregate children, not aggregate provenance as equality.
          const pending = [message], visited = new Set<object>();
          while (pending.length) {
            if (--allowance < 0) return incomplete("signed-effect-budget", "Signed message dependency allowance exhausted; results are incomplete");
            const value = pending.pop()!;
            if (visited.has(value)) continue; visited.add(value);
            if (!value.items && !value.fields) signedScalars.push(value);
            for (const flow of value.flows) { if (--allowance < 0) return incomplete("signed-effect-budget", "Signed message dependency allowance exhausted; results are incomplete"); signed.add(flow.source.id); }
            pending.push(...value.items ?? [], ...Object.values(value.fields ?? {}));
          }
          const binding = signedScalarEqualityClosure(path, index, signedScalars, allowance);
          allowance -= binding.work;
          if (!binding.complete) return incomplete("signed-effect-budget", "Signed scalar binding closure unavailable or exhausted; review is incomplete");
          const effectKey = merkleDigestKey(write.after);
          for (const flow of write.after.flows) {
            if (--allowance < 0) return incomplete("signed-effect-budget", "Effect dependency allowance exhausted; results are incomplete");
            const source = flow.source;
            if (signed.has(source.id) || write.after.identity === source.id && !!effectKey && binding.keys.has(effectKey)) continue;
            const entry = facts.program.symbols.get(path.entry)!.name;
            results.push(finding(facts, {
              detectorId: signedEffectInput.id, severity: "low", confidence: "medium",
              title: "Effect input not among signed message dependencies",
              message: `${entry} enforces a canonical jubjubSchnorrVerify result before writing ${symbol.name}, whose value derives from ${source.name}. This effect input is not among signed message dependencies in this modeled successful history. Review application intent: other trusted guards may authorize this input, and this observation does not establish sole authorization or exploitability.`,
              location: write.location, source: source.location, constraint: signature.location,
              trace: [{ kind: "call", label: "Enforced canonical signature", location: signature.location }, ...flow.trace],
              callPath: write.callPath.map(id => facts.program.symbols.get(id)!.name),
              remediation: "Review whether the signer should approve this effect input. If so, include it in the signed message; otherwise document the independent authorization or intended freedom.",
              metadata: { reviewRequired: true, entry, source: source.name, sourceKind: source.kind, ledger: symbol.name,
                evidence: "effect input not among signed message dependencies", pathFeasibility: "not-proven", soleAuthorization: false },
            }, `${path.entry}:${source.id}:${signature.location.start}`));
          }
        }
      }
    }
    return unique(results);
  },
};
