import type { Detector, Finding } from "./types.js";
import { finding, unique } from "./types.js";
import { enforcedEqualities } from "../dataflow/predicates.js";
import { identityBinding, identityInputs } from "../dataflow/split-identity.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { spanId } from "../model.js";
import { nativeHashScope } from "../semantic/hash-targets.js";

export const splitWitnessIdentity: Detector = {
  id: "split-witness-identity", defaultEnabled: false,
  description: "Ledger-bound witness digest and mutation operand use independently supplied witness snapshots without mandatory equality binding",
  requires: ["all-predicates", "digest-inputs", "collection-operations", "original-write-history"],
  run(facts) {
    if (!facts.program.entries.some(entry => {
      if (facts.program.functions.get(entry)!.symbol.kind === "constructor") return false;
      const scope = nativeHashScope(facts.program, entry);
      return !scope.complete || scope.applicable;
    })) return [];
    const incomplete = (message: string): Finding[] => { ruleObservationIssue(facts, splitWitnessIdentity.id, "split-identity-evidence-unavailable", message); return []; };
    if (!facts.digestEvidence || !facts.collectionEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
      return incomplete("Split identity review requires exact native digest inputs, collection operands and all uncompressed successful predicates");
    let allowance = 1_000_000;
    const findings: Finding[] = [], completed = new Set(facts.completedEntries);
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      if (!path.predicates) return incomplete("Successful predicate snapshots unavailable for split identity review");
      for (const predicate of path.predicates) {
        if (--allowance < 0 || predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) return incomplete("Predicate structure unavailable or bounded split identity allowance exhausted");
        const decoded = enforcedEqualities(predicate.value, predicate.truth); allowance -= decoded.work;
        if (!decoded.complete || allowance < 0) return incomplete("Split identity predicate decoding exhausted its allowance");
        for (const equality of decoded.equalities) for (const [guard, ledger] of [[equality.left, equality.right], [equality.right, equality.left]]) {
          if (--allowance < 0) return incomplete("Split identity review exhausted its allowance");
          if (!equality.equals || !guard.directDigest || !ledger.preexistingLedger?.size) continue;
          const inputs = identityInputs(guard, allowance); allowance -= inputs.work;
          if (!inputs.complete) return incomplete("Guard identity input snapshots exhausted their allowance");
          if (!inputs.leaves.length) continue;
          const binding = identityBinding(path, [guard, ...inputs.leaves], allowance); allowance -= binding.work;
          if (!binding.complete) return incomplete("Mandatory identity binding unavailable or exhausted");
          for (let index = 0; index < (path.operations?.length ?? 0); index++) {
            if (--allowance < 0) return incomplete("Split identity effect review exhausted its allowance");
            const effect = path.operations![index];
            // Collection key is an exact resolved transfer operand, not a wildcard
            // write path or arbitrary value taint. Native operands are snapshots.
            const operands = effect.kind === "collection-write" && ["insert", "insertDefault", "insertCoin", "remove"].includes(effect.name) ? effect.args.slice(1,2)
              : effect.kind === "kernel-write" ? effect.args.filter(value => value.type === guard.type && !value.fields && !value.items) : [];
            for (const operand of operands) {
              const effectInputs = identityInputs(operand, allowance); allowance -= effectInputs.work;
              if (!effectInputs.complete) return incomplete("Effect identity input snapshots exhausted their allowance");
              if (!effectInputs.leaves.length || binding.bound(operand) || effectInputs.leaves.every(binding.bound)) continue;
              // Report only fully independent supplied identities. Mixed inputs
              // require a richer relation and do not establish this contract.
              if (effectInputs.leaves.some(binding.bound)) continue;
              const entry = facts.program.symbols.get(path.entry)!.name;
              findings.push(finding(facts, {
                detectorId: splitWitnessIdentity.id, severity: "low", confidence: "high",
                title: "Guard and mutation use independent witness identities",
                message: `${entry} enforces a native digest of supplied witness snapshots against preexisting ledger data and performs ${effect.name} with an independently supplied witness operand. No mandatory scalar equality binds the observed digest/inputs to this operand/inputs in this successful history. Review whether the identities should agree; authentication intent, sole authorization, feasibility and exploitability are unproven.`,
                location: effect.location, source: effectInputs.leaves[0].flows.find(flow => flow.source.id === effectInputs.leaves[0].identity)!.source.location, constraint: predicate.location,
                trace: [{ kind: "constraint", label: "Ledger-bound witness digest", location: predicate.location }, { kind: "effect", label: "Independent supplied mutation operand", location: effect.location }],
                callPath: effect.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
                remediation: "If the effect must act for the checked identity, reuse one identity snapshot or enforce the required identity equality across the composed helpers. Document intentionally independent operands.",
                metadata: { reviewRequired: true, entry, evidence: "independent-witness-snapshots-without-mandatory-scalar-binding", effectKind: effect.kind, effectName: effect.name,
                  guardSources: inputs.leaves.map(value => value.flows.find(flow => flow.source.id === value.identity)!.source.name), effectSources: effectInputs.leaves.map(value => value.flows.find(flow => flow.source.id === value.identity)!.source.name),
                  guardCallSites: predicate.callSites, effectCallSites: effect.callSites, soleAuthorization: false, authenticationIntent: "unknown", pathFeasibility: "not-proven", confidenceScope: "static-snapshot-relationship" },
              }, `${path.entry}:${spanId(predicate.location)}:${spanId(effect.location)}:${effect.callSites?.map(spanId).join(":")}`));
            }
          }
        }
      }
    }
    return unique(findings);
  },
};
