import { uncheckedWitnessState } from "../dataflow/witness-state.js";
import { hasWitnessState } from "../semantic/witness-state-targets.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export const unconstrainedWitnessToState: Detector = {
  id: "unconstrained-witness-to-state", defaultEnabled: false,
  description: "A raw witness leaf reaches surviving ledger state without a modeled assertion using that leaf",
  requires: ["successful-predicates", "private-provenance", "state-writes", "completed-entries"],
  run(facts) {
    if (!facts.program.entries.some(entry => hasWitnessState(facts.program, entry))) return [];
    const issue = (message: string, entry?: string) => facts.diagnostics.push({ code: "witness-state-evidence-incomplete",
      message: `${message}; unchecked witness-state review is incomplete`, location: entry ? facts.program.functions.get(entry)!.declaration.span : facts.program.rootSource.ast.span });
    if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || facts.sourceQueries) {
      issue("Exact histories and full successful predicates are required"); return [];
    }
    const findings = new Map<string, Finding>();
    let work = 0;
    const charge = (amount = 1) => { if ((work += amount) > 200000) throw new Error("Witness-state review work allowance exhausted"); };
    for (const path of facts.paths) {
      if (!facts.completedEntries.includes(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      try {
        for (const { flow, write, leaf } of uncheckedWitnessState(path, charge)) {
          const entry = facts.program.symbols.get(path.entry)!.name, ledger = facts.program.symbols.get(write.ledger)!.name;
          const item = finding(facts, {
            detectorId: unconstrainedWitnessToState.id, severity: "medium", confidence: "low",
            title: "Raw witness value reaches ledger state without a value-specific assertion",
            message: `${entry} writes raw output of ${flow.source.name} into ${ledger} on a modeled successful history without an assertion depending on that witness leaf. Disclosure permits publication; it does not validate the value. An unrelated caller guard or a witness attestation about the value supplies no circuit validation. Public registration and prover-chosen metadata can be intentional; review the required application relation.`,
            location: flow.source.location, source: flow.source.location,
            trace: [...flow.trace, { kind: "effect", label: `ledger ${ledger}`, location: write.location }],
            callPath: write.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
            remediation: "If this field must represent an independently established fact, enforce the required relationship in the circuit using the exact supplied value. Document intentionally prover-chosen data. Review authorization and the adequacy of the check separately.",
            metadata: { entry, reviewRequired: true, evidence: "raw-witness-leaf-without-value-specific-assertion", pathFeasibility: "not-proven",
              affectedEffects: [{ ledger, location: write.location, region: write.region, leaf }],
              invocationSites: [flow.source.invocation], checkedRelationAdequacy: "not-proven" },
          }, path.entry + ":" + spanId(flow.source.location));
          const prior = findings.get(item.fingerprint);
          if (prior) for (const key of ["affectedEffects", "invocationSites"] as const) {
            const values = [...prior.metadata[key] as unknown[], ...item.metadata[key] as unknown[]];
            prior.metadata[key] = [...new Map(values.map(value => [JSON.stringify(value), value])).values()];
          } else findings.set(item.fingerprint, item);
        }
      } catch (error) { issue(error instanceof Error ? error.message : String(error), path.entry); }
    }
    return [...findings.values()];
  },
};
