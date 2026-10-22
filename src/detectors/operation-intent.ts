import { OPERATION_INTENT_RULE } from "../semantic/operation-intent.js";
import { operationIntentProof } from "../dataflow/operation-intent.js";
import { finding, unique, type Detector } from "./types.js";

export const operationIntentPolicy: Detector = {
  id: OPERATION_INTENT_RULE, description: "A protected Cell mutation does not satisfy its declared complete operation-intent statement",
  policyRequired: true, defaultEnabled: false,
  requires: ["declared-operation-intent", "exact-signed-statement", "registered-key", "original-write-history", "canonical-self", "nonce-consumption"],
  run(facts, policies) {
    const evidence = facts.operationIntentEvidence;
    const selected = policies?.operationIntent?.filter(policy => policy.circuit === evidence?.entry) ?? [];
    if (!policies?.operationIntent?.length) return [];
    if (!evidence) {
      facts.diagnostics.push({code:"operation-intent-evidence-unavailable",message:"Exact operation-intent evidence unavailable",location:facts.program.rootSource.ast.span,
        scope:{kind:"rule",detectorId:OPERATION_INTENT_RULE,entry:policies.operationIntent[0].circuit}}); return [];
    }
    const results = [];
    const unavailable = (code: string, message: string) => facts.diagnostics.push({ code, message,
      location: facts.program.functions.get(evidence.entry)!.declaration.span,
      scope: {kind: "rule", detectorId: OPERATION_INTENT_RULE, entry: evidence.entry} });
    for (const policy of selected) {
      const proof = operationIntentProof(facts,policy,{steps:evidence.maxSteps-facts.metrics.steps,values:evidence.maxValues-facts.metrics.abstractValues});
      facts.metrics.steps += proof.work; facts.metrics.abstractValues += proof.values;
      if (!proof.complete) {
        unavailable("operation-intent-proof-unavailable",proof.reason ?? "Operation-intent proof unavailable"); return [];
      }
      const entry = facts.program.symbols.get(policy.circuit)!.name;
      for (const mismatch of proof.mismatches) results.push(finding(facts,{
        detectorId: OPERATION_INTENT_RULE, severity:"info", confidence:"high", title:"Declared operation-intent requirement not established",
        message:`The operationIntent policy for ${entry} requires one enforced registered-key signature over the declared operation, canonical self, version, current nonce and exact protected inputs, followed by nonce consumption. This original modeled successful history does not establish: ${mismatch.missing.join(", ")}. This is a static application-policy mismatch; prover exposure, exploitability and deployed impact are unproved.`,
        location:mismatch.location,trace:[{kind:"effect",label:"Protected Cell mutation",location:mismatch.location}],callPath:mismatch.callPath.map(id=>facts.program.symbols.get(id)?.name ?? id),
        remediation:"Align the actual signed statement, registered verifier key, protected write operands and nonce lifecycle with the declared policy. Revise the policy only when the application's intended authorization differs.",
        metadata:{reviewRequired:true,entry,entryIdentity:policy.circuit,evidence:"complete-operation-intent-policy-mismatch",missing:mismatch.missing,policy,impact:"not-proven",pathFeasibility:"not-proven"},
      },JSON.stringify([policy,mismatch.location,mismatch.missing])));
    }
    return unique(results);
  },
};
