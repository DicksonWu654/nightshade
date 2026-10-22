import { exportedShieldedDescriptors } from "../analysis/exported-shielded-descriptor.js";
import { EXPORTED_SHIELDED_DESCRIPTOR_RULE } from "../semantic/shielded-descriptor-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const exportedShieldedDescriptor: Detector = {
  id: EXPORTED_SHIELDED_DESCRIPTOR_RULE, defaultEnabled: false,
  description: "Canonical shielded coin descriptor fields have an unchanged source route to an exported result",
  requires: ["resolved-source", "canonical-stdlib-calls", "resolved-types"],
  run(facts) {
    const result = exportedShieldedDescriptors(facts.program);
    facts.metrics.steps += result.work;
    for (const failure of result.failures) facts.diagnostics.push({ code: "shielded-descriptor-provenance-unavailable",
      message: `${failure.reason}; exported shielded descriptor review is incomplete`,
      location: facts.program.functions.get(failure.entry)!.declaration.span,
      scope: { kind: "rule", detectorId: EXPORTED_SHIELDED_DESCRIPTOR_RULE, entry: failure.entry } });
    return unique(result.observations.map(item => finding(facts, {
      detectorId: EXPORTED_SHIELDED_DESCRIPTOR_RULE, severity: "info", confidence: "high",
      title: "Shielded coin descriptor fields reach an exported result",
      message: "Canonical shielded coin descriptor fields have an unchanged resolved source route to this exported result. The result is available at the Compact/application output boundary. Review whether callers should receive these fields; intentional wallet metadata APIs can match. This does not establish successful execution, public ledger publication, a secrecy-policy violation or exploitability.",
      location: item.location, source: item.origins[0].location,
      callPath: [facts.program.symbols.get(item.entry)!.name],
      trace: [{ kind: "source", label: "Canonical shielded descriptor", location: item.origins[0].location }, { kind: "sink", label: "Exported application result", location: item.location }],
      remediation: "Return only the intended application result, or document the descriptor fields and authorized recipients of this API. Apply explicit secrecy policies independently.",
      metadata: { reviewRequired: true, evidence: "canonical-descriptor-unchanged-source-route", visibility: "application-output",
        entry: item.entry, fields: [...new Set(item.origins.map(origin => origin.field))], producers: [...new Set(item.origins.map(origin => origin.producer))],
        successfulReach: "not-proven", publicLedgerPublication: "not-proven", secrecyPolicyViolation: "not-claimed", exploitability: "not-proven" },
    }, item.entry)));
  },
};
