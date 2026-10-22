import { contractOwnerObservations } from "../analysis/contract-owner.js";
import type { AnalysisFacts } from "../dataflow/index.js";
import type { ResolvedPolicies } from "../policies.js";
import { OZ_POLICY_REVISION } from "../semantic/openzeppelin-identities.js";
import { finding, unique, type Detector } from "./types.js";

export function unsupportedContractOwnerFindings(facts: AnalysisFacts, policies?: ResolvedPolicies, allowance = 200000,
  selectedEntries: readonly string[] = facts.program.entries) {
  const result = contractOwnerObservations(facts, policies, allowance, selectedEntries);
  facts.diagnostics.push(...result.diagnostics);
  return unique(result.observations.map(item => finding(facts, {
    detectorId: "unsupported-contract-owner", severity: "medium", confidence: "high",
    title: "Declared callable Ownable ends with a contract-address owner",
    message: "On a complete modeled successful history, the final surviving owner tag selects ContractAddress for this policy-declared callable Ownable instance. The pinned assertOnlyOwner guard explicitly rejects this arm, regardless of address bytes, while this owner value remains stored. This does not establish permanent irrecoverability, whole-contract lockout or concrete feasibility.",
    location: item.location, constraint: item.guard,
    trace: [{ kind: "state-write", label: "Final authenticated owner tag selects ContractAddress", location: item.effect },
      { kind: "constraint", label: "Pinned owner guard rejects the contract-address arm", location: item.guard }],
    callPath: item.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
    remediation: "Keep the selected callable owner in the account-identifier arm using the safe ownership-transfer circuit. Exclude deliberate authority suspension or future C2C migration staging from callableOwnable policies.",
    metadata: { owner: item.owner, entry: facts.program.symbols.get(item.entry)!.name, instance: item.instance,
      activeArm: "right", libraryRevision: OZ_POLICY_REVISION,
      evidence: "final-known-contract-owner-tag-on-successful-history", pathFeasibility: "not-proven", crossEntryCoverage: false,
      invocationSites: [item.callSites.map(site => ({ file: site.file, line: site.line, column: site.column }))] },
  }, `${item.owner}:${item.entry}`)));
}

export const unsupportedContractOwner: Detector = {
  id: "unsupported-contract-owner", defaultEnabled: false, policyRequired: true,
  description: "A declared callable pinned Ownable instance finishes with a contract-address owner rejected by its guard",
  requires: ["module-identities", "state-writes", "all-predicates", "constants", "completed-entries", "callable-ownable-policy"],
  run: unsupportedContractOwnerFindings,
};
