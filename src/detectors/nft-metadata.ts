import { nftMetadataObservations } from "../analysis/nft-metadata.js";
import { NON_FUNGIBLE_TOKEN_IDENTITY, OZ_POLICY_REVISION } from "../semantic/openzeppelin-identities.js";
import type { AnalysisFacts } from "../dataflow/index.js";
import type { ResolvedPolicies } from "../policies.js";
import { finding, unique, type Detector } from "./types.js";

export function staleNftMetadataFindings(facts: AnalysisFacts, policies?: ResolvedPolicies, allowance = 200000) {
  const result = nftMetadataObservations(facts, policies, allowance);
  facts.diagnostics.push(...result.diagnostics);
  return unique(result.observations.map(item => finding(facts, {
    detectorId: "stale-nft-metadata", severity: "low", confidence: "high",
    title: "Current NFT metadata retains a payload from before burn/remint",
    message: "On a complete modeled successful history, this policy-selected current-incarnation metadata lookup returns the exact auxiliary payload stored before an authenticated same-ID NFT burn/remint. No overlapping auxiliary mutation replaces or clears that payload. The pinned NFT clears its own token URI; this finding concerns the separate application cache declared by policy.",
    location: item.location, source: item.stored, constraint: item.burn,
    trace: [{ kind: "ledger-write", label: "Old auxiliary metadata stored", location: item.stored },
      { kind: "call", label: "Authenticated NFT burn", location: item.burn },
      { kind: "call", label: "Authenticated same-ID NFT remint", location: item.remint },
      { kind: "sink", label: "Terminal current-incarnation metadata lookup", location: item.location }],
    callPath: [facts.program.symbols.get(item.consumer)!.name],
    remediation: "Clear the declared auxiliary cache on burn or supply the new incarnation's metadata before the selected consumer returns it. Exclude intentional archives from currentNftMetadata policies.",
    metadata: { libraryRevision: OZ_POLICY_REVISION, librarySha256: NON_FUNGIBLE_TOKEN_IDENTITY.hash,
      owners: item.owners, auxiliary: item.metadata, consumer: item.consumer, instance: item.instance,
      evidence: "same-history-exact-payload-preservation", pathFeasibility: "not-proven", crossEntryCoverage: false },
  }, `${item.owners}:${item.metadata}:${item.consumer}`)));
}

export const staleNftMetadata: Detector = {
  id: "stale-nft-metadata", description: "Policy-selected current NFT metadata retains an old auxiliary payload across same-history burn/remint",
  defaultEnabled: false, policyRequired: true,
  requires: ["module-identities", "collection-observations", "successful-histories", "current-incarnation-policy"],
  run: staleNftMetadataFindings,
};
