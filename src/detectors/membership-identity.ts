import type { Detector } from "./types.js";
import { finding, unique } from "./types.js";
import { membershipIdentityObservations } from "../dataflow/membership-identity.js";
import { MEMBERSHIP_IDENTITY_RULE } from "../semantic/membership-identity.js";

export const independentMembershipIdentityReview: Detector = {
  id: MEMBERSHIP_IDENTITY_RULE, defaultEnabled: false,
  description: "Keyed mutation digest/key equality and required Set membership use independent witness snapshots",
  requires: ["all-predicates", "digest-inputs", "collection-operations", "original-write-history"],
  run(facts) {
    return unique(membershipIdentityObservations(facts).map(observation => {
      const {write,member,equality,membership}=observation;
      const entry=facts.program.symbols.get(observation.entry)?.name ?? observation.entry;
      return finding(facts, {
        detectorId: MEMBERSHIP_IDENTITY_RULE, severity: "info", confidence: "high",
        title: "Set membership and keyed mutation use independent identities",
        message: `${entry} requires a secret-derived digest to equal the exact mutation key and requires Set membership of a separate supplied witness snapshot in this successful history. No enforced scalar equality connects the observed digest or its input to the membership operand. Review whether the two identities should agree; an administrator may intentionally act for an independently checked key. This source relationship does not establish authorization failure or application impact.`,
        location: membership.location, constraint:equality.location, source:member.location,
        trace:[{kind:"constraint",label:"Required Set membership",location:membership.location},{kind:"constraint",label:"Digest equals mutation key",location:equality.location},{kind:"effect",label:"Exact keyed state mutation",location:write.location}],
        callPath:write.callPath.map(id=>facts.program.symbols.get(id)?.name??id),
        remediation:"If membership must hold for the checked key, reuse the exact checked identity or enforce the intended scalar equality. Document intentional independent administrator membership.",
        metadata:{reviewRequired:true,entry,evidence:"required-independent-membership-and-digest-key-relationship",soleAuthorization:false,authenticationIntent:"unknown",applicationImpact:"not-inferred",pathFeasibility:"not-proven",confidenceScope:"static-snapshot-relationship",effectLedger:facts.program.symbols.get(write.ledger)?.name??write.ledger,effectLine:write.location.line,effectLines:observation.effectSites.map(site=>site.line),effectSitesScope:"observed-occurrences-across-complete-histories",membershipRevision:member.result.collectionPredicate?.revision},
      },observation.groupId);
    }));
  },
};
