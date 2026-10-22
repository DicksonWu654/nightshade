import { pathLength, identityLength, wrapIdentityMeter } from "../semantic/metering.js";
import type { AnalysisFacts, RuntimeOperation } from "./index.js";
import { intentBooleanRequirements } from "./operation-intent-booleans.js";
import { SHIELDED_MINT } from "../semantic/mint-targets.js";
import { SOURCE_CLAIM_RULE, sourceClaimRecipientType, type ResolvedSourceClaim } from "../semantic/source-claims.js";
import type { Diagnostic } from "../model.js";

export function sourceClaimObservations(facts: AnalysisFacts) {
  const observations: { claim: ResolvedSourceClaim; operation: RuntimeOperation }[] = [], diagnostics: Diagnostic[] = [];
  const evidence = facts.sourceClaimEvidence;
  let work = 0, values = 0;
  const charge = (amount = 1, retained = 0): void => {
    work += amount; values += retained;
    if (!evidence || facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + values > evidence.maxValues) throw new Error("Source claim matching exhausted its shared allowance");
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  try {
    charge(1, 2);
    if (!evidence?.claims?.length || !facts.completedEntries.includes(evidence.entry) || facts.diagnostics.length
      || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.invocationEvidence?.includes(SHIELDED_MINT)
      || evidence.histories !== facts.paths.length) throw new Error("Complete selected source claim histories are unavailable");
    for (const path of facts.paths) {
      charge();
      if (path.entry !== evidence.entry || !path.predicates || !path.sourceClaimHistory
        || path.sourceClaimHistory.operations !== (path.operations?.length ?? 0) || path.sourceClaimHistory.predicates !== path.predicates.length
        || path.sourceClaimHistory.writes !== path.writes.length) throw new Error("Original source claim history coverage is unavailable");
      let requirements: ReturnType<typeof intentBooleanRequirements> | undefined;
      for (const operation of path.operations ?? []) {
        charge(); if (operation.kind !== "circuit-invocation" || operation.name !== SHIELDED_MINT) continue;
        charge(operation.callPath.length + (operation.callSites?.length ?? 0));
        if (!operation.callSites || operation.callSites.length !== operation.callPath.length) throw new Error("Canonical mint call identity is unavailable");
        const recipient = operation.args[3];
        charge(1 + identityLength(recipient?.type, charge), 1 + Math.ceil(identityLength(recipient?.type, charge) / 16));
        if (!recipient || !sourceClaimRecipientType(facts.program, recipient.type ?? "", wrapIdentityMeter(charge, (work = 1, values = 0) => { charge(work, values); return true; }))) throw new Error("Exact native mint recipient type is unavailable");
        const tag = recipient.fields?.is_left;
        if (!tag) throw new Error("Mint recipient tag is unavailable");
        let truth: boolean | undefined;
        if (tag.constantKind === "boolean" && ["true", "false"].includes(tag.constant ?? "")) truth = tag.constant === "true";
        else {
          if (!requirements) {
            charge(0, 1); const mandatory = [];
            for (const predicate of path.predicates) {
              charge(1 + predicate.callPath.length);
              // Native recipient dispatch merely partitions an unconstrained
              // recipient. It does not enforce the application's claim.
              if (predicate.callPath.includes(SHIELDED_MINT)) continue;
              charge(0, 1); mandatory.push(predicate);
            }
            requirements = intentBooleanRequirements(mandatory, charge);
          }
          truth = requirements.truth(tag);
        }
        if (truth === undefined) throw new Error("Mint recipient tag is opaque on a complete successful history");
        if (!truth) continue;
        for (const claim of evidence.claims) {
          // Precharge finding strings, fingerprint source sorting, trace and retained containers.
          let emission = 160 + claim.quote.length + identityLength(claim.circuit, charge) + pathLength(operation.location.file, charge) + operation.callPath.length * 8;
          for (const file of facts.program.files.keys()) { charge(); emission += pathLength(file, charge) + 4; }
          for (const id of operation.callPath) { charge(); emission += identityLength(id, charge) * 2; }
          charge(emission, emission); observations.push({ claim, operation });
        }
      }
    }
  } catch (error) {
    observations.length = 0;
    diagnostics.push({ code: "source-claim-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: evidence ? facts.program.functions.get(evidence.entry)!.declaration.span : facts.program.rootSource.ast.span,
      ...(evidence ? { scope: { kind: "rule" as const, detectorId: SOURCE_CLAIM_RULE, entry: evidence.entry } } : {}) });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
  return { observations, diagnostics };
}
