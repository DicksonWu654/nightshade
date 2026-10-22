import type { AnalysisFacts } from "../dataflow/index.js";
import { spanId } from "../model.js";
import { runtimeWidthOutputSites, SHIELDED_WIDTH_RULE } from "../semantic/runtime-width-targets.js";
import { numericBound } from "../semantic/types.js";
import { finding, type Detector, type Finding } from "./types.js";

const FIRST_OVERSIZED_VALUE = 1n << 64n;

/** Constant native operands only; no application cap or runtime-execution proof. */
export function runtimeWidthFindings(facts: AnalysisFacts, allowance = 200000, scopeAllowance = 20000,
  entries: readonly string[] = facts.program.entries): Finding[] {
  const results: Finding[] = [];
  for (const entry of entries) {
    const scope = runtimeWidthOutputSites(facts.program, entry, scopeAllowance);
    if (scope.complete && !scope.applicable) continue;
    const issue = (reason: string) => {
      if (facts.diagnostics.some(diagnostic => diagnostic.code === "shielded-width-evidence-unavailable"
        && diagnostic.scope?.kind === "rule" && diagnostic.scope.detectorId === SHIELDED_WIDTH_RULE && diagnostic.scope.entry === entry)) return;
      facts.diagnostics.push({ code: "shielded-width-evidence-unavailable",
        message: `${reason}; ${SHIELDED_WIDTH_RULE} has no complete result for this entry`,
        location: facts.program.functions.get(entry)!.declaration.span,
        scope: { kind: "rule", detectorId: SHIELDED_WIDTH_RULE, entry } });
    };
    if (!scope.complete) { issue("Canonical native output applicability exhausted its bounded scan"); continue; }
    if (facts.program.compilerVersion !== "0.34.0" || facts.program.zkirVersion !== 2) {
      issue("Reference runtime 0.19.0 compatibility is qualified only for compiler 0.34.0/ZKIR2"); continue;
    }
    if (!facts.mintQuantityEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states") {
      issue("Exact numeric operands, all successful predicates and equivalent-state histories are required"); continue;
    }
    if (!facts.completedEntries.includes(entry)) { issue("The entry lacks complete successful-history coverage"); continue; }
    if (facts.diagnostics.some(diagnostic => diagnostic.scope?.kind === "rule"
      && diagnostic.scope.detectorId === SHIELDED_WIDTH_RULE && diagnostic.scope.entry === entry)) continue;
    let work = 0, unavailable: string | undefined;
    const charge = () => Number.isSafeInteger(allowance) && ++work <= allowance;
    const groups = new Map<string, Finding>();
    for (const path of facts.paths) {
      if (!charge()) { unavailable = "Native operand observation allowance exhausted"; break; }
      if (path.entry !== entry) continue;
      for (const operation of path.operations ?? []) {
        if (!charge()) { unavailable = "Native operand observation allowance exhausted"; break; }
        if (operation.kind !== "native-witness" || operation.name !== "createZswapOutput") continue;
        if (!scope.sites.has(spanId(operation.location))) { unavailable = "Native output lacks an exact canonical source site"; break; }
        const value = operation.args[0]?.fields?.value;
        // Legal aggregate widening retains a literal's narrower Uint domain in
        // the facts. The resolved native call establishes the coin field type;
        // only a represented unsigned domain contained in Uint128 is admissible.
        const bound = value?.type ? numericBound(facts.program.representationOf(value.type)) : undefined;
        if (!value || bound === undefined || bound <= 0n || bound > 1n << 128n) {
          unavailable = "Native output does not retain an unsigned value domain contained in Uint<128>"; break;
        }
        if (value.constant === undefined) continue;
        if (value.constantKind !== "integer") { unavailable = "Native output constant lacks integer evidence"; break; }
        if (value.constant.length > 80 || !/^\d+$/.test(value.constant)) {
          unavailable = "Native output constant lacks bounded unsigned integer evidence"; break;
        }
        const amount = BigInt(value.constant);
        if (amount >= bound) { unavailable = "Native output constant contradicts its retained unsigned domain"; break; }
        if (amount < FIRST_OVERSIZED_VALUE) continue;
        const name = facts.program.symbols.get(entry)!.name;
        const item = finding(facts, {
          detectorId: SHIELDED_WIDTH_RULE, severity: "low", confidence: "high",
          title: "Shielded coin value exceeds the reference runtime encoding range",
          message: `${name} passes a definite Uint<128> coin value ${value.constant} to native createZswapOutput on a modeled successful history. This exceeds the 64-bit coin encoding range in reference runtime 0.19.0. Applicability expressly assumes that reference runtime; the actual installed or deployed runtime is unverified.`,
          location: operation.location, trace: [{ kind: "effect", label: "native shielded coin output", location: operation.location }],
          callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "Review runtime compatibility and constrain the emitted coin to the supported encoding range, or use a separately qualified compatible runtime. This observation does not establish transaction funding, proof feasibility or runtime rejection.",
          metadata: { reviewRequired: true, entry: name, operation: "createZswapOutput", evidence: "definite-native-output-constant-exceeds-reference-width",
            values: [value.constant], sourceType: "Uint<128>", referenceMaximum: String(FIRST_OVERSIZED_VALUE - 1n),
            referenceRuntimeVersion: "0.19.0", runtimeApplicability: "expressly-assumed-reference-runtime", actualRuntime: "unverified",
            compilerProfile: facts.program.semanticProfile, runtimeRejection: "not-proven", funding: "not-proven", pathFeasibility: "not-proven",
            affectedEffects: [operation.location], invocationSites: [operation.callSites ?? []] },
        }, entry);
        const prior = groups.get(item.fingerprint);
        if (prior) {
          prior.metadata.values = [...new Set([...prior.metadata.values as string[], value.constant])].sort();
          const sites = [...prior.metadata.invocationSites as unknown[], operation.callSites ?? []];
          prior.metadata.invocationSites = [...new Map(sites.map(site => [JSON.stringify(site), site])).values()];
        } else groups.set(item.fingerprint, item);
      }
      if (unavailable) break;
    }
    if (unavailable) issue(unavailable);
    else results.push(...groups.values());
  }
  return results;
}

export const shieldedCoinRuntimeWidth: Detector = {
  id: SHIELDED_WIDTH_RULE, defaultEnabled: false,
  description: "A definite native shielded output exceeds the expressly assumed runtime 0.19.0 coin encoding range",
  requires: ["canonical-native-output-sites", "exact-numeric-operands", "completed-entries"],
  run: facts => runtimeWidthFindings(facts),
};
