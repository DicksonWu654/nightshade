import type { AbstractValue, AnalysisFacts, SuccessfulPath } from "../dataflow/index.js";
import { finding, type Detector, type Finding } from "./types.js";
import { eitherTargets } from "../semantic/either-targets.js";
import { spanId } from "../model.js";

/** Exact successful receiver snapshots, never provenance-name matching. */
export const eitherPayloadMismatch: Detector = {
  id: "either-payload-mismatch",
  description: "A native Either's known inactive arm reaches an output, state effect or successful effect gate",
  defaultEnabled: true,
  requires: ["resolved-types", "successful-either-selections", "public-sinks", "state-writes", "predicates"],
  run(facts) { return detectEitherPayloads(facts); },
};

export function detectEitherPayloads(facts: AnalysisFacts, maxWork = 200000): Finding[] {
  if (!facts.eitherEvidence || facts.pathSemantics !== "equivalent-states") {
    const scope = eitherTargets(facts.program);
    if (scope.complete && !scope.applicable) return [];
    facts.diagnostics.push({ code: "either-evidence-unavailable", message: "Either payload analysis requires exact receiver/tag selection observations; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
  const rejectingSites = new Set(facts.assertionReaches.filter(reach => reach.mayFail).map(reach => `${reach.entry}:${spanId(reach.location)}`));
  const varyingBranches = new Set((facts.eitherBranches ?? []).filter(branch => branch.mayTrue && branch.mayFalse).map(branch => branch.id));
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1): void => {
    work += amount;
    if (!Number.isSafeInteger(maxWork) || maxWork < 1 || work > maxWork) throw new Exhausted();
  };
  try {
    const groups = new Map<string, Finding>();
    for (const path of facts.paths) for (const read of path.eitherReads ?? []) {
      charge();
      if (read.tag.constantKind !== "boolean" || read.tag.constant !== String(read.arm !== "left")) continue;
      const effects = consequences(path, read.id, charge, rejectingSites, varyingBranches);
      if (!effects.length) continue;
      const entry = facts.program.symbols.get(path.entry)!.name;
      const key = `${path.entry}:${spanId(read.location)}`;
      const invocations = read.callSites.map(site => ({ location: site }));
      const prior = groups.get(key);
      if (prior) {
        const union = (left: unknown[], right: unknown[]): unknown[] => {
          charge(left.length + right.length);
          return [...new Map([...left, ...right].map(item => [JSON.stringify(item), item])).values()];
        };
        prior.metadata.effects = union(prior.metadata.effects as unknown[], effects);
        prior.metadata.invocations = union(prior.metadata.invocations as unknown[], invocations);
        continue;
      }
      groups.set(key, finding(facts, {
        detectorId: eitherPayloadMismatch.id, severity: "medium", confidence: "high",
        title: "Inactive Either payload affects a successful operation",
        message: `${entry} uses the native Either ${read.arm} payload on a modeled successful history where this receiver's is_left tag selects ${read.arm === "left" ? "right" : "left"}. The payload reaches an output/state effect or an assertion/control gate for an effect. Compact represents both arms; reading a payload alone does not enforce its tag. Review intentional inactive-arm use and input validation.`,
        location: read.location,
        trace: [{ kind: "projection", label: `Either.${read.arm} with inactive receiver tag`, location: read.location }, ...effects.map(effect => ({ kind: "sink", label: effect.kind, location: effect.location }))],
        callPath: read.callPath.map(id => facts.program.symbols.get(id)!.name),
        remediation: "Select the payload matching this receiver's is_left tag, or assert the expected tag before allowing the operation to succeed. Document intentional inactive-arm use with a suppression reason.",
        metadata: { reviewRequired: true, entry, arm: read.arm, isLeft: read.tag.constant === "true", evidence: "exact-successful-receiver-snapshot", effects, invocations, pathFeasibility: "not-proven" },
      }, path.entry));
    }
    return [...groups.values()].sort((left, right) => String(left.metadata.entry).localeCompare(String(right.metadata.entry)) || left.location.start - right.location.start);
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    facts.diagnostics.push({ code: "either-finding-budget", message: "Either consequence traversal exhausted its bounded allowance; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
}

function consequences(path: SuccessfulPath, id: string, charge: (amount?: number) => void, rejectingSites: ReadonlySet<string>, varyingBranches: ReadonlySet<string>): { kind: string; location: import("../model.js").Span; through: "value" | "predicate" }[] {
  const depends = (value: AbstractValue, id: string): boolean => {
    charge(1 + (value.eitherPayloads?.length ?? 0));
    if (value.eitherPayloads?.includes(id)) return true;
    return !!value.eitherControls?.some(control => { charge(1 + control.payloads.length); charge(control.branches.length); return control.branches.every(branch => varyingBranches.has(branch)) && control.payloads.includes(id); });
  };
  const effects: { kind: string; location: import("../model.js").Span; through: "value" | "predicate" }[] = [];
  for (const write of path.writes) if (depends(write.after, id)) effects.push({ kind: "ledger-write", location: write.location, through: "value" });
  for (const sink of path.sinks) if (depends(sink.value, id)) effects.push({ kind: sink.kind, location: sink.location, through: "value" });
  const privileged = (path.operations ?? []).filter(operation => { charge(); return ["kernel-write", "native-witness", "collection-write", "event"].includes(operation.kind); });
  for (const operation of privileged) if (operation.args.some(arg => depends(arg, id)) || operation.control.some(value => depends(value, id))) effects.push({ kind: operation.kind, location: operation.location, through: "value" });
  // A successful assertion can gate an unrelated constant write. Later guards
  // also constrain preceding atomic effects; dominance alone is insufficient.
  if (path.predicates?.some(predicate => { charge(); return predicate.assertionGate && rejectingSites.has(`${path.entry}:${spanId(predicate.location)}`) && depends(predicate.value, id); })) {
    for (const write of path.writes) { charge(); effects.push({ kind: "ledger-write", location: write.location, through: "predicate" }); }
    for (const operation of privileged) { charge(); effects.push({ kind: operation.kind, location: operation.location, through: "predicate" }); }
  }
  return [...new Map(effects.map(effect => [`${effect.kind}:${spanId(effect.location)}:${effect.through}`, effect])).values()];
}
