import type { AbstractValue, AnalysisFacts, PrivateSource } from "../dataflow/index.js";
import { digestTargets } from "../semantic/digest-targets.js";
import { finiteDomain } from "../semantic/domains.js";
import { finding, type Detector, type Finding } from "./types.js";
import { spanId } from "../model.js";

/** Direct digest evidence excludes comparisons, control-only dependencies and
 * salted multi-private-input hashes. Domain comes from the actual source type. */
export const lowEntropyHashDisclosure: Detector = {
  id: "low-entropy-hash-disclosure",
  description: "A published direct hash has one private input drawn from a small declared domain",
  defaultEnabled: true,
  requires: ["resolved-types", "private-provenance", "public-sinks", "direct-hash-inputs"],
  run(facts) { return detectSmallDomainHash(facts); },
};

export function detectSmallDomainHash(facts: AnalysisFacts, allowance = 200000): Finding[] {
  if (!facts.digestEvidence || facts.pathSemantics !== "equivalent-states") {
    const scope = digestTargets(facts.program);
    if (scope.complete && !scope.applicable) return [];
    const hasHash = facts.paths.some(path => path.sinks.some(sink => sink.value.flows.some(flow => flow.form === "hash")));
    if (!scope.complete || hasHash) facts.diagnostics.push({ code: "hash-domain-evidence-unavailable", message: "Small-domain hash review requires exact histories with immutable typed digest inputs; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1): void => { work += amount; if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance) throw new Exhausted(); };
  const domains = new Map<string, number | undefined>();
  const groups = new Map<string, Finding>();
  try {
    for (const path of facts.paths) {
      // Raw public values, including later atomic writes, are public context on
      // this successful history. Implicit flows/derived expressions cannot
      // establish that the underlying input itself has been published.
      const published = new Set<string>();
      const publicValues = path.sinks.map(sink => sink.value);
      while (publicValues.length) {
        charge();
        const value = publicValues.pop()!;
        for (const item of value.items ?? []) { charge(); publicValues.push(item); }
        for (const field of Object.values(value.fields ?? {})) { charge(); publicValues.push(field); }
        for (const flow of value.flows) {
          charge();
          if (flow.form === "raw" && value.identity === flow.source.id) published.add(flow.source.id);
        }
      }
      for (const sink of path.sinks) {
        const pending = [sink.value];
        const seen = new Set<AbstractValue>();
        while (pending.length) {
          charge();
          const value = pending.pop()!;
          if (seen.has(value)) continue;
          seen.add(value);
          for (const item of value.items ?? []) { charge(); pending.push(item); }
          for (const field of Object.values(value.fields ?? {})) { charge(); pending.push(field); }
          const hash = value.directDigest;
          if (!hash || !["persistentHash", "transientHash", "keccak256"].includes(hash.primitive)) continue;
          const privateLeaves = new Map<string, { source: PrivateSource; type: string }>();
          const ingredients = [hash.input];
          let supported = true;
          while (ingredients.length) {
            charge();
            const ingredient = ingredients.pop()!;
            if (ingredient.constant !== undefined) continue;
            if (ingredient.items || ingredient.fields) {
              for (const item of ingredient.items ?? []) { charge(); ingredients.push(item); }
              for (const field of Object.values(ingredient.fields ?? {})) { charge(); ingredients.push(field); }
              continue;
            }
            if (!ingredient.flows.length) continue;
            const raw = ingredient.flows.find(flow => flow.form === "raw" && flow.source.id === ingredient.identity);
            charge(ingredient.flows.length);
            if (!raw || ingredient.negated || ingredient.comparison || ingredient.ordering || !ingredient.type) { supported = false; break; }
            if (!published.has(raw.source.id)) privateLeaves.set(raw.source.id, { source: raw.source, type: ingredient.type });
          }
          if (!supported || privateLeaves.size !== 1) continue;
          const { source, type } = [...privateLeaves.values()][0];
          if (!domains.has(type)) {
            const domain = finiteDomain(facts.program, type, 65536, Math.min(4096, allowance - work));
            charge(domain.work);
            if (!domain.complete) throw new Exhausted();
            domains.set(type, domain.upperBound);
          }
          const bound = domains.get(type);
          if (bound === undefined || bound < 2) continue;
          const entry = facts.program.symbols.get(path.entry)!.name;
          // Run-local allocation counters differ in an isolated entry pass. Keep
          // reported identity tied to the canonical declaration/invocation leaf.
          const origin = JSON.stringify([path.entry, spanId(source.location), source.kind, source.symbol, source.declarationLeaf, source.invocation]);
          const key = `${spanId(sink.location)}:${origin}`;
          if (groups.has(key)) continue;
          groups.set(key, finding(facts, {
            detectorId: lowEntropyHashDisclosure.id, severity: "medium", confidence: "high",
            title: "Published hash has a small private input domain",
            message: `${entry} publishes a direct ${hash.primitive} digest of ${source.name}, whose declared ${type} domain has at most ${bound} values. The modeled hash input contains one private source and may include public context, which adds no secret uncertainty. Hashing alone does not hide such a small domain. Intentional disclosure, reveal phases and public identifiers require review; no secrecy intent or actual entropy is inferred.`,
            location: sink.location, source: source.location,
            trace: [{ kind: "source", label: `${type}: at most ${bound} values`, location: source.location }, { kind: "sink", label: `${hash.primitive} reaches ${sink.kind}`, location: sink.location }],
            callPath: sink.callPath.map(id => facts.program.symbols.get(id)!.name),
            remediation: "When the value must remain hidden, use the protocol's commitment primitive with sufficiently unpredictable private opening randomness. Confirm whether publishing this digest is intentional before changing the protocol.",
            metadata: { reviewRequired: true, entry, primitive: hash.primitive, inputDomainUpperBound: bound, domainEvidence: "declared-type", evidence: "direct-single-private-source-digest", entropyEstimated: false, pathFeasibility: "not-proven" },
          }, origin));
        }
      }
    }
    return [...groups.values()];
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    facts.diagnostics.push({ code: "hash-domain-budget", message: "Small-domain hash observation exhausted its bounded allowance; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
}
