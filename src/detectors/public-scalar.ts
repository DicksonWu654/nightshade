import type { AbstractValue, AnalysisFacts } from "../dataflow/index.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { spanId } from "../model.js";
import { standardType } from "../semantic/intrinsics.js";
import { PUBLIC_SCALAR_CAST, PUBLIC_SCALAR_RULE, PUBLIC_SCALAR_TARGETS, PUBLIC_SCALAR_PROFILE_MESSAGE, publicScalarRecipe, publicScalarScope } from "../semantic/public-scalar-targets.js";
import { parseType, printType } from "../semantic/types.js";
import { finding, type Detector, type Finding } from "./types.js";

export const publishedDigestGeneratorScalarReview: Detector = {
  id: PUBLIC_SCALAR_RULE,
  description: "Published exact digest determines a scalar used in native generator multiplication whose result survives in a ledger Cell",
  defaultEnabled: false,
  requires: ["resolved-calls", "private-provenance", "public-sinks", "direct-hash-inputs", "exact-invocation-operands"],
  run(facts) { return publicScalarFindings(facts); },
};

export function publicScalarFindings(facts: AnalysisFacts, allowance = 200000): Finding[] {
  const evidence = facts.publicScalarEvidence;
  let work = 0, entry = "";
  class Exhausted extends Error {}
  const charge = (steps = 1, values = 0): boolean => {
    work += steps;
    if (evidence) {
      facts.metrics.steps += steps; facts.metrics.abstractValues += values;
      evidence.entrySteps.set(entry, (evidence.entrySteps.get(entry) ?? 0) + steps);
    }
    if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance
      || evidence && ((evidence.entrySteps.get(entry) ?? 0) > evidence.maxSteps || facts.metrics.abstractValues > evidence.maxValues)) throw new Exhausted();
    return true;
  };
  // Diagnostic slots were reserved by the selected Dataflow carrier. Refusal
  // never retries interpretation or reconstructs a new observation.
  const incomplete = (code: string, message: string) => {
    facts.diagnostics.push({ code, message, location: facts.program.functions.get(entry)?.declaration.span ?? facts.program.rootSource.ast.span,
      scope: { kind: "rule", detectorId: PUBLIC_SCALAR_RULE, entry } });
    return [];
  };
  const key = (value: AbstractValue) => {
    const result = immutableOperandKey(value, 4096, undefined, charge);
    if (!result.complete) throw new Exhausted();
    return result.key;
  };
  const same = (a: AbstractValue, b: AbstractValue) => { const left = key(a); return left !== undefined && left === key(b); };
  const digestOperand = (value: AbstractValue) => {
    const digest = value.directDigest;
    if (digest?.primitive !== "persistentHash" || !digest.inputType || digest.input.items?.length !== 1) return;
    let type = digest.inputType, depth = 0;
    while (facts.program.nominalTypes.has(type)) {
      charge(); if (++depth > 32) throw new Exhausted();
      type = facts.program.nominalTypes.get(type)!.underlying;
    }
    // Bound and reserve type parsing/printing and representation strings before
    // allocating. Nominal expansion above is charged one declaration at a time.
    if (type.length > 4096) throw new Exhausted();
    charge(type.length + 1, type.length * 6 + 8);
    if (printType(parseType(facts.program.representationOf(type))) !== "Vector<1,Bytes<32>>") return;
    return digest.input.items[0];
  };
  let findings: Map<string, Finding> | undefined;
  try {
    for (const selected of evidence?.entrySteps.keys() ?? facts.program.entries) {
      entry = selected;
      if (!evidence && (facts.completedEntries.length || facts.paths.length)
        && !facts.completedEntries.includes(entry) && !facts.paths.some(path => path.entry === entry)) continue;
      // Already exhausted/incomplete observations cannot provide clean native
      // facts. Their actual spent metrics remain intact.
      if (evidence && (!facts.completedEntries.includes(entry) || facts.diagnostics.some(issue => !issue.scope || issue.scope.entry === entry))) {
        if (facts.diagnostics.some(issue => issue.scope?.detectorId === PUBLIC_SCALAR_RULE && issue.scope.entry === entry)) return [];
        return incomplete("public-scalar-evidence", "Selected scalar source observation is incomplete; no matching retry is available");
      }
      const target = publicScalarScope(facts.program, entry, 20000, evidence ? charge : undefined);
      if (!evidence) charge(target.work);
      if (!target.complete) return incomplete(target.unavailable === "budget" ? "public-scalar-budget" : "public-scalar-target-unavailable", "Canonical generator applicability is unavailable within the shared allowance");
      if (!target.applicable) continue;
      if (!evidence) return incomplete("public-scalar-evidence", "Applicable scalar review requires a selected source-budget carrier");
      charge(4, 6);
      const recipe = publicScalarRecipe(facts.program);
      if (!recipe) return incomplete("public-scalar-profile", PUBLIC_SCALAR_PROFILE_MESSAGE);
      if (facts.pathSemantics !== "equivalent-states" || !facts.digestEvidence)
        return incomplete("public-scalar-evidence", "Published digest scalar review requires exact digest and selected native/cast operands");
      for (const target of PUBLIC_SCALAR_TARGETS) {
        charge(); if (!facts.invocationEvidence?.includes(target)) return incomplete("public-scalar-evidence", "Selected native/cast operands are unavailable");
      }
      if (!findings) { charge(0, 3); findings = new Map(); }
      for (const path of facts.paths) {
        charge(); if (path.entry !== entry) continue;
        if ((path.operations?.length ?? 0) > evidence.maxSteps || path.writes.length > evidence.maxSteps) throw new Exhausted();
        charge(0, 3 + path.writes.length * 3 + (path.operations?.length ?? 0));
        const terminal = new Map<string, (typeof path.writes)[number]>();
        for (const write of path.writes) { charge(); terminal.set(write.ledger, write); }
        const operations: NonNullable<typeof path.operations> = [];
        for (const op of path.operations ?? []) { charge(); if (op.kind === "circuit-invocation") operations.push(op); }
        for (const degradation of operations) {
          charge(); if (degradation.name !== "intrinsic::degradeToTransient" || degradation.args.length !== 1 || degradation.result.type !== "Field") continue;
          const seed = digestOperand(degradation.args[0]); if (!seed || seed.type !== "Bytes<32>" || seed.negated || seed.comparison || seed.ordering) continue;
          let source: (typeof seed.flows)[number]["source"] | undefined;
          for (const flow of seed.flows) { charge(); if (flow.form === "raw" && flow.source.kind === "witness" && seed.identity === flow.source.id) { source = flow.source; break; } }
          if (!source) continue;
          charge(0, 1); // Reserve the closure before capturing this degradation.
          const processScalar = (scalar: AbstractValue, cast?: (typeof operations)[number]) => {
            for (const generator of operations) {
              charge(); if (generator.name !== "intrinsic::ecMulGenerator" || generator.args.length !== 1
                || generator.args[0].type !== (recipe === "field" ? "Field" : standardType("JubjubScalar")) || generator.result.type !== standardType("JubjubPoint")
                || !same(generator.args[0], scalar)) continue;
              for (const registration of terminal.values()) {
                charge(); if (registration.region.length || facts.program.symbols.get(registration.ledger)?.type !== standardType("JubjubPoint") || !same(registration.after, generator.result)) continue;
                for (const sink of path.sinks) {
                  charge(); if (sink.kind === "exported-return") continue;
                  charge(0, 4); const pending = [sink.value], seen = new Set<AbstractValue>();
                  while (pending.length) {
                    charge(); const value = pending.pop()!; if (seen.has(value)) continue;
                    charge(0, 2); seen.add(value);
                    for (const child of value.items ?? []) { charge(1, 2); pending.push(child); }
                    for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { charge(1, 2); pending.push(value.fields![name]); }
                    const publishedSeed = digestOperand(value); if (!publishedSeed || !same(publishedSeed, seed)) continue;
                    // Reserve identity serialization, path normalization/sorting,
                    // traces, strings, metadata and retained finding before any
                    // allocation. File-path sort work is bounded conservatively.
                    const ledger = facts.program.symbols.get(registration.ledger)!.name;
                    let callChars = 0;
                    for (const id of sink.callPath) { charge(); callChars += facts.program.symbols.get(id)!.name.length; }
                    const originChars = ledger.length + callChars + entry.length + generator.location.file.length + registration.location.file.length + sink.location.file.length + (source!.invocation?.site.length ?? 0) + 256;
                    let fileChars = 0;
                    for (const file of facts.program.files.keys()) { charge(); fileChars += file.length; }
                    const fileCount = facts.program.files.size;
                    charge(1 + fileCount * (fileCount + 1) + sink.callPath.length,
                      180 + sink.callPath.length * 4 + fileCount * 6 + Math.ceil((originChars * (fileCount + 4) + fileChars * 3) / 32));
                    const origin = JSON.stringify([path.entry, spanId(generator.location), spanId(registration.location), spanId(sink.location), source!.invocation]);
                    if (findings!.has(origin)) continue;
                    findings!.set(origin, finding(facts, {
                      detectorId: PUBLIC_SCALAR_RULE, severity: "info", confidence: "high",
                      title: "Published digest determines a stored generator multiplication scalar",
                      message: `This path publishes persistentHash<Vector<1, Bytes<32>>> of the same immutable private witness operand used by native degradeToTransient, ${recipe === "field" ? "whose Field result feeds native ecMulGenerator directly" : "followed by a resolved Field-to-JubjubScalar cast and native ecMulGenerator"}. The generator result survives in ledger ${ledger}. The scalar is determined by the published digest. Review whether the application requires this scalar to remain private; encryption use, enrollment safety, ciphertext impact, deployed impact and path feasibility are not established.`,
                      location: sink.location, source: source!.location,
                      trace: [{ kind: "source", label: "exact immutable witness operand", location: source!.location },
                        { kind: "transform", label: "native degradeToTransient of exact digest", location: degradation.location },
                        ...(recipe === "scalar-cast" ? [{ kind: "transform" as const, label: "resolved Field-to-JubjubScalar cast", location: cast!.location }] : []),
                        { kind: "transform", label: "native generator multiplication", location: generator.location },
                        { kind: "sink", label: `surviving point Cell write: ${ledger}`, location: registration.location },
                        { kind: "sink", label: "same typed persistent digest published", location: sink.location }],
                      callPath: sink.callPath.map(id => facts.program.symbols.get(id)!.name),
                      remediation: "Review the scalar's intended confidentiality. If private scalar material is required, separate the published identifier and scalar derivation with distinct hash domains or independent secrets.",
                      metadata: { reviewRequired: true, entry: facts.program.symbols.get(path.entry)!.name,
                        evidence: recipe === "field" ? "exact-legacy-native-field-and-surviving-point-cell" : "exact-modern-native-scalar-and-surviving-point-cell", scalarDeterminedByPublishedDigest: true,
                        encryptionUseProven: false, deployedImpactProven: false, pathFeasibility: "not-proven" },
                    }, origin));
                  }
                }
              }
            }
          };
          if (recipe === "field") processScalar(degradation.result);
          else for (const cast of operations) {
            charge(); if (cast.name === PUBLIC_SCALAR_CAST && cast.args.length === 1 && same(cast.args[0], degradation.result)) processScalar(cast.result, cast);
          }
        }
      }
    }
    if (!findings) return [];
    charge(0, 1 + findings.size); return [...findings.values()];
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    return incomplete("public-scalar-budget", "Exact published digest scalar observation exhausted the shared work/value allowance; results are incomplete");
  }
}
