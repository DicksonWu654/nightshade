import type { AbstractValue, AnalysisFacts } from "../dataflow/index.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { spanId } from "../model.js";
import { encryptionScope, encryptionTargets } from "../semantic/encryption-targets.js";
import { standardType } from "../semantic/intrinsics.js";
import { parseType, printType } from "../semantic/types.js";
import { finding, type Detector, type Finding } from "./types.js";

export const publiclyDerivableEncryptionSecret: Detector = {
  id: "publicly-derivable-encryption-secret",
  description: "A published digest determines the scalar of a registered curve point through resolved native calls",
  defaultEnabled: true,
  requires: ["resolved-calls", "private-provenance", "public-sinks", "direct-hash-inputs", "exact-invocation-operands"],
  run(facts) { return encryptionSecretFindings(facts); },
};

/** A proven native recipe and direct terminal point registration. A write
 * history is not final storage: later writes to the same root reject survival.
 * Checkpoint prefixes are separate histories supplied by the shared engine. */
export function encryptionSecretFindings(facts: AnalysisFacts, allowance = 200000): Finding[] {
  const roles = encryptionTargets(facts.program);
  if (!roles.complete || roles.unsupported.size) {
    for (const entry of facts.program.entries) {
      const scope = encryptionScope(facts.program, entry);
      if (!scope.complete || scope.unsupported) facts.diagnostics.push({ code: "encryption-target-unavailable",
        message: "Generator derivation recipe/profile is unsupported or applicability exceeded its allowance; this entry is incomplete",
        location: facts.program.functions.get(entry)!.declaration.span,
        scope: { kind: "rule", detectorId: publiclyDerivableEncryptionSecret.id, entry } });
    }
    if (facts.diagnostics.some(issue => issue.scope?.detectorId === publiclyDerivableEncryptionSecret.id)) return [];
  }
  if (facts.pathSemantics !== "equivalent-states" || !facts.digestEvidence
    || [...roles.targets].some(id => !facts.invocationEvidence?.includes(id))) {
    for (const entry of facts.program.entries) {
      const scope = encryptionScope(facts.program, entry);
      if (!scope.complete || scope.applicable) facts.diagnostics.push({ code: "encryption-evidence-unavailable",
        message: "Encryption-secret review requires exact typed digests and selected invocation operands; this entry is incomplete",
        location: facts.program.functions.get(entry)!.declaration.span,
        scope: { kind: "rule", detectorId: publiclyDerivableEncryptionSecret.id, entry } });
    }
    return [];
  }
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1) => { work += amount; if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance) throw new Exhausted(); };
  const key = (value: AbstractValue): string | undefined => {
    const result = immutableOperandKey(value, Math.min(4096, allowance - work)); charge(result.work);
    if (!result.complete) throw new Exhausted();
    return result.key;
  };
  const groups = new Map<string, Finding>();
  try {
    for (const path of facts.paths) {
      charge();
      if (!facts.completedEntries.includes(path.entry)) continue;
      const terminal = new Map<string, (typeof path.writes)[number]>();
      for (const write of path.writes) { charge(); terminal.set(write.ledger, write); }
      const registrations = [...terminal.values()].filter(write => !write.region.length
        && facts.program.symbols.get(write.ledger)!.type === standardType("JubjubPoint"));
      for (const op of path.operations ?? []) {
        charge();
        if (op.kind !== "circuit-invocation" || !roles.targets.has(op.name)) continue;
        const secret = op.args[0];
        if (!secret || printType(parseType(facts.program.representationOf(secret.type ?? "unknown"))) !== "Bytes<32>") continue;
        const source = secret.flows.find(flow => flow.form === "raw" && flow.source.kind === "witness" && secret.identity === flow.source.id)?.source;
        charge(secret.flows.length);
        if (!source || secret.negated || secret.comparison || secret.ordering) continue;
        const secretKey = key(secret), resultKey = key(op.result);
        if (!secretKey || !resultKey) continue;
        for (const registration of registrations) {
          charge();
          if (key(registration.after) !== resultKey) continue;
          for (const sink of path.sinks) {
            charge();
            if (sink.kind === "exported-return") continue;
            const pending = [sink.value], seen = new Set<AbstractValue>();
            while (pending.length) {
              charge(); const value = pending.pop()!;
              if (seen.has(value)) continue;
              seen.add(value);
              for (const child of [...value.items ?? [], ...Object.values(value.fields ?? {})]) { charge(); pending.push(child); }
              const digest = value.directDigest;
              if (digest?.primitive !== "persistentHash" || !digest.inputType
                || printType(parseType(facts.program.representationOf(digest.inputType))) !== "Vector<1,Bytes<32>>"
                || digest.input.items?.length !== 1 || key(digest.input.items[0]) !== secretKey) continue;
              const entry = facts.program.symbols.get(path.entry)!.name, ledger = facts.program.symbols.get(registration.ledger)!.name;
              const origin = JSON.stringify([path.entry, spanId(op.location), spanId(registration.location), spanId(sink.location), spanId(source.location), source.invocation]);
              if (groups.has(origin)) continue;
              groups.set(origin, finding(facts, {
                detectorId: publiclyDerivableEncryptionSecret.id, severity: "high", confidence: "high",
                title: "Published digest determines a registered curve point's scalar",
                message: `${entry} publishes persistentHash<Vector<1, Bytes<32>>>([${source.name}]) and registers the surviving result of a resolved generator derivation on that exact immutable witness value in ledger ${ledger}. The resolved native chain applies degradeToTransient to that same digest before ecMulGenerator. The scalar is therefore determined by published data. If this point is used as an encryption key, review the intended scalar secrecy; this does not recover the original witness seed or establish encryption use, a deployed compromise or path feasibility.`,
                location: sink.location, source: source.location,
                trace: [{ kind: "source", label: "same immutable private witness operand", location: source.location },
                  { kind: "transform", label: "resolved hash-to-scalar-to-generator derivation", location: op.location },
                  { kind: "sink", label: `surviving curve point registration: ${ledger}`, location: registration.location },
                  { kind: "sink", label: "matching persistent digest is public", location: sink.location }],
                callPath: sink.callPath.map(id => facts.program.symbols.get(id)!.name),
                remediation: "Separate account-identifier and encryption-key hash domains, or use independent secret material. Review existing key registrations before changing a protocol.",
                metadata: { reviewRequired: true, entry, evidence: "exact-native-chain-registration-and-digest",
                  derivedScalarPublic: true, encryptionUseProven: false, originalSeedRecovered: false, ciphertextUseProven: false, pathFeasibility: "not-proven",
                  keyRegistration: registration.location, keyDerivation: op.location, invocationSites: op.callSites ?? [] },
              }, origin));
            }
          }
        }
      }
    }
    return [...groups.values()];
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    facts.diagnostics.push({ code: "encryption-evidence-budget", message: "Exact encryption-secret observation exceeded its bounded allowance; results are incomplete", location: facts.program.rootSource.ast.span });
    return [];
  }
}
